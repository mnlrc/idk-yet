# Phase 1 Course: What a Small Website Scanner Can Actually Find

This course explains the first useful slice of the project: a Python command-line tool that makes a small number of ordinary HTTP requests and reports observable website configuration issues. It is meant to make the project’s progression clear: first understand one request and its response, then add checks, then learn what requires HTML or JavaScript analysis.

## What you should be able to do after this course

- Explain what information an HTTP client can observe without a browser or website source repository.
- Understand the checks currently implemented in `src/scanners/http_scanner.py`.
- Recognize which observations are hardening opportunities rather than confirmed exploitable vulnerabilities.
- Add later checks for cookies and returned HTML without turning the program into a crawler or exploit tool.
- Know which classes of vulnerability this tool cannot determine from one public page request.

## Scope and authorization

Only analyze websites you own or have explicit permission to assess. The current scanner makes one `GET` request to the supplied URL, verifies TLS, does not follow redirects, and checks selected response headers. It does not submit forms, guess paths, crawl links, execute JavaScript, or test exploit payloads.

The address check in the current code is a local-CLI guard, not a complete SSRF defense: it resolves a hostname before the HTTP library connects, and DNS could change between those steps. Do not expose this scanner as a hosted service without connection-time address pinning or network egress controls.

## 1. The mental model: request, response, observation

A browser or `requests` client sends an HTTP request to a server. The server returns a status code, response headers, and usually a response body. The current program observes the status and headers. Because it uses `stream=True` and does not read the response body, it currently does **not** inspect the page’s HTML, CSS, or JavaScript.

```text
CLI target → URL validation → DNS pre-check → one HTTP request
                                                   |
                                                   v
                                  status + response headers
                                                   |
                                                   v
                                           observations
```

A missing header is evidence about configuration. It is not automatically proof that an attacker can exploit the website. Severity should stay cautious, and every finding should show the evidence and explain its limits. The project’s severity enum is a communication aid, not a mathematically authoritative risk score.

The short code snippets below show the detection logic rather than complete methods. `add_finding(...)` means “append a `Finding` with this check ID, severity, title, evidence, and remediation”; `report(...)` means “format that observation as a finding.” The actual scanner should keep using the `Finding` dataclass and centralize this construction rather than printing from each check.

## 2. TLS certificate and HTTPS connection problems

### Theory

HTTPS uses TLS to encrypt traffic, detect tampering, and authenticate the server to the client. The client checks the certificate chain and verifies that the certificate is valid for the hostname. If validation fails, the client should stop instead of silently accepting the connection. [OWASP TLS guidance](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)

### A realistic situation

A small organization renews its website certificate on the main hostname but forgets `portal.example.test`. Users visiting the portal see a certificate warning. A careless monitoring script that disables certificate checks could hide the problem and train people to ignore warnings.

### Detection in Python

The current scanner has `verify=True`. `requests` raises an SSL error when certificate verification fails; the code turns that into a scan error instead of a finding. That is an honest first behavior: the scanner cannot trust the HTTP response enough to analyze it.

```python
try:
    response = session.get(url, timeout=(3, 8), verify=True)
except requests.exceptions.SSLError:
    raise ScanError("TLS verification failed")
```

This catches connection-time validation failures such as an untrusted or hostname-mismatched certificate. It does **not** report how many days remain before a certificate expires, enumerate supported TLS versions, or assess cipher suites. Those require separate TLS inspection logic. Never use `verify=False` to make a scan “work.”

## 3. HTTP redirects and HTTPS availability

### Theory

If a site is intended to be HTTPS-only, visitors who start with `http://` should be directed to the HTTPS version. A redirect is not encryption by itself: the initial HTTP request can still be observed or modified before the browser reaches HTTPS. HSTS helps browsers remember to use HTTPS on later visits. [OWASP Web Security Testing Guide: TLS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Weak_Cryptography/01-Weak_Transport_Layer_Security/)

### A realistic situation

A visitor follows an old bookmark to `http://shop.example.test`. The server redirects to HTTPS, but a network attacker could interfere with the first unencrypted request before that redirect arrives. HSTS can reduce this risk after the browser has learned the policy; preloading is a separate deployment choice with consequences for every covered subdomain.

### Detection in Python

The current scanner disables automatic redirect following and reports a 3xx response. This is deliberate: following a `Location` automatically could send the scanner to a different host without validating it.

```python
response = session.get(url, allow_redirects=False, timeout=(3, 8))
if 300 <= response.status_code < 400:
    location = response.headers.get("Location")
    # Report the status and destination for review; do not follow it yet.
```

The current check reports **any** redirect. It does not prove the redirect is safe, that it points to HTTPS, or that every page uses HTTPS. A useful later feature is a carefully bounded HTTP-to-HTTPS check that validates each redirect destination before making another request.

## 4. Missing HSTS policy

### Theory

`Strict-Transport-Security` (HSTS) tells browsers that, for a configured period, they should use HTTPS for that site. Browsers only honor the policy when received over a valid HTTPS connection. `includeSubDomains` expands the policy to subdomains and should only be used when those subdomains are ready for HTTPS. [OWASP HSTS guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html)

### A realistic situation

A company’s login site supports HTTPS but also answers on HTTP. Without HSTS, a user can be exposed to a downgrade risk on a first visit that begins with HTTP. Missing HSTS is a useful hardening finding, but it does not by itself show that credentials have been intercepted or that the site is exploitable.

### Detection in Python

This check already exists in `_check_headers` and is only applied to HTTPS responses:

```python
if scheme == "https" and "Strict-Transport-Security" not in headers:
    add_finding(
        check_id="http.headers.hsts",
        severity=Severity.MEDIUM,
        title="HTTP Strict Transport Security is not enabled",
    )
```

The current code checks only for the header’s presence. A later version should parse `max-age`, notice `max-age=0`, and report `includeSubDomains` as context rather than blindly requiring it.

## 5. Missing or weak Content Security Policy (CSP)

### Theory

CSP lets a site constrain which sources a browser may load for scripts, styles, images, frames, and other resources. It can reduce the impact of some injection bugs, but it does not repair the underlying bug and a permissive policy may add little protection. An enforcing `Content-Security-Policy` header differs from `Content-Security-Policy-Report-Only`, which reports violations without blocking them. [OWASP CSP guidance](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)

### A realistic situation

A product page allows scripts from any origin using a broad wildcard policy. If an attacker can inject markup into the page or compromise a permitted script host, the browser’s policy may not meaningfully constrain the resulting script. Conversely, a site without CSP is not automatically vulnerable to cross-site scripting (XSS); CSP is a defense layer, not an XSS detector.

### Detection in Python

The current scanner reports an absent enforcing CSP header:

```python
policy = headers.get("Content-Security-Policy")
if policy is None:
    add_finding("http.headers.csp", "Content-Security-Policy is not set")
```

This is intentionally only an absence check. It does not evaluate directives, identify unsafe sources, or inspect a `Content-Security-Policy-Report-Only` policy. A useful next improvement is to distinguish “no policy” from “report-only policy exists” and label both accurately. Do not try to certify a complex CSP with a few substring checks.

## 6. Missing MIME-sniffing protection

### Theory

`X-Content-Type-Options: nosniff` tells browsers to respect the declared media type in situations where they might otherwise infer a type. Incorrect content types combined with sniffing can cause content to be interpreted differently from what the server intended. This is a supporting control, not a universal defense against script injection. [OWASP HTTP headers guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

### A realistic situation

A file-sharing site serves user-uploaded content with inconsistent `Content-Type` values. A browser that interprets a file as executable content may treat it differently from the site’s intended download. The risk depends on the served file, browser behavior, and origin isolation.

### Detection in Python

The current scanner reports the header as missing:

```python
value = headers.get("X-Content-Type-Options")
if value is None:
    add_finding("http.headers.content_type_options", "MIME sniffing protection is not set")
```

A stronger check should distinguish a missing header from a present but unexpected value; the common value is `nosniff`. It should also avoid claiming that missing `nosniff` proves a file can execute.

## 7. Clickjacking and frame embedding

### Theory

Clickjacking tricks a user into interacting with a sensitive page embedded in another page, often inside a transparent or misleading frame. `Content-Security-Policy: frame-ancestors ...` controls which ancestors may embed a page. `X-Frame-Options` is an older control still used for compatibility. [MDN clickjacking overview](https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/Clickjacking), [MDN `frame-ancestors`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors)

### A realistic situation

A logged-in user opens an attacker-controlled page while still signed in to an online service. If that service allows framing, the attacker may visually overlay the service’s account button beneath a misleading button. The impact depends on the framed page containing meaningful user actions and on browser protections.

### Detection in Python

The current code treats either a CSP string containing `frame-ancestors` or an `X-Frame-Options` header as protection:

```python
csp = headers.get("Content-Security-Policy", "").lower()
has_frame_protection = "frame-ancestors" in csp or "X-Frame-Options" in headers
if not has_frame_protection:
    add_finding("http.headers.frame_protection", "No framing restriction was found")
```

This is a rough presence check. It could accept a policy that permits all ancestors, and it does not assess whether the page has sensitive actions. A later parser should inspect the directive’s value and distinguish `frame-ancestors 'none'`, `'self'`, explicit origins, and permissive wildcards.

## 8. Referrer information exposure

### Theory

The `Referrer-Policy` response header controls how much of the current URL a browser may send in a `Referer` header when navigating or loading resources. URLs can contain search terms, identifiers, or other sensitive values. A suitable policy limits unintended disclosure while preserving expected site behavior. [OWASP HTTP headers guidance](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)

### A realistic situation

A support page puts an account identifier in its query string and embeds a third-party image. Depending on browser policy and navigation context, URL details could be included in the request sent to another origin. Avoid placing secrets in URLs in the first place; a policy is an additional control.

### Detection in Python

The current scanner reports when the header is absent:

```python
if "Referrer-Policy" not in headers:
    add_finding("http.headers.referrer_policy", "Referrer behavior is not explicitly configured")
```

Modern browsers have a default policy, so absence is not proof that the full URL is currently leaked. The scanner does not yet judge whether a present value is weak or invalid. Its finding is appropriately informational.

## 9. Cookie attributes: Secure, HttpOnly, and SameSite (next check)

### Theory

Cookies often carry session identifiers. `Secure` restricts transmission to HTTPS; `HttpOnly` prevents ordinary page JavaScript from reading the cookie; `SameSite` controls whether a browser sends it with cross-site requests. These attributes reduce specific risks but do not make a session safe by themselves. `SameSite` is defense in depth and does not replace a proper CSRF design. [OWASP session management guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), [OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

### A realistic situation

A site sets a session cookie without `Secure`. If a browser is induced to send that cookie over an unencrypted HTTP request, a network observer may be able to read it. A cookie without `HttpOnly` is accessible to JavaScript, which can increase the impact of an XSS bug. `SameSite=None` without `Secure` is also misconfigured for modern browser behavior.

### Detection in Python

This is **not implemented yet**. A response may contain several `Set-Cookie` headers, so inspect each separately rather than splitting a combined string on commas (cookie expiration dates themselves contain commas).

```python
from http.cookies import SimpleCookie

for raw_cookie in response.raw.headers.getlist("Set-Cookie"):
    parsed = SimpleCookie()
    parsed.load(raw_cookie)
    for cookie in parsed.values():
        if response.url.startswith("https://") and not cookie["secure"]:
            report_cookie_observation(cookie.key, "Secure is absent")
        if not cookie["httponly"]:
            report_cookie_observation(cookie.key, "HttpOnly is absent")
        if cookie["samesite"].lower() == "none" and not cookie["secure"]:
            report_cookie_observation(cookie.key, "SameSite=None is missing Secure")
```

Do not assume every cookie is an authentication cookie. A JavaScript-readable preference cookie may be intentional. Avoid printing cookie values in evidence; they may be credentials. Report the cookie name and missing attribute only.

## 10. Mixed content in returned HTML (next check)

### Theory

Mixed content occurs when an HTTPS page refers to a resource over HTTP. The insecure resource may be observed or modified in transit. Insecure scripts and styles are especially consequential because they can affect page behavior; browsers may block some resource types and upgrade others. [MDN mixed-content guidance](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Mixed_content)

### A realistic situation

A secure checkout page loads its payment logo from `http://static.example.test/logo.svg`. An attacker on the network could alter the image; if the insecure reference were instead a script, the attacker could affect code running in the page’s origin. This is a source-level observation; browser handling varies by resource type.

### Detection in Python

This requires reading and parsing the HTML body, which the current scanner does not do. The example uses Beautiful Soup; if you adopt it, add `beautifulsoup4` as a dependency.

```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit

soup = BeautifulSoup(html_text, "html.parser")
for tag in soup.find_all(src=True):
    resource_url = urljoin(page_url, tag["src"])
    if urlsplit(page_url).scheme == "https" and urlsplit(resource_url).scheme == "http":
        report("mixed-content", f"{tag.name} loads over HTTP: {resource_url}")
```

This starter example checks `src` attributes only. A real implementation should also examine stylesheet links, `srcset`, CSS `url(...)`, inline styles, and other relevant attributes. It should classify resource types and avoid labeling every insecure image the same as an executable script.

## 11. External scripts without Subresource Integrity (next check)

### Theory

Subresource Integrity (SRI) lets a page attach a cryptographic hash to a script or stylesheet so the browser can verify that the downloaded file matches the expected bytes. It is useful when a site depends on a cross-origin resource such as a CDN. Lack of SRI does not prove the provider has been compromised; it means the page lacks that integrity check. [MDN SRI guidance](https://developer.mozilla.org/en-US/docs/Web/Security/Defenses/Subresource_Integrity)

### A realistic situation

A marketing site loads a fixed analytics library from a third-party CDN. If that exact version is pinned and the host unexpectedly serves modified bytes, an `integrity` value can make the browser refuse the changed script. Dynamically versioned files or scripts that change frequently need a different deployment strategy.

### Detection in Python

This also requires HTML parsing and is not implemented yet:

```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit

soup = BeautifulSoup(html_text, "html.parser")
page_host = urlsplit(page_url).hostname
for script in soup.find_all("script", src=True):
    script_url = urljoin(page_url, script["src"])
    script_host = urlsplit(script_url).hostname
    if script_host != page_host and not script.get("integrity"):
        report("external-script-no-sri", script_url)
```

This is a review signal, not automatically a high-severity vulnerability. More careful logic should compare origins (scheme, hostname, and port), consider `crossorigin`, and explain that SRI is most suitable for resources whose bytes are stable.

## 12. Forms that submit sensitive data over HTTP (next check)

### Theory

An HTTPS page can still contain a form whose `action` points to HTTP. If a user submits a password or other sensitive value to that destination, the form submission is not protected by TLS. A form with an empty action submits to the current page, so resolve relative actions against the page URL before judging them.

### A realistic situation

A legacy login form is embedded in an otherwise HTTPS page but posts credentials to an old HTTP endpoint. The address bar looks secure while the submitted credentials travel without transport encryption.

### Detection in Python

This is a static HTML check and is not implemented yet:

```python
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit

soup = BeautifulSoup(html_text, "html.parser")
for form in soup.find_all("form"):
    action = urljoin(page_url, form.get("action") or page_url)
    if urlsplit(page_url).scheme == "https" and urlsplit(action).scheme == "http":
        report("form-downgrade", f"Form submits to an HTTP URL: {action}")
```

The snippet identifies the configured action; it does not submit the form or prove what the server does with the data. Do not send test credentials to a live site.

## 13. What this first scanner cannot determine

One passive request to a public page is not enough to establish most application vulnerabilities. In particular, this scanner cannot determine whether:

- a backend query is vulnerable to SQL injection;
- an input is exploitable for reflected or stored XSS;
- one user can access another user’s records (broken access control / IDOR);
- login, password reset, or session logic is correct;
- a state-changing endpoint has effective CSRF protection;
- a server-side dependency is vulnerable;
- an API endpoint leaks data that is not linked from the homepage;
- JavaScript loaded dynamically after browser execution is safe;
- every page or subdomain has the same configuration as the one URL checked.

These questions require source-code review, authenticated testing, carefully authorized test cases, or browser/runtime analysis. Do not try to infer “secure” from a quiet scan. The accurate result is “no issues found by these specific checks on this response.”

## 14. A logical implementation progression

Use this sequence to know what to build and what to expect at each step:

1. **One URL and one HTTP response — current step.** Validate the URL, verify TLS, make one bounded request, do not follow redirects, and report basic headers.
2. **Make current observations more precise.** Parse HSTS directives; evaluate CSP presence versus report-only; validate `nosniff`; parse frame controls; include HTTP status and requested URL in a scan summary.
3. **Inspect response cookies.** Preserve repeated `Set-Cookie` headers, redact values, and label cookie findings as contextual.
4. **Read and parse one HTML document.** Add a body-size cap and a parser; check mixed-content references, external script integrity metadata, and insecure form actions.
5. **Fetch referenced CSS/JS selectively.** Set maximum asset count, byte limits, timeouts, same-origin rules, redirect validation, and deduplication before adding network requests.
6. **Add tests with local fixtures.** Use mocked HTTP responses or a local test server. Never make project tests depend on live public targets.
7. **Only then consider a browser.** Use browser automation only for checks that need runtime DOM behavior; it executes website JavaScript and needs tighter isolation and resource controls.

At every step, implement one check, write a deterministic fixture, document what it can and cannot conclude, and keep the command-line output understandable.

## References

- [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [OWASP Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [OWASP Cross-Site Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html)
- [Requests documentation](https://requests.readthedocs.io/en/latest/)
- [Beautiful Soup documentation](https://www.crummy.com/software/BeautifulSoup/bs4/doc/)
