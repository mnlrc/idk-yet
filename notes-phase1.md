# Notes & personnal understanding

When looking for weaknesses of a website, we find a few recurrent elements.
Some can be identified only by accessing the response headers of a fetched website and
others can be found as a part of the HTML code of the website.

## Header vulnerabilities

These vulnerabilities are a great way to evaluate the security of a website
in a simple way.

By checking if:

- the website uses **HTTPS** (s for secure; using SSL/TLS: data encryption preventing man in the middle attacks)
- scenarios where the user logs into the website with **HTTP** before getting redirected to **HTTPS** may happen. In this case, the attacker can retrieve information before the user connects with **TLS**.
- **HSTS** (HTTP Strict Transport Security) is a web security policy that tells browsers to access a website only using HTTPS, not insecure HTTP, which helps protect against man-in-the-middle attacks like SSL stripping. It works when the server sends the Strict-Transport-Security response header, and the browser stores the rule for a set time (for example, using max-age) -- thank you wikipedia.
- **CSP** (Content Security Policy) is a computer security standard introduced to prevent cross-site scripting (**XSS**), clickjacking and other code injection attacks resulting from execution of malicious content in the trusted web page context.
- **Clickjacking**
- others...



## Website vulnerabilities

Some of these vulnerabilities can already be hinted at when reading the header. This
is the case of the **CME** (Common Weakness Enumeration) number 79 and 80 ie Cross-Site
Scripting (XSS) and HTML injections respectively.

These injections being similar to SQL injections in the way that we enter data in the
input fields that will be executed for *malicious* purposes.

