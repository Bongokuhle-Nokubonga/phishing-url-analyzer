# Phishing URL Analyzer

A security-awareness tool that checks a link for common phishing tricks and **explains every
warning in plain language**. It runs entirely in the browser: the link is never opened or sent anywhere.

**Try it:** https://bongokuhle-nokubonga.github.io/phishing-url-analyzer/

## What it checks

| Check | Example | Why it matters |
|---|---|---|
| Brand name on someone else's domain | `paypal.com.account-verify.xyz` | The real domain is `account-verify.xyz`; "paypal.com" is decoration |
| Look-alike spelling | `rnicrosoft`, `paypa1`, `netfliix` | `rn`→`m`, `1`→`l` and extra letters fool a quick glance |
| International look-alike characters | `xn--pple-43d.com` | Punycode hides Cyrillic letters that look Latin |
| `@` in the link | `microsoft.com@evil.example` | Browsers ignore everything before the `@` |
| Raw IP address and unusual ports | `http://192.168.10.5:8080/` | Real companies use domain names |
| Link shorteners | `bit.ly/…` | The destination is hidden until you click |
| Risky domain endings | `.xyz`, `.top`, `.zip` | Cheap and heavily abused |
| Pressure words | `verify`, `suspended`, `reset` | Phishing pushes urgency |
| Embedded redirects, file downloads, `javascript:` links | `?next=https://…`, `invoice.exe` | Bounce you elsewhere or run code |
| No HTTPS | `http://` | Passwords would travel unencrypted |

Includes **South African brands** often used in local phishing (FNB, Absa, Capitec, Standard Bank,
Nedbank, SARS), and handles domains like `fnb.co.za` correctly so real bank sites aren't flagged.

Each finding adds points; the total (capped at 100) gives **Low / Medium / High** risk.

## Security of the tool itself

The input is attacker-controlled, so the page never uses `innerHTML`: every value is inserted
with `textContent`, so a malicious "URL" can't inject script into the page.

## Tests

The logic lives in [`analyzer.js`](analyzer.js), separate from the page. **10 test groups** cover real
sites (which must score Low with no brand warnings), impersonation, look-alikes, SA banks, IP and
`@` tricks, punycode, shorteners, downloads, redirects and invalid input.

- In the browser: [`tests.html`](https://bongokuhle-nokubonga.github.io/phishing-url-analyzer/tests.html)
- In Node: `node tests/run.mjs` (runs on every push with GitHub Actions)

## Limitations

These are heuristics, the same red flags taught in security-awareness training. A Low score
does not prove a link is safe, and it doesn't check live threat-intelligence feeds.
