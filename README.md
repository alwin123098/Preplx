# SiteGuard local reasoning prototype

Run with Node 18+:

```sh
node server.js
```

Then open `http://localhost:3000`.

This prototype uses no external AI or security-scanning API. Its local reasoning engine evaluates actual, publicly visible signals such as HTTPS and certificate expiry, HTTP status, security headers, cookie settings, insecure form actions, and visible CMS plugin usage. It makes a single ordinary request only to a public website the user enters. It blocks local/private network addresses and does not attempt to log in, exploit vulnerabilities, scan ports, or modify the website. It does not claim to perform malware-database or full vulnerability-database checks.

The report UI displays live local-engine findings. The local security desk stores up to 30 recent audit summaries in `audit-history.json` on this device.
