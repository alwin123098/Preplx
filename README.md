# SiteGuard local reasoning prototype

Run with Node 18+:

```sh
node server.js
```

Then open `http://localhost:3000`.

This prototype uses no external AI or security-scanning API. Its local reasoning engine evaluates actual, publicly visible signals such as HTTPS and certificate expiry, HTTP status, security headers, cookie settings, insecure form actions, and visible CMS plugin usage. It makes a single ordinary request only to a public website the user enters. It blocks local/private network addresses and does not attempt to log in, exploit vulnerabilities, scan ports, or modify the website. It does not claim to perform malware-database or full vulnerability-database checks.

The report UI displays live local-engine findings. The local security desk stores up to 30 recent audit summaries in `audit-history.json` on this device.

ZIP safety controls include an 8 MB request limit, two-review concurrency limit, ZIP integrity testing, 5–8 second subprocess timeouts, 256 KB output limits, private temporary files, unsafe archive path rejection, and cleanup in a `finally` block. Uploaded code is read as text only; it is never loaded by Node, imported, evaluated, or executed. This is defense-in-depth for a local prototype, not a guarantee of complete malware detection or a replacement for an isolated production sandbox.

## Bring your own AI

After a website scan, users can ask their own model for a second opinion. Supported presets include OpenAI, Grok/xAI, Groq, Gemini, OpenRouter, Ollama-compatible endpoints, and custom HTTPS OpenAI-compatible endpoints. The API key is sent only for that request, is cleared from the form after success, is not saved in `audit-history.json`, and is not committed to the repository. Only the structured scan findings are sent by default; ZIP contents are not sent.
