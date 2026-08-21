/*
 * SiteGuard local audit service.
 * Uses Node's built-in modules only: no third-party packages and no AI APIs.
 * It makes one normal GET request to the URL the user explicitly submits.
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const os = require('os');
const { execFile } = require('child_process');

const root = __dirname;
const historyFile = path.join(root, 'audit-history.json');
let activeZipAudits = 0;
const mime = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8' };

function cleanUrl(value) {
  const target = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  const url = new URL(target);
  if (!['http:', 'https:'].includes(url.protocol)) throw new Error('Only http and https websites can be checked.');
  return url;
}

function isPrivateIp(address) {
  if (address.includes(':')) return address === '::1' || address.startsWith('fc') || address.startsWith('fd') || address.startsWith('fe80:');
  const parts = address.split('.').map(Number);
  return parts[0] === 10 || parts[0] === 127 || parts[0] === 0 || (parts[0] === 169 && parts[1] === 254) || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168);
}
async function ensurePublicTarget(url) {
  const records = await dns.lookup(url.hostname, { all: true });
  if (!records.length || records.some(record => isPrivateIp(record.address))) throw new Error('Only public websites can be checked. Local and private network addresses are not allowed.');
}
function readHistory() { try { return JSON.parse(fs.readFileSync(historyFile, 'utf8')); } catch { return []; } }
function saveAudit(record) { const history = readHistory().filter(item => item.domain !== record.domain); history.unshift(record); fs.writeFileSync(historyFile, JSON.stringify(history.slice(0, 30), null, 2)); }
function run(command, args, options = {}) { return new Promise((resolve, reject) => execFile(command, args, { maxBuffer: 256 * 1024, timeout: 5000, ...options }, (error, stdout, stderr) => error ? reject(new Error(stderr || error.message)) : resolve(stdout))); }
function safeArchivePath(name) { return !!name && !name.includes('\0') && !name.startsWith('/') && !/^[a-zA-Z]:[\\/]/.test(name) && !name.split(/[\\/]/).includes('..') && !/[\u0000-\u001f]/.test(name); }
function requestAI(url, options, payload) { return new Promise((resolve, reject) => { const transport = url.protocol === 'https:' ? https : http; const req = transport.request(url, { method: 'POST', headers: { 'Content-Type': 'application/json', ...options.headers }, timeout: 30000 }, response => { let body = ''; response.setEncoding('utf8'); response.on('data', chunk => { if (body.length < 300000) body += chunk; }); response.on('end', () => { try { const parsed = JSON.parse(body); if (response.statusCode >= 400) return reject(new Error(parsed.error?.message || parsed.error || `AI provider returned HTTP ${response.statusCode}.`)); resolve(parsed); } catch { reject(new Error('The AI provider returned an unreadable response.')); } }); }); req.on('timeout', () => req.destroy(new Error('AI request timed out.'))); req.on('error', reject); req.end(JSON.stringify(payload)); }); }
async function aiReview(config, audit) {
  const provider = String(config.provider || 'openai'); const model = String(config.model || '').trim(); const key = String(config.apiKey || '').trim();
  if (!key || !model) throw new Error('Choose a model and enter an API key.');
  let endpoint = String(config.endpoint || '').trim();
  if (provider === 'openai') endpoint = 'https://api.openai.com/v1/chat/completions';
  if (provider === 'grok') endpoint = 'https://api.x.ai/v1/chat/completions';
  if (provider === 'openrouter') endpoint = 'https://openrouter.ai/api/v1/chat/completions';
  if (provider === 'ollama') endpoint = endpoint || 'http://127.0.0.1:11434/v1/chat/completions';
  if (provider === 'gemini') endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(key)}`;
  const target = cleanUrl(endpoint); if (target.protocol !== 'https:' && provider !== 'ollama') throw new Error('AI endpoints must use HTTPS.'); if (provider !== 'ollama') await ensurePublicTarget(target);
  const prompt = `You are a defensive website security advisor. Explain these already-detected findings in plain language for a small business owner. Do not invent vulnerabilities, claim you tested anything beyond the evidence, or provide attack instructions. Give a short priority order and safe remediation checklist. Findings:\n${JSON.stringify(audit).slice(0, 50000)}`;
  const result = provider === 'gemini' ? await requestAI(target, {}, { contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.2, maxOutputTokens: 900 } }) : await requestAI(target, { Authorization: `Bearer ${key}` }, { model, messages: [{ role: 'system', content: 'You provide defensive, evidence-based security guidance.' }, { role: 'user', content: prompt }], temperature: 0.2, max_tokens: 900 });
  const text = provider === 'gemini' ? result.candidates?.[0]?.content?.parts?.map(part => part.text || '').join('') : result.choices?.[0]?.message?.content;
  if (!text) throw new Error('The AI provider returned no review text.'); return { text };
}
function sourceFinding(file, contents) {
  const checks = [
    [/\beval\s*\(/, 'high', 'Dynamic code execution found', 'Avoid eval(). Use a strict allow-list or parse only trusted structured data.', 'Replace eval(input) with JSON.parse(input) when you expect JSON.'],
    [/child_process|\bexec\s*\(|\bshell_exec\s*\(/, 'high', 'System command execution found', 'Commands built from user-controlled data can let an attacker run code on the server.', 'Use a fixed allow-list of actions; never pass user input to a shell command.'],
    [/base64_decode\s*\(.{0,200}eval|eval\s*\(.{0,200}base64/i, 'high', 'Obfuscated executable code found', 'Encoded code that is immediately executed is a common malware pattern.', 'Remove it unless you can verify its source and purpose.'],
    [/password\s*=\s*["'][^"']{6,}|api[_-]?key\s*[=:]\s*["'][^"']{8,}|sk-[a-zA-Z0-9_-]{12,}/i, 'medium', 'Possible secret stored in source code', 'Keys and passwords in a ZIP can be exposed through source control or sharing.', 'Move the value to an environment variable, rotate the existing secret, and add it to .gitignore.'],
    [/SELECT\s+.*\+|INSERT\s+.*\+|\$query\s*=\s*.*\$_(?:GET|POST|REQUEST)/i, 'medium', 'Possible unsafe database query', 'Building database queries with request data can expose your database to injection attacks.', 'Use parameterized queries or your framework’s query builder.'],
    [/innerHTML\s*=|document\.write\s*\(/, 'low', 'Potential unsafe browser HTML insertion', 'Untrusted text inserted as HTML can let attackers run scripts in a visitor’s browser.', 'Use textContent or sanitize HTML with a trusted, allow-list based sanitizer.']
  ];
  return checks.filter(([pattern]) => pattern.test(contents)).map(([, severity, title, explanation, fix]) => ({ file, severity, title, explanation, fix }));
}
async function auditZip(body, boundary) {
  const marker = Buffer.from(`--${boundary}`); const start = body.indexOf(marker); const headerEnd = body.indexOf(Buffer.from('\r\n\r\n'), start);
  if (start < 0 || headerEnd < 0) throw new Error('A ZIP file is required.');
  const header = body.subarray(start, headerEnd).toString(); const name = (header.match(/filename="([^"]+)"/) || [])[1] || '';
  const fileStart = headerEnd + 4; const fileEnd = body.indexOf(marker, fileStart) - 2;
  if (!name.toLowerCase().endsWith('.zip') || fileEnd <= fileStart) throw new Error('Please upload a .zip file.');
  const temp = path.join(os.tmpdir(), `siteguard-${Date.now()}-${Math.random().toString(16).slice(2)}.zip`);
  fs.writeFileSync(temp, body.subarray(fileStart, fileEnd), { mode: 0o600 });
  try {
    await run('unzip', ['-tqq', temp], { timeout: 8000 });
    const names = (await run('unzip', ['-Z1', temp], { timeout: 4000 })).split('\n').filter(Boolean);
    if (names.length > 1000) throw new Error('This ZIP contains too many files.');
    if (names.some(name => !safeArchivePath(name))) throw new Error('This ZIP contains an unsafe path. Remove absolute paths or ../ entries and try again.');
    const allowed = names.filter(name => /\.(js|ts|jsx|tsx|php|py|rb|java|go|html|css|json|env|yml|yaml)$/i.test(name)).slice(0, 120);
    const findings = [];
    for (const name of allowed) { const text = await run('unzip', ['-p', temp, '--', name], { maxBuffer: 220 * 1024, timeout: 3000 }); findings.push(...sourceFinding(name, text.slice(0, 200000))); }
    const unique = findings.filter((finding, index, all) => index === all.findIndex(other => other.file === finding.file && other.title === finding.title));
    const high = unique.filter(finding => finding.severity === 'high').length, medium = unique.filter(finding => finding.severity === 'medium').length;
    return { filename: name, filesChecked: allowed.length, score: Math.max(15, 100 - high * 24 - medium * 12 - (unique.length - high - medium) * 5), findings: unique };
  } finally { try { fs.unlinkSync(temp); } catch {} }
}

function requestSite(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.get(url, { headers: { 'User-Agent': 'SiteGuard-Local-Audit/1.0', Accept: 'text/html,*/*' }, timeout: 10000 }, response => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location && redirects < 3) {
        response.resume(); return resolve(requestSite(new URL(response.headers.location, url), redirects + 1));
      }
      let body = ''; response.setEncoding('utf8');
      response.on('data', chunk => { if (body.length < 600000) body += chunk; });
      response.on('end', () => resolve({ url, status: response.statusCode, headers: response.headers, body, certificate: response.socket?.getPeerCertificate?.() }));
    });
    request.on('timeout', () => request.destroy(new Error('The website took too long to respond.')));
    request.on('error', reject);
  });
}

// The local reasoning model: readable signals -> weighted risk -> plain-language recommendation.
function reason(site) {
  const h = site.headers, html = site.body.toLowerCase(), findings = [];
  const add = (level, title, explanation, fix, points, evidence, fixSteps) => findings.push({ level, title, explanation, fix, points, evidence, fixSteps: fixSteps || [fix] });
  if (site.status >= 400) add('urgent', `Your website returned an error (${site.status})`, 'Visitors and search engines may not be able to access this page correctly.', 'Check your hosting logs and recent website changes.', 20, `Observed HTTP status: ${site.status}`, ['Check the server error log for this request.', 'Review the most recent deploy or website change.', 'Fix the underlying error, then re-run this public check.']);
  if (site.url.protocol !== 'https:') add('urgent', 'Your website does not use a secure connection', 'Information sent to this site can be read or changed on the way there.', 'Enable HTTPS and redirect every HTTP address to HTTPS.', 35, `Final page address uses: ${site.url.protocol}`, ['Install a valid TLS certificate with your host.', 'Redirect all HTTP requests to HTTPS at the web server or CDN.', 'Test forms and checkout pages again after the redirect.']);
  else {
    add('good', 'Your site uses a secure connection', 'Visitors can send information to your website over an encrypted connection.', '', -4);
    const certificateExpiry = site.certificate?.valid_to;
    if (certificateExpiry) { const expires = new Date(certificateExpiry); const remaining = (expires - Date.now()) / 86400000; if (Number.isFinite(remaining) && remaining < 30) add('urgent', 'Your security certificate expires soon', `Your HTTPS certificate expires in about ${Math.max(0, Math.ceil(remaining))} days.`, 'Renew the certificate with your hosting provider before it expires.', 25, `Certificate expiry presented by server: ${certificateExpiry}`, ['Renew the certificate in your host, CDN, or certificate manager.', 'Deploy the renewed certificate to every domain and subdomain.', 'Confirm the site loads with no browser certificate warning.']); }
  }
  if (!h['strict-transport-security']) add('recommended', 'Add a rule that always uses your secure connection', 'Without this rule, a visitor can sometimes be sent to an unprotected version of the site first.', 'Ask your host or developer to add the HSTS response header.', 8, 'Header not present: Strict-Transport-Security', ['Add Strict-Transport-Security at your web server or CDN.', 'Start with max-age=31536000; includeSubDomains after testing.', 'Only enable it once every page works over HTTPS.']);
  if (!h['content-security-policy']) add('recommended', 'Add protection against injected scripts', 'A browser security rule can reduce harm if malicious code is added to a page.', 'Ask your developer to add a Content-Security-Policy header.', 9, 'Header not present: Content-Security-Policy', ["Begin with a report-only Content-Security-Policy to see what would break.", "Allow only the script, style, image, and API domains your site actually needs.", 'Move to an enforcing policy after reviewing reports.']);
  if (!h['x-content-type-options']) add('recommended', 'Tell browsers to handle files safely', 'A small missing browser rule can make some file-based attacks easier.', 'Add X-Content-Type-Options: nosniff.', 4, 'Header not present: X-Content-Type-Options', ['Add X-Content-Type-Options: nosniff in your server or CDN response headers.', 'Confirm CSS, JavaScript, and downloads retain correct MIME types.']);
  if (!h['x-frame-options'] && !/frame-ancestors/i.test(h['content-security-policy'] || '')) add('recommended', 'Prevent your pages being embedded in fake sites', 'Attackers can place a copy of your page inside another site to trick customers.', 'Add X-Frame-Options: DENY or a frame-ancestors policy.', 5, 'No X-Frame-Options header or CSP frame-ancestors rule found', ['Use Content-Security-Policy: frame-ancestors \'none\' for pages that should not be embedded.', 'Use a named allow-list only if trusted partner sites must embed the page.']);
  const cookieText = Array.isArray(h['set-cookie']) ? h['set-cookie'].join('; ') : h['set-cookie'] || '';
  if (/set-cookie/i.test(JSON.stringify(h)) && (!/;\s*secure/i.test(cookieText) || !/;\s*httponly/i.test(cookieText))) add('recommended', 'Strengthen the cookies used by your visitors', 'At least one cookie may be missing browser protections that help protect signed-in visitors.', 'Set Secure and HttpOnly on session cookies.', 7, 'A Set-Cookie response was present without Secure and/or HttpOnly attributes', ['Set Secure and HttpOnly on every session or authentication cookie.', 'Set SameSite=Lax or SameSite=Strict unless a cross-site flow needs another value.', 'Log out and back in to verify the site still works.']);
  if (!h['referrer-policy']) add('recommended', 'Limit information shared when visitors leave your site', 'Browsers may share more of a page address than necessary when someone follows a link away.', 'Add a Referrer-Policy header such as strict-origin-when-cross-origin.', 3, 'Header not present: Referrer-Policy', ['Add Referrer-Policy: strict-origin-when-cross-origin at your server or CDN.', 'Test any analytics or payment-provider redirects afterward.']);
  if (/<form[\s\S]*?action=["']http:\/\//i.test(site.body)) add('urgent', 'A form sends data through an insecure address', 'Customer details submitted through this form may not stay private.', 'Change the form action to an HTTPS address.', 25, 'Public page HTML contains a form action beginning with http://', ['Change the form action to an HTTPS URL or a relative URL.', 'Confirm the receiving endpoint redirects HTTP to HTTPS.', 'Submit a harmless test form and confirm its final request is encrypted.']);
  if (h['access-control-allow-origin'] === '*' && String(h['access-control-allow-credentials']).toLowerCase() === 'true') add('urgent', 'Your CORS policy may expose authenticated data', 'The server permits every origin while also allowing credentials, which is an unsafe cross-site configuration.', 'Restrict CORS to trusted origins and never combine wildcard origins with credentials.', 20, 'Headers: Access-Control-Allow-Origin: * and Access-Control-Allow-Credentials: true', ['Replace * with the exact trusted website origins.', 'Return Access-Control-Allow-Credentials only where cookies or authorization are required.', 'Test browser requests from both trusted and untrusted origins.']);
  if (h.server) add('low', 'Your server software is publicly identified', 'Version or server details can help attackers tailor an attack after another weakness is found.', 'Remove unnecessary Server response details where your platform allows it.', 2, `Server header observed: ${String(h.server).slice(0, 120)}`, ['Configure your web server or CDN to remove or generalize the Server header.', 'Keep server software patched even after hiding this detail.']);
  if (/wp-content\/plugins\/[^/]+\/.*?(?:ver=|\.js|\.css)/i.test(site.body)) add('recommended', 'Keep your website plugins up to date', 'Your public pages show that this site uses plugins. Outdated plugins are a common way websites are compromised.', 'Check your CMS dashboard for plugin updates and remove unused plugins.', 8, 'Public page references WordPress plugin assets', ['In WordPress, update every active plugin from Dashboard → Updates.', 'Remove inactive plugins rather than leaving them installed.', 'Keep a backup and test major updates on a staging site first.']);
  if (!findings.some(f => f.level === 'urgent')) add('good', 'No immediate public warning signs found', 'This quick check did not find a visible urgent issue. Continue monitoring because websites change.', '', -3);
  const raw = findings.reduce((total, item) => total + item.points, 0);
  const score = Math.max(18, Math.min(100, 100 - raw));
  return { score, status: score < 60 ? 'Urgent action needed' : score < 80 ? 'Needs attention' : 'Looking good', checkedAt: new Date().toISOString(), findings: findings.sort((a, b) => b.points - a.points) };
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/api/audit') {
    let raw = ''; req.on('data', c => raw += c); req.on('end', async () => {
      try {
        const { url } = JSON.parse(raw); const target = cleanUrl(url); await ensurePublicTarget(target); const site = await requestSite(target); const audit = reason(site);
        const result = { domain: site.url.hostname.replace(/^www\./, ''), statusCode: site.status, ...audit }; saveAudit(result);
        res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(result));
      } catch (error) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: error.message || 'Unable to check this website.' })); }
    }); return;
  }
  if (req.method === 'GET' && req.url === '/api/history') { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify(readHistory())); }
  if (req.method === 'POST' && req.url === '/api/ai-review') {
    let raw = ''; req.on('data', chunk => { if (raw.length < 70000) raw += chunk; }); req.on('end', async () => { try { const body = JSON.parse(raw); const result = await aiReview(body.config || {}, body.audit || {}); res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(result)); } catch (error) { res.writeHead(400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: error.message })); } }); return;
  }
  if (req.method === 'POST' && req.url === '/api/zip-audit') {
    if (activeZipAudits >= 2) { res.writeHead(429, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: 'Two ZIP reviews are already running. Please try again shortly.' })); }
    activeZipAudits += 1;
    const type = req.headers['content-type'] || ''; const match = type.match(/boundary=(.+)$/);
    if (!match) { res.writeHead(400, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ error: 'Upload data was not recognised.' })); }
    const chunks = []; let length = 0;
    req.on('data', chunk => { length += chunk.length; if (length <= 8 * 1024 * 1024) chunks.push(chunk); });
    req.setTimeout(15000, () => req.destroy(new Error('ZIP upload timed out.')));
    req.on('end', async () => { try { if (length > 8 * 1024 * 1024) throw new Error('Please upload a ZIP smaller than 8 MB.'); const result = await auditZip(Buffer.concat(chunks), match[1]); res.writeHead(200, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(result)); } catch (error) { res.writeHead(error.message.includes('timed out') ? 408 : 400, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: error.message })); } finally { activeZipAudits -= 1; } }); return;
  }
  const requested = req.url === '/' ? '/index.html' : decodeURIComponent(req.url.split('?')[0]);
  const file = path.resolve(root, `.${requested}`);
  if (!file.startsWith(root) || !fs.existsSync(file)) { res.writeHead(404); return res.end('Not found'); }
  res.writeHead(200, { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store, max-age=0' }); fs.createReadStream(file).pipe(res);
});
server.listen(3000, () => console.log('SiteGuard is running at http://localhost:3000'));
