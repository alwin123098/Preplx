const form = document.querySelector('#scan-form');
const input = document.querySelector('#website');
const progress = document.querySelector('#progress');
const report = document.querySelector('#report');
const domainLabel = document.querySelector('#scan-domain');
const reportDomain = document.querySelector('#report-domain');
const percent = document.querySelector('#scan-percent');
const bar = document.querySelector('#bar-fill');
const steps = [...document.querySelectorAll('#scan-steps li')];

function normalise(value) {
  let url = value.trim();
  if (!/^https?:\/\//i.test(url)) url = `https://${url}`;
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return null; }
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const domain = normalise(input.value);
  if (!domain || !domain.includes('.')) {
    input.setCustomValidity('Enter a valid website address, such as yourwebsite.com');
    input.reportValidity();
    return;
  }
  input.setCustomValidity('');
  document.querySelector('#scan').classList.add('hidden');
  report.classList.add('hidden');
  progress.classList.remove('hidden');
  progress.classList.add('is-scanning');
  domainLabel.textContent = domain.toUpperCase();
  reportDomain.textContent = `— ${domain}`;
  progress.scrollIntoView({ behavior: 'smooth', block: 'center' });
  percent.textContent = 'Live check'; bar.style.width = '72%';
  steps.forEach((step, index) => { step.classList.toggle('active', index === 0); step.querySelector('span').textContent = index === 0 ? 'Checking' : 'Pending'; });
  try {
    const response = await fetch('/api/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ url: input.value }) });
    const audit = await response.json(); if (!response.ok || audit.error) throw new Error(audit.error || 'The audit could not be completed.');
    bar.style.width = '100%'; percent.textContent = 'Complete'; steps.forEach(step => { step.classList.remove('active'); step.querySelector('span').textContent = 'Checked'; });
    renderAudit(audit); progress.classList.remove('is-scanning'); progress.classList.add('hidden'); report.classList.remove('hidden'); report.classList.add('report-reveal'); report.scrollIntoView({ behavior: 'smooth', block: 'start' });
  } catch (error) {
    progress.querySelector('h2').textContent = 'We could not complete this check.';
    progress.classList.remove('is-scanning');
    progress.querySelector('ul').innerHTML = `<li class="active">${error.message}<span>Try another public website</span></li>`;
    bar.style.width = '0'; percent.textContent = 'Not run';
    document.querySelector('#scan').classList.remove('hidden');
  }
});

function renderAudit(audit) {
  document.querySelector('.score b').textContent = audit.score;
  document.querySelector('.score-label').innerHTML = `<i></i> ${audit.status}`;
  const urgent = audit.findings.filter(item => item.level === 'urgent').length;
  const recommended = audit.findings.filter(item => item.level === 'recommended').length;
  document.querySelector('.score-card small').textContent = urgent ? `${urgent} urgent issue${urgent > 1 ? 's' : ''} should be fixed first.` : 'No urgent public warning signs were found.';
  document.querySelector('.summary-card').innerHTML = `<div class="summary-stat"><strong>${urgent}</strong><span>urgent issue${urgent === 1 ? '' : 's'}</span></div><div class="summary-stat"><strong>${recommended}</strong><span>improvements</span></div><p>Checked live using SiteGuard’s local reasoning engine. These results come from public website signals, not an external AI service.</p>`;
  const esc = value => String(value || '').replace(/[&<>'"]/g, char => ({ '&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;' }[char]));
  const item = finding => { const steps = (finding.fixSteps || (finding.fix ? [finding.fix] : [])).map(step => `<li>${esc(step)}</li>`).join(''); return `<article class="finding ${finding.level === 'urgent' ? 'urgent' : ''}"><div class="finding-icon">${finding.level === 'urgent' ? '!' : finding.level === 'good' ? '✓' : '↗'}</div><div><div class="finding-title"><h4>${esc(finding.title)}</h4><span class="${finding.level === 'good' ? 'good' : ''}">${finding.level === 'good' ? 'LOOKING GOOD' : esc(finding.level).toUpperCase()}</span></div><p>${esc(finding.explanation)}</p>${finding.evidence ? `<div class="evidence"><b>Evidence</b>${esc(finding.evidence)}</div>` : ''}${steps ? `<details class="fix-method"><summary>Show fix method <b>→</b></summary><ol>${steps}</ol></details>` : ''}</div></article>`; };
  document.querySelector('.findings').innerHTML = `<div class="finding-heading"><h3>Your action list</h3><p>Results from a local, explainable security reasoning engine.</p></div>${audit.findings.map(item).join('')}`;
  loadHistory();
}

function loadHistory() {
  fetch('/api/history').then(response => response.json()).then(history => {
    const list = document.querySelector('#history-list');
    if (!history.length) return;
    list.innerHTML = history.map(item => {
      const date = new Date(item.checkedAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
      const urgent = item.findings.filter(finding => finding.level === 'urgent').length;
      return `<article class="history-row"><div class="history-domain">${item.domain}<small>${urgent ? `${urgent} urgent item${urgent > 1 ? 's' : ''}` : 'No urgent public warnings'}</small></div><div class="history-score">${item.score}</div><div class="history-state ${urgent ? 'urgent' : ''}">${item.status}<span class="history-date">Checked ${date}</span></div><a class="history-action" href="#scan">Recheck →</a></article>`;
    }).join('');
  }).catch(() => {});
}
loadHistory();

document.querySelector('#new-scan').addEventListener('click', () => {
  report.classList.add('hidden'); document.querySelector('#scan').classList.remove('hidden'); input.focus(); document.querySelector('#scan').scrollIntoView({ behavior: 'smooth', block: 'center' });
});
document.querySelector('#monitor-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const email = document.querySelector('#email');
  if (!email.checkValidity()) return email.reportValidity();
  const toast = document.querySelector('#toast'); toast.classList.remove('hidden'); event.target.reset(); setTimeout(() => toast.classList.add('hidden'), 4200);
});
