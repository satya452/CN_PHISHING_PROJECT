/* ============================================================
   PhishGuard — dashboard.js
   ============================================================ */

// ── DOM refs ──────────────────────────────────────────────
const form = document.getElementById('scan-form');
const input = document.getElementById('url');
const button = document.getElementById('scan-button');
const errorBox = document.getElementById('error');
const errorText = document.getElementById('error-text');
const resultBox = document.getElementById('result');
const loader = document.getElementById('loader');

// ── Particle canvas background ────────────────────────────
(function initCanvas() {
  const canvas = document.getElementById('bg-canvas');
  const ctx = canvas.getContext('2d');
  let W, H, particles = [];

  function resize() {
    W = canvas.width = window.innerWidth;
    H = canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  const N = 60;
  for (let i = 0; i < N; i++) {
    particles.push({
      x: Math.random() * 1920,
      y: Math.random() * 1080,
      vx: (Math.random() - .5) * .35,
      vy: (Math.random() - .5) * .35,
      r: Math.random() * 1.5 + .5,
    });
  }

  function draw() {
    ctx.clearRect(0, 0, W, H);
    // draw particles
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = W; if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H; if (p.y > H) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(61,214,220,0.55)';
      ctx.fill();
    });
    // draw connecting lines
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 130) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(61,214,220,${.18 * (1 - dist / 130)})`;
          ctx.lineWidth = .7;
          ctx.stroke();
        }
      }
    }
    requestAnimationFrame(draw);
  }
  draw();
})();

// ── Helpers ───────────────────────────────────────────────
const pretty = v => String(v ?? '—');

function showError(msg) {
  errorText.textContent = msg;
  errorBox.classList.remove('hidden');
}
function clearError() {
  errorText.textContent = '';
  errorBox.classList.add('hidden');
}

function setRiskRing(score, band) {
  const fill = document.getElementById('ring-fill');
  const circ = 2 * Math.PI * 50; // r=50
  const offset = circ - (score / 100) * circ;
  fill.style.strokeDasharray = circ;
  fill.style.strokeDashoffset = offset;
  fill.style.stroke =
    band === 'High' ? '#f25f5c' :
      band === 'Medium' ? '#f0a500' : '#30d980';
}

// ── Render result ─────────────────────────────────────────
function renderResult(data) {
  resultBox.classList.remove('hidden');

  // timestamp
  document.getElementById('timestamp').textContent = data.timestamp || '';

  // score + ring
  const score = data.risk_score ?? 0;
  document.getElementById('score').textContent = score;
  setRiskRing(score, data.risk_band);

  // linear meter fallback
  const fill = document.getElementById('meter-fill');
  fill.style.width = `${score}%`;
  fill.style.background =
    data.risk_band === 'High' ? '#f25f5c' :
      data.risk_band === 'Medium' ? '#f0a500' : '#30d980';

  // badge
  const badge = document.getElementById('band');
  badge.textContent = data.risk_band || 'Low';
  badge.className = 'risk-badge';
  if (data.risk_band === 'High') badge.classList.add('high');
  if (data.risk_band === 'Medium') badge.classList.add('medium');

  // advice
  document.getElementById('advice').textContent = data.advice || '';

  // DNS details
  document.getElementById('hostname').textContent = data.hostname || '—';
  document.getElementById('dns-status').textContent = data.dns?.status || data.dns_status || 'unknown';
  document.getElementById('addresses').textContent = (data.dns?.addresses || []).join(', ') || 'No address returned';
  document.getElementById('total-time').textContent = `${data.timings_ms?.total ?? '—'} ms`;
  const rep = data.reputation || {};
  document.getElementById('rep-status').textContent = rep.message || rep.status || 'Not available';

  // Reasons
  const reasons = document.getElementById('reasons');
  reasons.replaceChildren();
  (data.reasons || []).forEach(item => {
    const li = document.createElement('li');
    if (item.points !== null && item.points !== undefined) {
      const pts = document.createElement('span');
      pts.className = 'points';
      pts.textContent = `+${item.points}`;
      li.appendChild(pts);
    }
    li.appendChild(document.createTextNode(item.reason));
    reasons.appendChild(li);
  });

  // Feature signals
  const featuresEl = document.getElementById('features');
  featuresEl.replaceChildren();
  const labels = {
    url_length: 'URL Length', hostname_length: 'Hostname Length',
    dot_count: 'Dots in Host', subdomain_count: 'Subdomains',
    hyphen_count: 'Hyphens', at_symbol: '@ Symbol',
    ip_literal: 'IP Host', https: 'HTTPS Scheme',
    punycode: 'Punycode', encoded_chars: 'Encoded Chars',
    double_slash_path: 'Repeated Slash',
    suspicious_terms: 'Suspicious Terms', numeric_hostname: 'Numeric Host',
  };
  Object.entries(data.features || {}).forEach(([key, value]) => {
    const div = document.createElement('div');
    div.className = 'feature';

    const lbl = document.createElement('b');
    lbl.textContent = labels[key] || key;

    const val = document.createElement('span');
    if (typeof value === 'boolean') {
      val.textContent = value ? 'Detected' : 'Not detected';
      val.className = value ? 'detected' : 'undetected';
    } else {
      val.textContent = pretty(value);
    }
    div.append(lbl, val);
    featuresEl.appendChild(div);
  });

  // Disclaimer
  document.getElementById('disclaimer').textContent = data.disclaimer || '';

  // Scroll
  resultBox.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── History ───────────────────────────────────────────────
async function loadHistory() {
  const tbody = document.getElementById('history-body');
  try {
    const res = await fetch('/api/history');
    const items = await res.json();
    tbody.replaceChildren();
    if (!items.length) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 5; td.className = 'empty-row';
      td.textContent = 'No scans yet.';
      tr.appendChild(td); tbody.appendChild(tr); return;
    }
    items.forEach(item => {
      const tr = document.createElement('tr');
      const time = item.timestamp ? new Date(item.timestamp).toLocaleTimeString() : '—';
      [time, item.hostname, item.risk_score, item.dns_status,
        item.total_ms == null ? '—' : `${item.total_ms} ms`
      ].forEach(v => {
        const td = document.createElement('td');
        td.textContent = pretty(v);
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
  } catch {
    const td = document.createElement('td');
    td.colSpan = 5; td.className = 'empty-row';
    td.textContent = 'History unavailable.';
    const tr = document.createElement('tr');
    tr.appendChild(td); tbody.replaceChildren(tr);
  }
}

// ── Form submit ───────────────────────────────────────────
form.addEventListener('submit', async event => {
  event.preventDefault();
  clearError();
  resultBox.classList.add('hidden');
  loader.classList.remove('hidden');
  button.disabled = true;
  button.innerHTML = `
    <span class="btn-text">Scanning…</span>
    <span class="btn-icon">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="animation:spin .8s linear infinite">
        <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
      </svg>
    </span>`;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: input.value.trim() }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Could not scan this URL.');
    renderResult(data);
    await loadHistory();
  } catch (err) {
    showError(err.message || 'Network error. Is the local server running?');
  } finally {
    loader.classList.add('hidden');
    button.disabled = false;
    button.innerHTML = `
      <span class="btn-text">Analyze</span>
      <span class="btn-icon">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <path d="M5 12h14M12 5l7 7-7 7"/>
        </svg>
      </span>`;
  }
});

document.getElementById('refresh-history').addEventListener('click', loadHistory);

// ── Spin keyframe (injected once) ─────────────────────────
const spinStyle = document.createElement('style');
spinStyle.textContent = '@keyframes spin { to { transform: rotate(360deg); } }';
document.head.appendChild(spinStyle);

loadHistory();
