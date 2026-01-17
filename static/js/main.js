function getToken() {
  return localStorage.getItem('jwt_token');
}

function setToken(t) {
  localStorage.setItem('jwt_token', t);
}

async function apiFetch(url, opts = {}) {
  const headers = opts.headers || {};
  const token = getToken();
  if (token) headers['Authorization'] = 'Bearer ' + token;
  return fetch(url, { ...opts, headers });
}

// Analyze form
document.addEventListener('DOMContentLoaded', () => {
  const analyzeForm = document.getElementById('analyze-form');
  const resultsDiv = document.getElementById('results');
  const mapDiv = document.getElementById('map');
  const timelineUl = document.getElementById('timeline');

  if (analyzeForm) {
    analyzeForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      resultsDiv.innerHTML = 'Analyzing...';
      timelineUl.innerHTML = '';
      if (mapDiv) mapDiv.innerHTML = '';

      const formData = new FormData(analyzeForm);
      const resp = await apiFetch('/api/analyze', { method: 'POST', body: formData });
      const data = await resp.json();
      if (!resp.ok) {
        resultsDiv.innerHTML = `<div class="text-danger">Error: ${data.error || 'Unknown error'}</div>`;
        return;
      }

      // Render basic fields
      const tbl = document.createElement('table');
      tbl.className = 'table table-sm';
      tbl.innerHTML = `
        <tr><th>From</th><td>${data.from || ''}</td></tr>
        <tr><th>To</th><td>${data.to || ''}</td></tr>
        <tr><th>Subject</th><td>${data.subject || ''}</td></tr>
        <tr><th>Date</th><td>${data.date || ''}</td></tr>
        <tr><th>Message-ID</th><td>${data.message_id || ''}</td></tr>
      `;
      resultsDiv.innerHTML = '';
      const tblWrap = document.createElement('div');
      tblWrap.className = 'table-responsive';
      tblWrap.appendChild(tbl);
      resultsDiv.appendChild(tblWrap);

      // IP table
      const ips = data.ip_trace || [];
      const ipTable = document.createElement('table');
      ipTable.className = 'table table-sm';
      ipTable.innerHTML = '<thead><tr><th>IP</th><th>Private</th><th>Geo</th></tr></thead>';
      const tb = document.createElement('tbody');
      (data.geolocation || []).forEach((g) => {
        const priv = ips.find(i => i.ip === g.ip)?.is_private;
        const geo = [g.city, g.region, g.country].filter(Boolean).join(', ');
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${g.ip || ''}</td><td>${priv ? 'Yes' : 'No'}</td><td>${geo || ''}</td>`;
        tb.appendChild(tr);
      });
      ipTable.appendChild(tb);
      const ipWrap = document.createElement('div');
      ipWrap.className = 'table-responsive';
      ipWrap.appendChild(ipTable);
      resultsDiv.appendChild(ipWrap);

      // Timeline
      (data.hops || []).forEach(h => {
        const li = document.createElement('li');
        li.className = 'list-group-item';
        li.textContent = `${h.timestamp || ''} — ${h.received || ''}`;
        timelineUl.appendChild(li);
      });

      // Map
      if (mapDiv) {
        const map = L.map('map');
        let points = [];
        (data.geolocation || []).forEach(g => {
          if (typeof g.latitude === 'number' && typeof g.longitude === 'number') {
            const marker = L.marker([g.latitude, g.longitude]).addTo(map);
            marker.bindPopup(`${g.ip}<br>${[g.city, g.region, g.country].filter(Boolean).join(', ')}`);
            points.push([g.latitude, g.longitude]);
          }
        });
        if (points.length > 0) {
          const bounds = L.latLngBounds(points);
          map.fitBounds(bounds.pad(0.3));
          L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
            attribution: '&copy; OpenStreetMap contributors'
          }).addTo(map);
          L.polyline(points, { color: 'red' }).addTo(map);
        } else {
          map.setView([20, 0], 2);
          L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
            maxZoom: 19,
            attribution: '&copy; OpenStreetMap contributors'
          }).addTo(map);
        }
      }
    });
  }

  // Login
  const loginForm = document.getElementById('login-form');
  if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(loginForm);
      const body = {
        email: form.get('email'),
        password: form.get('password'),
      };
      const resp = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await resp.json();
      if (resp.ok && data.token) {
        setToken(data.token);
        window.location.href = '/dashboard';
      } else {
        alert(data.error || 'Login failed');
      }
    });
  }

  // Register
  const registerForm = document.getElementById('register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const form = new FormData(registerForm);
      const body = {
        email: form.get('email'),
        password: form.get('password'),
      };
      const resp = await fetch('/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      const data = await resp.json();
      if (resp.ok && data.token) {
        setToken(data.token);
        window.location.href = '/dashboard';
      } else {
        alert(data.error || 'Register failed');
      }
    });
  }

  // Dashboard
  const historyTable = document.getElementById('history-table');
  const filterForm = document.getElementById('filter-form');
  async function loadHistory(params = {}) {
    const query = new URLSearchParams(params).toString();
    const resp = await apiFetch('/api/history' + (query ? ('?' + query) : ''));
    const data = await resp.json();
    const tbody = historyTable?.querySelector('tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (Array.isArray(data)) {
      data.forEach(r => {
        const ips = (r.ip_trace || []).map(i => i.ip).join(', ');
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${r.date || ''}</td><td>${r.from || ''}</td><td>${r.subject || ''}</td><td>${ips}</td><td>${r.timestamp || ''}</td>`;
        tbody.appendChild(tr);
      });
    }
  }
  if (historyTable) {
    loadHistory();
  }
  if (filterForm) {
    filterForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const fd = new FormData(filterForm);
      const params = {
        sender: fd.get('sender') || '',
        ip: fd.get('ip') || '',
        since: fd.get('since') || '',
        until: fd.get('until') || '',
      };
      Object.keys(params).forEach(k => { if (!params[k]) delete params[k]; });
      loadHistory(params);
    });
  }

  // Export
  const exportBtn = document.getElementById('export-btn');
  if (exportBtn) {
    exportBtn.addEventListener('click', async () => {
      const token = getToken();
      const resp = await fetch('/api/export', {
        headers: token ? { 'Authorization': 'Bearer ' + token } : {}
      });
      if (!resp.ok) {
        alert('Export failed');
        return;
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'analysis_export.csv';
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });
  }
});
