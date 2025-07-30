/* global io, Chart */
class Dashboard {
  constructor() {
    this.config = { tags: [], defaultUrl: 'https://example.com' };
    this.socket = null;
    this.chart  = null;

    /* WebGL preset descriptions (for the cards) */
    this.presetDetails = {
      'macbook-pro': {
        title: 'MacBook Pro (M1 Pro)',
        vendor: 'Apple Inc.',
        renderer: 'Apple M1 Pro',
        resolution: '2560 × 1600',
        features: ['Apple GPU', 'Metal API', 'Retina emulation']
      },
      'windows-pc': {
        title: 'Windows Gaming PC',
        vendor: 'NVIDIA Corp.',
        renderer: 'GeForce RTX 3080',
        resolution: '1920 × 1080',
        features: ['DirectX 12', 'DLSS', 'High-refresh']
      },
      'linux-pc': {
        title: 'Linux Workstation',
        vendor: 'Mesa/X.org',
        renderer: 'Radeon RX 6700 XT',
        resolution: '2560 × 1440',
        features: ['OpenGL 4.6', 'Vulkan', 'AMDGPU']
      }
    };
  }

  /* ─────────────────────────────────────────────────────────── */

  async init() {
    await this.loadConfig();
    this.initSocket();
    this.initChart();
    this.initForm();
    this.initPresets();
    await this.updateDashboard();
    setInterval(() => this.updateDashboard(), 5_000);
  }

  /* ── fetch basic config from backend ──────────────────────── */
  async loadConfig() {
    try {
      const res = await fetch('/api/config');
      if (!res.ok) throw new Error();
      this.config = await res.json();
      document.getElementById('urlInput').value = this.config.defaultUrl;
    } catch {
      this.showToast('Config Error', 'danger', 'Unable to load config');
    }
  }

  /* ── realtime WebSocket updates ───────────────────────────── */
  initSocket() {
    this.socket = io('/scanner', {
      reconnection: true,
      reconnectionAttempts: 5
    });

    this.socket
      .on('connect',    () => this.showToast('Connected',   'success', 'Real-time updates on-line'))
      .on('disconnect', () => this.showToast('Disconnected','warning', 'Connection lost'))
      .on('scanUpdate', data => this.updateScanUI(data))
      .on('scanError',  err  => this.showToast('Scan Error','danger',  err.message));
  }

  /* ── scan form (manual trigger) ───────────────────────────── */
  initForm() {
    const form = document.getElementById('scanForm');
    form.addEventListener('submit', async e => {
      e.preventDefault();
      const btn = form.querySelector('button[type="submit"]');
      btn.disabled = true;

      try {
        const fd = new FormData(form);
        const payload = {
          tag:         fd.get('tag'),
          url:         fd.get('url') || this.config.defaultUrl,
          webglPreset: fd.get('webglPreset'),
          timezone:    fd.get('timezone'),
          language:    fd.get('language'),
          proxy:       fd.get('proxy')
        };
        if (!payload.tag) throw new Error('Tag required');

        const res = await fetch('/api/scan', {
          method:  'POST',
          headers: { 'Content-Type':'application/json' },
          body:    JSON.stringify(payload)
        });
        if (!res.ok) throw new Error((await res.json()).error || 'Scan failed');

        const result = await res.json();
        this.showToast('Scan Complete', 'success', `${payload.tag}: ${result.status}`);
        this.updateScanUI(result);
      } catch (err) {
        this.showToast('Scan Failed', 'danger', err.message);
      } finally {
        btn.disabled = false;
      }
    });
  }

  /* ── doughnut chart ───────────────────────────────────────── */
  initChart() {
    const ctx = document.getElementById('verificationChart');
    this.chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['LIVE','UNVERIFIED','ERROR'],
        datasets: [{
          data: [0,0,0],
          backgroundColor: [
            'rgba(75,192,192,0.6)',   // greenish
            'rgba(255,206,86,0.6)',   // yellow
            'rgba(255,99,132,0.6)'    // red
          ],
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom' } }
      }
    });
  }

  /* ── WebGL preset cards ───────────────────────────────────── */
  initPresets() {
    const cards       = document.querySelectorAll('.preset-card');
    const presetInput = document.getElementById('webglPresetInput');

    cards.forEach(card => {
      card.onclick = () => {
        cards.forEach(c => c.classList.remove('active'));
        card.classList.add('active');
        const p = card.dataset.preset;
        presetInput.value = p;
        this.renderPresetDetails(p);
      };
    });

    /* default selection */
    const def = cards[0];
    def.classList.add('active');
    presetInput.value = def.dataset.preset;
    this.renderPresetDetails(def.dataset.preset);
  }

  renderPresetDetails(p) {
    const d = this.presetDetails[p];
    const c = document.getElementById('webglDetails');
    if (!d || !c) return;

    c.innerHTML = `
      <h6>${d.title}</h6>
      <ul class="list-unstyled mb-1">
        <li><strong>Vendor:</strong> ${d.vendor}</li>
        <li><strong>Renderer:</strong> ${d.renderer}</li>
        <li><strong>Resolution:</strong> ${d.resolution}</li>
      </ul>
      <strong>Features:</strong>
      <ul class="mb-0">${d.features.map(f => `<li>${f}</li>`).join('')}</ul>
    `;
  }

  /* ── periodic dashboard refresh ───────────────────────────── */
  async updateDashboard() {
    await Promise.all([
      this.updateStats(),
      this.updateChartData(),
      this.updateActivityLog()
    ]);
  }

  /* cards at top */
  async updateStats() {
    try {
      const res = await fetch('/api/stats');
      if (!res.ok) throw new Error();
      const { live, unverified, errors } = await res.json();

      document.getElementById('liveCount').textContent       = live;
      document.getElementById('unverifiedCount').textContent = unverified;
      document.getElementById('errorCount').textContent      = errors;
    } catch {
      this.showToast('Stats Error', 'danger', 'Could not load stats');
    }
  }

  /* doughnut refresh */
  async updateChartData() {
    try {
      const res = await fetch('/api/chart-data');
      if (!res.ok) throw new Error();
      const { summary } = await res.json();

      this.chart.data.datasets[0].data = [
        summary.LIVE        || 0,
        summary.UNVERIFIED  || 0,
        summary.ERROR       || 0
      ];
      this.chart.update();
    } catch {
      this.showToast('Chart Error', 'danger', 'Could not load chart data');
    }
  }

  /* last-5 activity rows */
  async updateActivityLog() {
    try {
      const res = await fetch('/api/scans?limit=5');
      if (!res.ok) throw new Error();
      const scans = await res.json();

      const tbody = document.getElementById('activityLog');
      tbody.innerHTML = scans.map(s => `
        <tr>
          <td>${new Date((s.created_at ?? s.ts ?? 0) * 1000).toLocaleString()}</td>
          <td>${s.tag}</td>
          <td>
            <span class="badge ${
        s.status === 'LIVE'        ? 'bg-success' :
          s.status === 'UNVERIFIED'  ? 'bg-warning' :
            'bg-danger'
      }">${s.status}</span>
          </td>
          <td>${s.confidence}%</td>
        </tr>
      `).join('');
    } catch {
      this.showToast('Log Error', 'danger', 'Could not load activity log');
    }
  }

  /* real-time single row append */
  updateScanUI(scan) {
    /* bump counters */
    const counterEl = document.getElementById(
      scan.status === 'LIVE'       ? 'liveCount' :
        scan.status === 'UNVERIFIED' ? 'unverifiedCount' :
          'errorCount'
    );
    if (counterEl) counterEl.textContent = (+counterEl.textContent + 1) || 1;

    /* prepend row */
    const tbody = document.getElementById('activityLog');
    if (!tbody) return;

    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${new Date(scan.ts || scan.timestamp || Date.now()).toLocaleString()}</td>
      <td>${scan.tag}</td>
      <td>
        <span class="badge ${
      scan.status === 'LIVE'        ? 'bg-success' :
        scan.status === 'UNVERIFIED'  ? 'bg-warning' :
          'bg-danger'
    }">${scan.status}</span>
      </td>
      <td>${scan.confidence}%</td>
    `;
    tbody.prepend(row);
  }

  /* Bootstrap-style toast helper */
  showToast(title, type, msg) {
    const container = document.getElementById('toastContainer');
    if (!container) return;

    const id   = `toast${Date.now()}`;
    const html = `
      <div id="${id}" class="toast show text-bg-${type}" role="alert" aria-live="assertive" aria-atomic="true">
        <div class="d-flex">
          <div class="toast-body">
            <strong>${title}</strong><br>${msg}
          </div>
          <button type="button" class="btn-close me-2 m-auto" data-bs-dismiss="toast"></button>
        </div>
      </div>`;

    container.insertAdjacentHTML('beforeend', html);

    /* auto-dismiss success/info toasts after 4 s */
    if (!['danger','warning'].includes(type)) {
      setTimeout(() => document.getElementById(id)?.remove(), 4_000);
    }
  }
}

/* bootstrap the dashboard once DOM is ready */
document.addEventListener('DOMContentLoaded', () => new Dashboard().init());
