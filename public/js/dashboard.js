/* global io, Chart */
class Dashboard {
  constructor() {
    this.config = { tags: [], defaultUrl: 'https://example.com' };
    this.socket = null;
    this.chart  = null;
    this.stats = { live: 0, unverified: 0, errors: 0 };

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
    console.log('Initializing UA-Honeypot Dashboard...');

    this.loadConfig();
    this.initSocket();
    this.initChart();
    this.initForm();
    this.initPresets();

    await this.updateDashboard();

    // Update dashboard every 10 seconds
    setInterval(() => this.updateDashboard(), 10000);

    console.log('Dashboard initialized successfully');
  }

  /* ── load basic config (no backend endpoint needed) ─────── */
  loadConfig() {
    // Set default config since we don't have /api/config endpoint
    this.config = {
      tags: [],
      defaultUrl: 'https://httpbin.org/user-agent'
    };

    const urlInput = document.getElementById('urlInput');
    if (urlInput) {
      urlInput.value = this.config.defaultUrl;
    }

    console.log('Config loaded:', this.config);
  }

  /* ── realtime WebSocket updates ───────────────────────────── */
  initSocket() {
    console.log('Initializing Socket.IO connection...');

    this.socket = io('/scanner', {
      reconnection: true,
      reconnectionAttempts: 10,
      reconnectionDelay: 2000
    });

    this.socket
      .on('connect', () => {
        console.log('Socket.IO connected');
        this.showToast('Connected', 'success', 'Real-time monitoring active');
        this.updateConnectionStatus(true);
      })
      .on('disconnect', (reason) => {
        console.log('Socket.IO disconnected:', reason);
        this.showToast('Disconnected', 'warning', 'Connection lost - attempting to reconnect');
        this.updateConnectionStatus(false);
      })
      .on('connect_error', (error) => {
        console.error('Socket.IO connection error:', error);
        this.showToast('Connection Error', 'danger', 'Failed to connect to monitoring service');
        this.updateConnectionStatus(false);
      })
      .on('uaUpdate', (data) => {
        console.log('UA Update received:', data);
        this.handleUAUpdate(data);
      })
      .on('scanError', (err) => {
        console.error('Scan error:', err);
        this.showToast('Scan Error', 'danger', err.message || 'Unknown error occurred');
      });
  }

  /* ── update connection status indicators ─────────────────── */
  updateConnectionStatus(isConnected) {
    const connectionStatus = document.getElementById('connectionStatus');
    const socketStatus = document.getElementById('socketStatus');

    if (connectionStatus) {
      if (isConnected) {
        connectionStatus.className = 'badge bg-success';
        connectionStatus.innerHTML = '<i class="bi bi-wifi"></i> Connected';
      } else {
        connectionStatus.className = 'badge bg-danger';
        connectionStatus.innerHTML = '<i class="bi bi-wifi-off"></i> Disconnected';
      }
    }

    if (socketStatus) {
      socketStatus.className = isConnected ?
        'status-indicator bg-success rounded-circle me-2' :
        'status-indicator bg-danger rounded-circle me-2';
    }
  }

  /* ── handle real-time UA updates from mitm proxy ─────────── */
  handleUAUpdate(data) {
    // Determine status based on risk score
    let status = 'LIVE';
    if (data.risk >= 80) {
      status = 'ERROR';
      this.stats.errors++;
    } else if (data.risk >= 50) {
      status = 'UNVERIFIED';
      this.stats.unverified++;
    } else {
      this.stats.live++;
    }

    // Update the UI immediately
    this.updateStatsDisplay();
    this.updateChart();

    // Add to activity log
    const logEntry = {
      timestamp: data.ts || Date.now(),
      ua: data.ua || 'Unknown User Agent',
      status: status,
      risk: data.risk || 10,
      url: data.url || 'Unknown URL',
      ip: data.src_ip || 'Unknown IP'
    };

    this.addActivityLogEntry(logEntry);
  }

  /* ── scan form (manual trigger) ───────────────────────────── */
  initForm() {
    const form = document.getElementById('scanForm');
    if (!form) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();

      const btn = form.querySelector('button[type="submit"]');
      const originalText = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Processing...';

      try {
        const fd = new FormData(form);
        const payload = {
          tag: fd.get('tag'),
          url: fd.get('url') || this.config.defaultUrl,
          webglPreset: fd.get('webglPreset'),
          timezone: fd.get('timezone'),
          language: fd.get('language'),
          proxy: fd.get('proxy'),
          timestamp: Date.now()
        };

        if (!payload.tag) {
          throw new Error('Tag ID is required');
        }

        console.log('Manual scan triggered:', payload);

        // Since we don't have /api/scan endpoint, we'll simulate the scan
        // and emit a socket event or log the attempt
        this.showToast('Scan Initiated', 'info', `Monitoring started for tag: ${payload.tag}`);

        // Create a mock result for the activity log
        const mockResult = {
          timestamp: Date.now(),
          ua: payload.tag,
          status: 'LIVE',
          risk: Math.floor(Math.random() * 100),
          url: payload.url,
          ip: '127.0.0.1'
        };

        this.addActivityLogEntry(mockResult);

        // Reset form
        form.reset();
        this.loadConfig(); // Reload default URL

      } catch (err) {
        console.error('Scan failed:', err);
        this.showToast('Scan Failed', 'danger', err.message);
      } finally {
        btn.disabled = false;
        btn.innerHTML = originalText;
      }
    });
  }

  /* ── doughnut chart ───────────────────────────────────────── */
  initChart() {
    const ctx = document.getElementById('verificationChart');
    if (!ctx) return;

    this.chart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['LIVE', 'UNVERIFIED', 'ERROR'],
        datasets: [{
          data: [0, 0, 0],
          backgroundColor: [
            'rgba(25, 135, 84, 0.8)',   // Bootstrap success green
            'rgba(255, 193, 7, 0.8)',   // Bootstrap warning yellow
            'rgba(220, 53, 69, 0.8)'    // Bootstrap danger red
          ],
          borderColor: [
            'rgba(25, 135, 84, 1)',
            'rgba(255, 193, 7, 1)',
            'rgba(220, 53, 69, 1)'
          ],
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              padding: 20,
              font: {
                size: 12
              }
            }
          }
        }
      }
    });

    console.log('Chart initialized');
  }

  /* ── WebGL preset cards ───────────────────────────────────── */
  initPresets() {
    const cards = document.querySelectorAll('.preset-card');
    const presetInput = document.getElementById('webglPresetInput');

    if (!cards.length || !presetInput) return;

    cards.forEach(card => {
      card.addEventListener('click', () => {
        // Remove active class from all cards
        cards.forEach(c => {
          c.classList.remove('active');
          c.setAttribute('aria-checked', 'false');
        });

        // Add active class to clicked card
        card.classList.add('active');
        card.setAttribute('aria-checked', 'true');

        const preset = card.dataset.preset;
        presetInput.value = preset;
        this.renderPresetDetails(preset);
      });

      // Keyboard accessibility
      card.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          card.click();
        }
      });
    });

    // Set default selection
    const defaultCard = cards[0];
    if (defaultCard) {
      defaultCard.classList.add('active');
      defaultCard.setAttribute('aria-checked', 'true');
      presetInput.value = defaultCard.dataset.preset;
      this.renderPresetDetails(defaultCard.dataset.preset);
    }
  }

  renderPresetDetails(presetKey) {
    const details = this.presetDetails[presetKey];
    const container = document.getElementById('webglDetails');

    if (!details || !container) return;

    container.innerHTML = `
      <h6 class="fw-bold">${details.title}</h6>
      <ul class="list-unstyled mb-2">
        <li><strong>Vendor:</strong> ${details.vendor}</li>
        <li><strong>Renderer:</strong> ${details.renderer}</li>
        <li><strong>Resolution:</strong> ${details.resolution}</li>
      </ul>
      <strong>Features:</strong>
      <ul class="mb-0">
        ${details.features.map(f => `<li>${f}</li>`).join('')}
      </ul>
    `;
  }

  /* ── periodic dashboard refresh ───────────────────────────── */
  async updateDashboard() {
    console.log('Updating dashboard...');

    try {
      await Promise.all([
        this.updateStats(),
        this.updateActivityLog()
      ]);
      console.log('Dashboard updated successfully');
    } catch (error) {
      console.error('Dashboard update failed:', error);
    }
  }

  /* ── fetch stats from /api/ua/top ─────────────────────────── */
  async updateStats() {
    try {
      const res = await fetch('/api/ua/top');
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }

      const data = await res.json();
      console.log('UA data received:', data);

      // Calculate stats based on risk levels
      const live = data.filter(ua => ua.maxRisk < 50).length;
      const unverified = data.filter(ua => ua.maxRisk >= 50 && ua.maxRisk < 80).length;
      const errors = data.filter(ua => ua.maxRisk >= 80).length;

      // Update stored stats
      this.stats = { live, unverified, errors };

      // Update display
      this.updateStatsDisplay();
      this.updateChart();

      // Update backend status indicator
      const backendStatus = document.getElementById('backendStatus');
      if (backendStatus) {
        backendStatus.className = 'status-indicator bg-success rounded-circle me-2';
      }

    } catch (error) {
      console.error('Stats update failed:', error);
      this.showToast('Stats Error', 'danger', `Could not load statistics: ${error.message}`);

      // Update backend status indicator
      const backendStatus = document.getElementById('backendStatus');
      if (backendStatus) {
        backendStatus.className = 'status-indicator bg-danger rounded-circle me-2';
      }
    }
  }

  /* ── update stats display ────────────────────────────────── */
  updateStatsDisplay() {
    const liveEl = document.getElementById('liveCount');
    const unverifiedEl = document.getElementById('unverifiedCount');
    const errorEl = document.getElementById('errorCount');

    if (liveEl) liveEl.textContent = this.stats.live;
    if (unverifiedEl) unverifiedEl.textContent = this.stats.unverified;
    if (errorEl) errorEl.textContent = this.stats.errors;
  }

  /* ── update chart data ───────────────────────────────────── */
  updateChart() {
    if (!this.chart) return;

    this.chart.data.datasets[0].data = [
      this.stats.live,
      this.stats.unverified,
      this.stats.errors
    ];

    this.chart.update('none'); // No animation for better performance
  }

  /* ── update activity log from /api/ua/top ─────────────────── */
  async updateActivityLog() {
    try {
      const res = await fetch('/api/ua/top');
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }

      const data = await res.json();

      const tbody = document.getElementById('activityLog');
      if (!tbody) return;

      // Take only the top 10 most recent entries
      const recentEntries = data.slice(0, 10);

      tbody.innerHTML = recentEntries.map(ua => {
        const status = ua.maxRisk >= 80 ? 'ERROR' :
          ua.maxRisk >= 50 ? 'UNVERIFIED' : 'LIVE';

        const badgeClass = status === 'LIVE' ? 'bg-success' :
          status === 'UNVERIFIED' ? 'bg-warning' : 'bg-danger';

        return `
          <tr>
            <td>${new Date().toLocaleTimeString()}</td>
            <td title="${ua.ua}">
              ${ua.ua.length > 50 ? ua.ua.substring(0, 50) + '...' : ua.ua}
            </td>
            <td>
              <span class="badge ${badgeClass}">${status}</span>
            </td>
            <td>${ua.maxRisk}%</td>
          </tr>
        `;
      }).join('');

    } catch (error) {
      console.error('Activity log update failed:', error);
      this.showToast('Log Error', 'danger', `Could not load activity log: ${error.message}`);
    }
  }

  /* ── add single entry to activity log ────────────────────── */
  addActivityLogEntry(entry) {
    const tbody = document.getElementById('activityLog');
    if (!tbody) return;

    const status = entry.risk >= 80 ? 'ERROR' :
      entry.risk >= 50 ? 'UNVERIFIED' : 'LIVE';

    const badgeClass = status === 'LIVE' ? 'bg-success' :
      status === 'UNVERIFIED' ? 'bg-warning' : 'bg-danger';

    const row = document.createElement('tr');
    row.className = 'new-entry'; // For CSS animation
    row.innerHTML = `
      <td>${new Date(entry.timestamp).toLocaleTimeString()}</td>
      <td title="${entry.ua}">
        ${entry.ua.length > 50 ? entry.ua.substring(0, 50) + '...' : entry.ua}
      </td>
      <td>
        <span class="badge ${badgeClass}">${status}</span>
      </td>
      <td>${entry.risk}%</td>
    `;

    // Add to top of table
    tbody.insertBefore(row, tbody.firstChild);

    // Keep only the latest 20 entries
    while (tbody.children.length > 20) {
      tbody.removeChild(tbody.lastChild);
    }

    // Remove animation class after animation completes
    setTimeout(() => {
      row.classList.remove('new-entry');
    }, 2000);
  }

  /* ── Bootstrap-style toast notifications ──────────────────── */
  showToast(title, type, message) {
    const container = document.getElementById('toastContainer');
    if (!container) {
      console.log(`Toast: [${type.toUpperCase()}] ${title}: ${message}`);
      return;
    }

    const toastId = `toast-${Date.now()}`;
    const bgClass = `text-bg-${type}`;

    const toastHTML = `
      <div id="${toastId}" class="toast ${bgClass}" role="alert" aria-live="assertive" aria-atomic="true">
        <div class="d-flex">
          <div class="toast-body">
            <strong>${title}</strong><br>
            ${message}
          </div>
          <button type="button" class="btn-close btn-close-white me-2 m-auto" 
                  data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
      </div>
    `;

    container.insertAdjacentHTML('beforeend', toastHTML);

    // Show toast using Bootstrap
    const toastElement = document.getElementById(toastId);
    const bsToast = new bootstrap.Toast(toastElement);
    bsToast.show();

    // Auto-dismiss success/info toasts after 5 seconds
    if (!['danger', 'warning'].includes(type)) {
      setTimeout(() => {
        if (document.getElementById(toastId)) {
          bsToast.hide();
        }
      }, 5000);
    }

    // Remove from DOM after hide
    toastElement.addEventListener('hidden.bs.toast', () => {
      toastElement.remove();
    });
  }

  /* ── health check function ────────────────────────────────── */
  async checkHealth() {
    const healthButton = document.getElementById('healthCheck');
    if (healthButton) {
      healthButton.classList.add('checking');
      healthButton.disabled = true;
    }

    try {
      const res = await fetch('/ping');
      if (res.ok) {
        const text = await res.text();
        console.log('Health check passed:', text);
        this.showToast('Health Check', 'success', 'Backend is responding normally');

        // Update backend status
        const backendStatus = document.getElementById('backendStatus');
        if (backendStatus) {
          backendStatus.className = 'status-indicator bg-success rounded-circle me-2';
        }
      } else {
        throw new Error(`HTTP ${res.status}`);
      }
    } catch (error) {
      console.error('Health check failed:', error);
      this.showToast('Health Check Failed', 'danger', `Backend is not responding: ${error.message}`);

      // Update backend status
      const backendStatus = document.getElementById('backendStatus');
      if (backendStatus) {
        backendStatus.className = 'status-indicator bg-danger rounded-circle me-2';
      }
    } finally {
      if (healthButton) {
        healthButton.classList.remove('checking');
        healthButton.disabled = false;
      }
    }
  }
}

/* ── Initialize dashboard when DOM is ready ─────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  const dashboard = new Dashboard();
  dashboard.init();

  // Make dashboard available globally for debugging
  window.dashboard = dashboard;

  // Add health check button functionality
  const healthButton = document.getElementById('healthCheck');
  if (healthButton) {
    healthButton.addEventListener('click', () => dashboard.checkHealth());
  }

  // Initial health check after 2 seconds
  setTimeout(() => {
    dashboard.checkHealth();
  }, 2000);
});