(function () {
  'use strict';

  let authenticated = false;
  let currentCredentialId = null;
  let devicesRegistered = false;
  let currentStatus = null;
  let _connected = true
  let lastScanResult = null
  var _intelData = {}
  var _currentAiPrNumber = null

  function updateConnectionIndicator(ok) {
    _connected = ok
    const el = document.getElementById('conn-indicator')
    if (!el) return
    el.className = ok ? 'conn-ok' : 'conn-err'
    el.title = ok ? 'Connected to GitHub' : 'Connection lost — retrying...'
  }

  function base64urlToBuffer(str) {
    const padding = '='.repeat((4 - str.length % 4) % 4);
    const base64 = (str + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    return buf;
  }

  function arrayBufferToBase64url(buf) {
    var bytes = new Uint8Array(buf)
    var binary = ''
    for (var i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i])
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  }

  function prepareWebAuthnOptions(options) {
    return {
      ...options,
      challenge: base64urlToBuffer(options.challenge),
      user: options.user ? { ...options.user, id: base64urlToBuffer(options.user.id) } : undefined,
      allowCredentials: options.allowCredentials?.map(c => ({
        ...c,
        id: base64urlToBuffer(c.id),
      })),
    };
  }

  async function api(path, options = {}) {
    if (!options.method || options.method === 'POST' || options.method === 'PUT' || options.method === 'DELETE' || options.method === 'PATCH') {
      if (!options.headers) options.headers = {}
      if (!options.headers['X-CSRF-Token'] && window.__csrfToken) {
        options.headers['X-CSRF-Token'] = window.__csrfToken
      }
    }
    try {
      const res = await fetch(path, {
        ...options,
        headers: {
          'Content-Type': 'application/json',
          ...(options.headers || {}),
        },
      });
      if (!res.ok) {
        if (res.status === 401) {
          handleUnauthenticated()
          const body = await res.json().catch(() => ({}));
          throw new Error(body.error || 'Authentication required')
        }
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `Request failed (${res.status})`);
      }
      updateConnectionIndicator(true)
      return res.json();
    } catch (err) {
      if (err.message === 'Failed to fetch' || err.message.includes('NetworkError')) {
        updateConnectionIndicator(false)
      }
      throw err
    }
  }

  function handleUnauthenticated() {
    authenticated = false
    window.__csrfToken = null
    // Show auth modal instead of switching panel
    const modal = document.getElementById('auth-modal')
    const msgEl = document.getElementById('auth-modal-message')
    const statusEl = document.getElementById('auth-modal-status')
    if (modal) {
      msgEl.textContent = 'Session expired — please re-authenticate with your passkey'
      statusEl.textContent = ''
      modal.style.display = 'flex'
    }
    // Schedule a session re-check to recover from transient failures
    setTimeout(function () {
      if (!authenticated) {
        api('/api/session/check').then(function (s) {
          if (s.authenticated) {
            authenticated = true
            if (modal) modal.style.display = 'none'
            const prevPanel = currentPanel
            showPanel(prevPanel || 'pr-section')
            loadPRs()
          }
        }).catch(function () {})
      }
    }, 3000)
  }

  function show(id) {
    document.getElementById(id).style.display = 'block';
  }

  function hide(id) {
    document.getElementById(id).style.display = 'none';
  }

  function setStatus(id, text, type) {
    const el = document.getElementById(id);
    el.textContent = text;
    el.className = 'status ' + (type || 'info');
  }

  async function checkSetup() {
    const status = await api('/api/status');
    devicesRegistered = status.registeredDevices > 0;
    currentStatus = status;
    updateLockdownBanner(status.locked);

    // Validate session server-side
    const session = await api('/api/session/check');
    authenticated = session.authenticated;

    // Fetch CSRF token
    try {
      const r = await api('/api/session/csrf-token');
      window.__csrfToken = r.csrfToken;
    } catch (e) {}

    if (status.setupRequired) {
      showPanel('enrollment-section');
    } else if (!devicesRegistered) {
      showPanel('setup-section');
    } else if (!authenticated) {
      // Pre-load GitHub config section so it can be navigated to
      panelsLoaded['github-config-section'] = true
      loadGithubConfig()
      // Show auth modal instead of switching panels
      const modal = document.getElementById('auth-modal')
      if (modal) {
        document.getElementById('auth-modal-message').textContent = 'Authenticate with your passkey to view pending authorizations.'
        document.getElementById('auth-modal-status').textContent = ''
        modal.style.display = 'flex'
      }
    } else {
        panelsLoaded['pr-section'] = true
        await loadPRs();
        panelsLoaded['devices-section'] = true
        panelsLoaded['token-section'] = true
        panelsLoaded['auth-mode-section'] = true
        panelsLoaded['branch-protection-section'] = true
        showPanel('soc-section');
        panelsLoaded['metrics-section'] = true
        panelsLoaded['webhook-section'] = true
        panelsLoaded['history-section'] = true
        await loadDevices();
        await loadTokenInfo();
        await loadAuthMode();
        await loadBranchProtection();
        await loadMetrics();
        await loadWebhookInfo();
        await loadSetupChecklist();
      }
  }

  function updateLockdownBanner(locked) {
    const banner = document.getElementById('lockdown-banner');
    if (locked) {
      banner.style.display = 'block';
    } else {
      banner.style.display = 'none';
    }
  }

  async function requireReAssertion(action) {
    return new Promise(function (resolve) {
      var modal = document.getElementById('reassert-modal')
      var statusEl = document.getElementById('reassert-status')
      modal.style.display = 'flex'
      statusEl.textContent = 'Generating challenge...'

      api('/api/auth/re-assert', { method: 'POST', body: JSON.stringify({ action }) }).then(function (challenge) {
        statusEl.textContent = 'Touch your security key...'
        return navigator.credentials.get({ publicKey: challenge.options })
      }).then(function (assertion) {
        statusEl.textContent = 'Verifying...'
        return api('/api/auth/re-assert/complete', {
          method: 'POST',
          body: JSON.stringify({
            credential: {
              id: assertion.id,
              rawId: arrayBufferToBase64url(assertion.rawId),
              response: {
                authenticatorData: arrayBufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: arrayBufferToBase64url(assertion.response.clientDataJSON),
                signature: arrayBufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? arrayBufferToBase64url(assertion.response.userHandle) : null,
              },
              type: assertion.type,
            },
            challenge: challenge.challenge,
          }),
        })
      }).then(function (result) {
        if (result.verified && result.reAssertToken) {
          resolve(result.reAssertToken)
        } else {
          statusEl.textContent = 'Verification failed'
          setTimeout(function () { modal.style.display = 'none'; resolve(null) }, 1500)
        }
      }).catch(function (err) {
        statusEl.textContent = 'Error: ' + err.message
        setTimeout(function () { modal.style.display = 'none'; resolve(null) }, 2000)
      })

      document.getElementById('reassert-cancel').addEventListener('click', function () {
        modal.style.display = 'none'
        resolve(null)
      }, { once: true })
    })
  }

  // Enrollment (first device — no session required, uses enrollment token)
  document.getElementById('enrollment-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const enrollmentToken = document.getElementById('enrollment-token').value;
    const deviceName = document.getElementById('enrollment-device-name').value;
    const btn = document.getElementById('enrollment-btn');
    btn.disabled = true;
    setStatus('enrollment-status', 'Initializing enrollment...', 'info');

    try {
      const { options, challenge } = await api('/api/setup/begin', {
        method: 'POST',
        body: JSON.stringify({ enrollmentToken, deviceName }),
      });

      const credential = await navigator.credentials.create({ publicKey: prepareWebAuthnOptions(options) });

      const result = await api('/api/setup/complete', {
        method: 'POST',
        body: JSON.stringify({
          credential: credential.toJSON(),
          challenge,
          deviceName,
          enrollmentToken,
        }),
      });

      if (result.verified) {
        setStatus('enrollment-status', 'Enrollment successful!', 'success');
        hide('enrollment-section');
        // Fetch CSRF token
        try {
          const r = await api('/api/session/csrf-token');
          window.__csrfToken = r.csrfToken;
        } catch (e) {}
        await checkSetup();
      } else {
        setStatus('enrollment-status', 'Enrollment failed', 'error');
      }
    } catch (err) {
      setStatus('enrollment-status', err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  // Registration (requires session — server handles cookie)
  document.getElementById('register-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const deviceName = document.getElementById('device-name').value;
    const btn = document.getElementById('register-btn');
    btn.disabled = true;
    setStatus('register-status', 'Initializing registration...', 'info');

    try {
      const { options, challenge } = await api('/api/webauthn/register/begin', {
        method: 'POST',
        body: JSON.stringify({ deviceName }),
      });

      const credential = await navigator.credentials.create({ publicKey: prepareWebAuthnOptions(options) });

      const result = await api('/api/webauthn/register/complete', {
        method: 'POST',
        body: JSON.stringify({
          credential: credential.toJSON(),
          challenge,
          deviceName,
        }),
      });

      if (result.verified) {
        setStatus('register-status', 'Device registered successfully!', 'success');
        hide('setup-section');
        await checkSetup();
      } else {
        setStatus('register-status', 'Registration failed', 'error');
      }
    } catch (err) {
      setStatus('register-status', err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  // Auth modal button
  document.getElementById('auth-modal-btn')?.addEventListener('click', async () => {
    const modal = document.getElementById('auth-modal')
    const statusEl = document.getElementById('auth-modal-status')
    const btn = document.getElementById('auth-modal-btn')
    btn.disabled = true
    statusEl.textContent = 'Authenticating...'
    statusEl.className = 'status info'
    try {
      const { options, challenge } = await api('/api/webauthn/assert/begin', { method: 'POST' })
      const credential = await navigator.credentials.get({ publicKey: prepareWebAuthnOptions(options) })
      const result = await api('/api/webauthn/assert/complete', {
        method: 'POST',
        body: JSON.stringify({ credential: credential.toJSON(), challenge }),
      })
      if (result.verified) {
        currentCredentialId = result.credentialId
        const session = await api('/api/session/check')
        authenticated = session.authenticated
        if (!authenticated) throw new Error('Session was not created')
        window.__csrfToken = null
        try { const r = await api('/api/session/csrf-token'); window.__csrfToken = r.csrfToken } catch (e) {}
        modal.style.display = 'none'
        statusEl.textContent = ''
        panelsLoaded['pr-section'] = true
        await loadPRs()
        panelsLoaded['devices-section'] = true
        showPanel('soc-section')
        panelsLoaded['token-section'] = true
        panelsLoaded['auth-mode-section'] = true
        panelsLoaded['branch-protection-section'] = true
        panelsLoaded['metrics-section'] = true
        panelsLoaded['github-config-section'] = true
        panelsLoaded['settings-section'] = true
        panelsLoaded['webhook-section'] = true
        panelsLoaded['history-section'] = true
        panelsLoaded['audit-section'] = true
        await loadDevices(); await loadTokenInfo(); await loadAuthMode()
        await loadBranchProtection(); await loadMetrics(); await loadGithubConfig()
        await loadSettingsPanel(); await loadWebhookInfo(); await loadAudit()
        await loadSetupChecklist()
      } else {
        statusEl.textContent = 'Authentication failed'
        statusEl.className = 'status error'
      }
    } catch (err) {
      if (err.name === 'NotAllowedError' || err.message?.includes('cancelled')) {
        statusEl.textContent = 'Authentication cancelled'
      } else {
        statusEl.textContent = err.message
      }
      statusEl.className = 'status error'
    } finally {
      btn.disabled = false
    }
  })
  // Click overlay to dismiss modal (but keep unauthenticated state)
  document.getElementById('auth-modal-overlay')?.addEventListener('click', function () {
    document.getElementById('auth-modal').style.display = 'none'
  })

  // Authentication (server creates session on success)
  document.getElementById('auth-btn').addEventListener('click', async () => {
    const btn = document.getElementById('auth-btn');
    btn.disabled = true;
    setStatus('auth-status', 'Authenticating...', 'info');

    try {
      const { options, challenge } = await api('/api/webauthn/assert/begin', {
        method: 'POST',
      });

      const credential = await navigator.credentials.get({ publicKey: prepareWebAuthnOptions(options) });

      const result = await api('/api/webauthn/assert/complete', {
        method: 'POST',
        body: JSON.stringify({
          credential: credential.toJSON(),
          challenge,
        }),
      });

      if (result.verified) {
        currentCredentialId = result.credentialId;
        // Server set session cookie — now re-check
        const session = await api('/api/session/check');
        authenticated = session.authenticated;
        if (!authenticated) {
          throw new Error('Session was not created — try re-authenticating');
        }
        // Fetch CSRF token (clearing stale token first)
        window.__csrfToken = null;
        try {
          const r = await api('/api/session/csrf-token');
          window.__csrfToken = r.csrfToken;
        } catch (e) {}
        setStatus('auth-status', 'Authenticated successfully!', 'success');
        panelsLoaded['pr-section'] = true
        await loadPRs();
        panelsLoaded['devices-section'] = true
        showPanel('soc-section');
        panelsLoaded['token-section'] = true
        panelsLoaded['auth-mode-section'] = true
        panelsLoaded['branch-protection-section'] = true
        panelsLoaded['metrics-section'] = true
        panelsLoaded['github-config-section'] = true
        panelsLoaded['settings-section'] = true
        panelsLoaded['webhook-section'] = true
        panelsLoaded['history-section'] = true
        panelsLoaded['audit-section'] = true
        await loadDevices();
        await loadTokenInfo();
        await loadAuthMode();
        await loadBranchProtection();
        await loadMetrics();
        await loadGithubConfig();
        await loadSettingsPanel();
        await loadWebhookInfo();
        await loadAudit();
        await loadSetupChecklist();
      } else {
        setStatus('auth-status', 'Authentication failed', 'error');
      }
    } catch (err) {
      setStatus('auth-status', err.message, 'error');
    } finally {
      btn.disabled = false;
    }
  });

  // PRs
  let _prevPRKeys = ''

  async function loadPRs() {
    if (!authenticated) return;
    const prList = document.getElementById('pr-list');

    try {
      const prs = await api('/api/prs');
      const key = JSON.stringify(prs.map(p => ({ n: p.prNumber, c: p.ciStatus, s: p.sentinelStatus, a: p.authStatus })))
      if (key === _prevPRKeys && prList.querySelector('.pr-card')) return
      _prevPRKeys = key

      if (prs.length === 0) {
        prList.innerHTML = '<p class="empty">No pending PRs awaiting authorization.</p>';
        _prevPRKeys = ''
        } else {
        // Remove cards for PRs no longer in the list
        const active = new Set(prs.map(p => p.prNumber))
        prList.querySelectorAll('.pr-card').forEach(el => {
          var num = parseInt(el.id.replace('pr-card-', ''), 10)
          if (!isNaN(num) && !active.has(num)) el.remove()
        })

        var newCards = []
        for (const pr of prs) {
          const existing = document.getElementById('pr-card-' + pr.prNumber)
          if (existing) {
            const badges = existing.querySelectorAll('.badge')
            if (badges.length >= 3) {
              badges[0].className = 'badge ' + pr.ciStatus
              badges[0].textContent = 'CI: ' + pr.ciStatus
              badges[1].className = 'badge ' + pr.sentinelStatus
              badges[1].textContent = 'Sentinel: ' + pr.sentinelStatus
              badges[2].className = 'badge ' + pr.authStatus
              badges[2].textContent = 'Auth: ' + pr.authStatus
            }
            continue
          }
          const card = document.createElement('div');
          card.id = 'pr-card-' + pr.prNumber;
          card.className = 'pr-card';
          card.innerHTML = `
            <div class="pr-card-split">
              <div class="pr-card-info">
                <div class="pr-card-header">
                  <div class="pr-title-row" data-pr="${pr.prNumber}" style="cursor:pointer">
                    <span class="pr-number">PR-${pr.prNumber}</span>
                    <h3 class="pr-title">${escapeHtml(pr.title)}</h3>
                    <span class="expand-indicator" id="expand-icon-${pr.prNumber}">[+]</span>
                  </div>
                  <div class="meta-row">
                    <span class="pr-author">AUTHOR: ${escapeHtml(pr.author)}</span>
                    <span class="meta-divider">//</span>
                    <span class="pr-date">CREATED: ${new Date(pr.createdAt).toLocaleString().toUpperCase()}</span>
                  </div>
                </div>
                <div class="status-row">
                  <span class="badge ${pr.ciStatus}">CI // ${pr.ciStatus}</span>
                  <span class="badge ${pr.sentinelStatus}">SENTINEL // ${pr.sentinelStatus}</span>
                  <span class="badge ${pr.authStatus}">GATEWAY // ${pr.authStatus}</span>
                  <span class="badge risk-low" id="ai-badge-${pr.prNumber}" style="${currentStatus?.aiEnabled ? '' : 'display:none'}">AI: PENDING</span>
                </div>
                <div class="pr-detail" id="pr-detail-${pr.prNumber}" style="display:none"></div>
                <div class="actions-wrapper">
                  <div class="actions">
                    <button class="auth-btn" data-pr="${pr.prNumber}">AUTHORIZE MERGE</button>
                    <button class="direct-auth-btn" data-pr="${pr.prNumber}">DIRECT AUTH</button>
                    <button class="reject-btn" data-pr="${pr.prNumber}">REJECT</button>
                    ${currentStatus?.scanEnabled && !currentStatus?.autoScan ? `<button class="scan-btn" data-pr="${pr.prNumber}">SCAN ANALYSIS</button>` : ''}
                    ${currentStatus?.aiEnabled ? `<button class="ai-btn" data-pr="${pr.prNumber}">AI ANALYZE</button>` : ''}
                  </div>
                </div>
                <div class="qr-section" id="qr-section-${pr.prNumber}" style="display:none"></div>
                <div class="checks-toggle-wrapper">
                  <button class="checks-toggle-btn" data-pr="${pr.prNumber}">EXPAND TELEMETRY & CHECKS</button>
                </div>
                <div class="checks-section" id="checks-section-${pr.prNumber}" style="display:none"></div>
              </div>
              <div class="pr-card-scan-panel" id="scan-panel-${pr.prNumber}"></div>
              <div class="pr-card-ai-panel" id="ai-panel-${pr.prNumber}" style="display:none"></div>
            </div>
          `;
          card.querySelector('.pr-title-row').addEventListener('click', function () {
            expandPRDetail(pr.prNumber)
          })
          prList.appendChild(card);
          newCards.push(card)
        }

        if (newCards.length > 0) {
          newCards.forEach(card => {
            card.querySelectorAll('.auth-btn').forEach(btn => btn.addEventListener('click', authorizePR))
            card.querySelectorAll('.direct-auth-btn').forEach(btn => btn.addEventListener('click', authorizeDirectPR))
            card.querySelectorAll('.reject-btn').forEach(btn => btn.addEventListener('click', rejectPR))
            if (currentStatus?.scanEnabled) {
              card.querySelectorAll('.scan-btn').forEach(btn => {
                var p = parseInt(btn.dataset.pr, 10)
                if (!isNaN(p)) btn.addEventListener('click', function () { scanPR(p, btn) })
              })
            }
            if (currentStatus?.aiEnabled) {
              card.querySelectorAll('.ai-btn').forEach(btn => {
                var p = parseInt(btn.dataset.pr, 10)
                if (!isNaN(p)) btn.addEventListener('click', function () { analyzePR(p, btn) })
              })
            }
            card.querySelectorAll('.checks-toggle-btn').forEach(btn => {
              btn.addEventListener('click', function () { togglePRChecks(this.dataset.pr, this) })
            })
          })

          // Auto-load cached scan results for new cards when autoScan is enabled
          if (currentStatus?.autoScan) {
            (async function loadCachedScans() {
              for (var ci = 0; ci < newCards.length; ci++) {
                var card = newCards[ci]
                var numEl = card.querySelector('.pr-number')
                if (!numEl) continue
                var num = parseInt(numEl.textContent.replace('PR-', ''), 10)
                if (isNaN(num)) continue
                try {
                  await api('/api/prs/' + num + '/scan-result')
                  scanPR(num, { disabled: false, textContent: 'Re-scan' })
                } catch {}
              }
            })()
          }
          // Auto-load cached AI results for new cards when autoAnalyze is enabled
          if (currentStatus?.autoAnalyze) {
            (async function loadCachedAI() {
              for (var ci = 0; ci < newCards.length; ci++) {
                var card = newCards[ci]
                var numEl = card.querySelector('.pr-number')
                if (!numEl) continue
                var num = parseInt(numEl.textContent.replace('PR-', ''), 10)
                if (isNaN(num)) continue
                var btn = card.querySelector('.ai-btn')
                if (btn) {
                  try {
                    await api('/api/prs/' + num + '/ai-analyze', { method: 'POST' })
                    analyzePR(num, { disabled: false, textContent: 'Re-analyze' })
                  } catch {}
                }
              }
            })()
          }
        }
      }

      // Load history
      await loadHistory();
    } catch (err) {
      prList.innerHTML = `<p class="empty">Error loading PRs: ${escapeHtml(err.message)}</p>`;
    }
  }

  async function loadHistory() {
    const historyList = document.getElementById('history-list');
    try {
      const prs = await api('/api/prs/history');
      if (prs.length === 0) {
        historyList.innerHTML = '<p class="empty">No authorization history yet.</p>';
        return;
      }
      historyList.innerHTML = '';
      for (const pr of prs) {
        const card = document.createElement('div');
        card.className = 'pr-card history';
        const time = pr.authorizedAt ? new Date(pr.authorizedAt).toLocaleString() : '';
        const deviceLabel = pr.authStatus === 'authorized' && pr.deviceName ? ` by ${escapeHtml(pr.deviceName)}` : '';
        card.innerHTML = `
          <h3>#${pr.prNumber}: ${escapeHtml(pr.title)}</h3>
          <div class="meta">${escapeHtml(pr.author)}</div>
          <div class="status-row">
            <span class="badge ${pr.authStatus}">${pr.authStatus}</span>
            <span class="meta">${time}${deviceLabel}</span>
          </div>
        `;
        historyList.appendChild(card);
      }
    } catch (err) {
      document.getElementById('history-section').style.display = 'none';
    }
  }

  async function loadScans() {
    var el = document.getElementById('scan-list');
    var metricsEl = document.getElementById('scan-metrics');
    var chartEl = document.getElementById('scan-chart-container');
    if (!el) return;
    el.innerHTML = '<p class="empty">Loading scans...</p>';
    try {
      var scans = await api('/api/scans');
      if (!scans || scans.length === 0) {
        el.innerHTML = '<p class="empty">No scans performed yet.</p>';
        if (metricsEl) metricsEl.innerHTML = '';
        if (chartEl) chartEl.innerHTML = '';
        return;
      }

      // Apply filters
      var fromVal = document.getElementById('scan-filter-from')?.value
      var toVal = document.getElementById('scan-filter-to')?.value
      var minRisk = parseInt(document.getElementById('scan-filter-risk')?.value || '0', 10)
      if (fromVal) {
        var fromTs = new Date(fromVal).getTime()
        scans = scans.filter(function(s) { return s.scannedAt >= fromTs })
      }
      if (toVal) {
        var toTs = new Date(toVal).getTime() + 86400000
        scans = scans.filter(function(s) { return s.scannedAt <= toTs })
      }
      if (minRisk > 0) {
        var riskLevel = function(score) {
          if (score >= 20) return 4
          if (score >= 10) return 3
          if (score >= 5) return 2
          if (score >= 1) return 1
          return 0
        }
        scans = scans.filter(function(s) { return riskLevel(s.riskScore) >= minRisk })
      }

      // Metrics
      if (metricsEl) {
        var totalScans = scans.length
        var avgRisk = Math.round(scans.reduce(function(s, sc) { return s + sc.riskScore }, 0) / totalScans)
        var totalCritical = scans.reduce(function(s, sc) { return s + sc.critical }, 0)
        var totalHigh = scans.reduce(function(s, sc) { return s + sc.high }, 0)
        var cleanScans = scans.filter(function(sc) { return sc.riskScore === 0 }).length
        metricsEl.innerHTML = '\
          <div class="delta-pill">' + totalScans + ' scans</div>\
          <div class="delta-pill' + (avgRisk >= 10 ? ' risk-high' : avgRisk >= 5 ? ' risk-medium' : '') + '">Avg risk: ' + avgRisk + '%</div>\
          <div class="delta-pill' + (totalCritical > 0 ? ' risk-critical' : '') + '">' + totalCritical + ' critical</div>\
          <div class="delta-pill' + (totalHigh > 0 ? ' risk-high' : '') + '">' + totalHigh + ' high</div>\
          <div class="delta-pill">' + cleanScans + ' clean</div>\
        '
      }

      // Bar chart (risk scores over time)
      if (chartEl) {
        var maxScore = Math.max.apply(null, scans.map(function(s) { return s.riskScore })) || 1
        var barW = Math.max(20, Math.min(60, 800 / scans.length))
        var chartW = Math.max(400, scans.length * (barW + 4))
        var chartH = 160
        chartEl.innerHTML = '<svg width="' + chartW + '" height="' + chartH + '" viewBox="0 0 ' + chartW + ' ' + chartH + '" xmlns="http://www.w3.org/2000/svg" style="display:block">' +
          '<rect width="100%" height="100%" fill="#0a0a14" rx="4"/>' +
          '<text x="8" y="14" fill="#8b949e" font-size="11" font-family="Consolas,monospace">Risk Score Timeline</text>' +
          scans.map(function(s, i) {
            var x = 10 + i * (barW + 4)
            var bh = (s.riskScore / maxScore) * 110
            var y = chartH - 30 - bh
            var color = s.riskScore >= 20 ? '#ff3333' : s.riskScore >= 10 ? '#ff7700' : s.riskScore >= 5 ? '#ffaa00' : '#44cc44'
            var dateStr = new Date(s.scannedAt).toLocaleDateString()
            var titleStr = 'PR #' + s.prNumber + ': ' + s.riskScore + '% risk' + (s.title ? ' — ' + escapeHtml(s.title) : '')
            return '<rect x="' + x + '" y="' + y + '" width="' + barW + '" height="' + bh + '" rx="2" fill="' + color + '" opacity="0.8">' +
              '<title>' + titleStr + '</title></rect>' +
              '<text x="' + (x + barW / 2) + '" y="' + (chartH - 14) + '" text-anchor="middle" fill="#8b949e" font-size="7" font-family="Consolas,monospace">#' + s.prNumber + '</text>'
          }).join('') +
          '</svg>'
      }

      // Table
      el.innerHTML = '<div class="checks-table"><table><thead><tr>' +
        '<th>PR</th><th>Title</th><th>Risk</th><th>Crit</th><th>High</th><th>Med</th><th>Low</th><th>Findings</th><th>Status</th><th>Date</th>' +
        '</tr></thead><tbody>' +
        scans.map(function(s) {
          var riskClass = s.riskScore >= 20 ? 'risk-critical' : s.riskScore >= 10 ? 'risk-high' : s.riskScore >= 5 ? 'risk-medium' : 'risk-low'
          var dateStr = new Date(s.scannedAt).toLocaleString()
          var statusBadge = s.authStatus === 'authorized' ? '<span class="badge success">Authorized</span>' :
            s.authStatus === 'rejected' ? '<span class="badge error">Rejected</span>' : '<span class="badge warning">Pending</span>'
          return '<tr>' +
            '<td><a href="#" onclick="showPanel(\'pr-section\');return false" style="color:var(--accent-cyan)">#' + s.prNumber + '</a></td>' +
            '<td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escapeHtml(s.title) + '</td>' +
            '<td><span class="badge ' + riskClass + '">' + s.riskScore + '%</span></td>' +
            '<td>' + s.critical + '</td>' +
            '<td>' + s.high + '</td>' +
            '<td>' + s.medium + '</td>' +
            '<td>' + s.low + '</td>' +
            '<td>' + s.findingsCount + '</td>' +
            '<td>' + statusBadge + '</td>' +
            '<td style="font-size:0.5rem;white-space:nowrap">' + dateStr + '</td>' +
            '</tr>'
        }).join('') +
        '</tbody></table></div>'
    } catch (err) {
      el.innerHTML = '<p class="empty">Error loading scans: ' + escapeHtml(err.message) + '</p>'
    }
  }

  async function authorizePR(e) {
    const prNumber = e.target.dataset.pr;
    const qrSection = document.getElementById(`qr-section-${prNumber}`);
    e.target.disabled = true;

    try {
      const { challengeId, qrUrl, qrDataUrl, expiresAt } = await api(`/api/prs/${prNumber}/authorize`, {
        method: 'POST',
      });

      qrSection.style.display = 'block';
      qrSection.innerHTML = '<div class="qr-status">Scan with your authenticator device</div>';

      if (qrDataUrl) {
        const img = document.createElement('img');
        img.src = qrDataUrl;
        img.style.width = '256px';
        img.style.height = '256px';
        img.alt = 'Authorization QR Code';
        qrSection.insertBefore(img, qrSection.firstChild);
      } else {
        qrSection.innerHTML += `<p>${escapeHtml(qrUrl)}</p>`;
      }

      const timeLeft = expiresAt - Date.now();
      if (timeLeft > 0) {
        setTimeout(() => {
          const qrStatus = qrSection.querySelector('.qr-status');
          if (qrStatus) {
            qrStatus.textContent = 'Challenge expired';
            qrStatus.className = 'qr-status error';
          }
        }, timeLeft);
      }
    } catch (err) {
      const msg = err.message;
      if (msg.includes('not found') || msg.includes('not awaiting')) {
        setStatus('pr-list', '⚠️ PR not ready yet. Page will refresh automatically — please try again in a moment.', 'warning');
        setTimeout(() => loadPRs(), 3000);
      } else {
        setStatus('pr-list', `Authorization failed: ${msg}`, 'error');
      }
    } finally {
      e.target.disabled = false;
    }
  }

  async function authorizeDirectPR(e) {
    const prNumber = parseInt(e.target.dataset.pr, 10);
    const btn = e.target;
    btn.disabled = true;
    setStatus('pr-list', 'Initiating authorization...', 'info');

    try {
      const { challengeId } = await api(`/api/prs/${prNumber}/authorize`, { method: 'POST' });

      setStatus('pr-list', `Authenticating for PR #${prNumber}...`, 'info');

      const { options, challenge } = await api('/api/webauthn/assert/begin', {
        method: 'POST',
        body: JSON.stringify({ prNumber }),
      });

      setStatus('pr-list', 'Touch your passkey to authorize...', 'info');

      const credential = await navigator.credentials.get({ publicKey: prepareWebAuthnOptions(options) });

      setStatus('pr-list', 'Verifying authorization...', 'info');

      const result = await api(`/api/prs/${prNumber}/confirm`, {
        method: 'POST',
        body: JSON.stringify({
          challengeId,
          credential: credential.toJSON(),
          challenge,
        }),
      });

      if (result.authorized) {
        setStatus('pr-list', `✓ PR #${prNumber} authorized successfully!`, 'success');
        setTimeout(() => loadPRs(), 2000);
      } else {
        setStatus('pr-list', `✗ Authorization failed: ${result.error || 'Unknown error'}`, 'error');
      }
    } catch (err) {
      if (err.name === 'NotAllowedError' || err.message?.includes('cancelled')) {
        setStatus('pr-list', 'Authentication cancelled', 'error');
      } else {
        setStatus('pr-list', `Authorization failed: ${err.message || 'Connection failed'}`, 'error');
      }
    } finally {
      btn.disabled = false;
    }
  }

  async function rejectPR(e) {
    var reAssertToken = await requireReAssertion('reject')
    if (!reAssertToken) return
    const prNumber = e.target.dataset.pr;
    e.target.disabled = true;

    try {
      await api(`/api/prs/${prNumber}/reject`, {
        method: 'POST',
        body: JSON.stringify({ reAssertToken: reAssertToken }),
      });
      await loadPRs();
    } catch (err) {
      setStatus('pr-list', `Rejection failed: ${err.message}`, 'error');
    } finally {
      e.target.disabled = false;
    }
  }

  async function scanPR(prNumber, btn) {
    const scanPanel = document.getElementById(`scan-panel-${prNumber}`);
    if (!scanPanel) {
      btn.disabled = false
      btn.textContent = 'Scan (error)'
      console.error('Scan panel not found for PR #' + prNumber)
      return
    }
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Scanning...';

    try {
      const result = await api(`/api/prs/${prNumber}/scan`, { method: 'POST' });
      lastScanResult = result;
      const severityClass = result.critical > 0 || result.high > 0 ? 'scan-critical' : result.medium > 0 ? 'scan-warning' : 'scan-clean';
      const severityLabel = result.critical > 0 ? 'CRITICAL' : result.high > 0 ? 'HIGH' : result.medium > 0 ? 'MEDIUM' : 'LOW';
      // Cache intel data for checks drawer
      if (result.intel) _intelData[prNumber] = result.intel
      scanPanel.innerHTML = `
        <div class="scan-panel-header">
          <div class="threat-score-block ${severityClass}">
            <span class="threat-label">RISK LEVEL</span>
            <span class="threat-value">${result.riskScore}%</span>
          </div>
          <div class="threat-breakdown">
            <h3 class="risk-label-title ${severityClass}">${severityLabel} RISK STATE</h3>
            <div class="severity-grid">
              <span class="sev-cell crit">CRIT: ${result.critical}</span>
              <span class="sev-cell high">HIGH: ${result.high}</span>
              <span class="sev-cell med">MED: ${result.medium}</span>
              <span class="sev-cell low">LOW: ${result.low}</span>
            </div>
          </div>
        </div>
        <div style="text-align:right;margin-bottom:0.75rem;">
          <button class="scan-report-open-btn" data-pr="${prNumber}">FULL REPORT</button>
        </div>
        ${result.findings.length > 0 ? `
          <div class="scan-findings-container">
            ${result.findings.map(f => {
              const filename = f.file ? f.file.split('/').pop() : 'source.js';
              return `
                <div class="scan-finding-card severity-${f.severity}">
                  <div class="finding-card-header">
                    <span class="finding-badge badge-${f.severity}">${f.severity.toUpperCase()}</span>
                    <h4 class="finding-title">${escapeHtml(f.title)}</h4>
                  </div>
                  <div class="finding-card-body">
                    <p class="finding-desc">${escapeHtml(f.description)}</p>
                    ${f.file ? `
                      <div class="finding-location">
                        <span class="location-path">PATH // ${escapeHtml(f.file)}${f.line != null ? ':' + f.line : ''}</span>
                      </div>
                    ` : ''}
                    ${f.code ? `
                      <div class="code-telemetry-box">
                        <div class="code-box-header">
                          <span class="code-file-label">SOURCE DELTA // ${escapeHtml(filename)}</span>
                        </div>
                        <pre class="code-box-body"><code>${escapeHtml(f.code)}</code></pre>
                      </div>
                    ` : ''}
                  </div>
                  ${f.prUrl ? `
                    <div class="finding-card-footer">
                      <a href="${escapeHtml(f.prUrl)}" target="_blank" class="view-pr-link">
                        <span>[ VIEW PATH ON GITHUB ]</span>
                      </a>
                    </div>
                  ` : ''}
                </div>
              `;
            }).join('')}
          </div>
        ` : `
          <div class="scan-clean-card">
            <span class="clean-status-label">// Cryptographically Clean</span>
            <p>Static analyzer reports 0 policy breaches or anomalies for commit payload.</p>
          </div>
        `}
        ${result.buildIntel ? `
          <div class="build-intel-section" style="margin-top:1rem;border:1px solid var(--border);border-radius:6px;padding:0.75rem;background:var(--bg-card);">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.5rem;">
              <span style="font-family:var(--font-mono);font-size:0.65rem;color:var(--text-bright);text-transform:uppercase;letter-spacing:0.1em;">Build Intelligence</span>
              <span class="badge-${result.buildIntel.risk}" style="font-size:0.6rem;padding:0.15rem 0.5rem;border-radius:3px;font-family:var(--font-mono);text-transform:uppercase;">${result.buildIntel.verdict} — Trust ${result.buildIntel.trustScore}/100</span>
            </div>
            <div style="font-size:0.6rem;color:var(--text-main);margin-bottom:0.5rem;">${escapeHtml(result.buildIntel.story.narrative)}</div>
            <div style="display:flex;flex-wrap:wrap;gap:0.5rem;margin-bottom:0.5rem;">
              ${result.buildIntel.trust.dimensions.map(d => `<div style="flex:1;min-width:80px;font-size:0.55rem;padding:0.3rem;border-radius:4px;background:var(--bg-input);border:1px solid var(--border);text-align:center;"><div style="color:var(--text-dark);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:0.15rem;">${d.name.replace(/_/g, ' ')}</div><div style="font-size:0.7rem;font-weight:600;color:${d.score >= 70 ? 'var(--accent-green)' : d.score >= 50 ? 'var(--accent-orange)' : 'var(--accent-red)'};">${d.score}/100</div></div>`).join('')}
            </div>
            ${result.buildIntel.buildSurface.tools.length > 0 ? `
              <div style="margin-top:0.4rem;">
                <span style="font-size:0.55rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);">Build Surface — Tools</span>
                <div style="display:flex;flex-wrap:wrap;gap:0.3rem;margin-top:0.2rem;">
                  ${result.buildIntel.buildSurface.tools.map(t => `<span style="font-size:0.55rem;padding:0.1rem 0.4rem;border-radius:3px;background:var(--bg-input);border:1px solid var(--border);color:var(--text-main);">${escapeHtml(t.name)} <span style="color:var(--text-dark);">(${escapeHtml(t.file)})</span></span>`).join('')}
                </div>
              </div>
            ` : ''}
            ${result.buildIntel.buildChain.deviations.length > 0 ? `
              <div style="margin-top:0.4rem;">
                <span style="font-size:0.55rem;color:var(--accent-orange);text-transform:uppercase;font-family:var(--font-mono);">Chain Deviations (${result.buildIntel.buildChain.deviations.length})</span>
                <div style="margin-top:0.2rem;">
                  ${result.buildIntel.buildChain.deviations.slice(0, 3).map(d => `<div style="font-size:0.55rem;color:var(--text-main);padding:0.1rem 0;border-bottom:1px solid var(--border);">${escapeHtml(d)}</div>`).join('')}
                  ${result.buildIntel.buildChain.deviations.length > 3 ? `<div style="font-size:0.55rem;color:var(--text-dark);margin-top:0.2rem;">+ ${result.buildIntel.buildChain.deviations.length - 3} more</div>` : ''}
                </div>
              </div>
            ` : ''}
            ${result.buildIntel.story.events.length > 0 ? `
              <div style="margin-top:0.4rem;">
                <span style="font-size:0.55rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);">Build Story (${result.buildIntel.story.events.length} event${result.buildIntel.story.events.length !== 1 ? 's' : ''})</span>
                <div style="margin-top:0.2rem;">
                  ${result.buildIntel.story.events.slice(0, 4).map(e => `<div style="font-size:0.55rem;color:var(--text-main);padding:0.1rem 0;border-bottom:1px solid var(--border);"><span class="badge-${e.severity === 'critical' ? 'critical' : e.severity === 'high' ? 'high' : e.severity === 'warning' ? 'warning' : 'low'}" style="font-size:0.5rem;padding:0.05rem 0.3rem;border-radius:2px;margin-right:0.3rem;">${e.severity.toUpperCase()}</span>${escapeHtml(e.label)}</div>`).join('')}
                  ${result.buildIntel.story.events.length > 4 ? `<div style="font-size:0.55rem;color:var(--text-dark);margin-top:0.2rem;">+ ${result.buildIntel.story.events.length - 4} more</div>` : ''}
                </div>
              </div>
            ` : ''}
          </div>
        ` : ''}
      `;
      scanPanel.classList.add('active');
      btn.textContent = 'Re-scan';
      // Wire Full Report button
      const reportBtn = scanPanel.querySelector('.scan-report-open-btn');
      if (reportBtn) reportBtn.addEventListener('click', () => showScanReport(prNumber));
      // Auto-open checks drawer to show radar chart + intel
      var checksBtn = document.querySelector('#pr-card-' + prNumber + ' .checks-toggle-btn')
      if (checksBtn) {
        var checksSection = document.getElementById('checks-section-' + prNumber)
        if (checksSection && checksSection.style.display === 'none') {
          togglePRChecks(prNumber, checksBtn)
        }
      }
    } catch (err) {
      console.error('Scan failed for PR #' + prNumber + ':', err)
      scanPanel.innerHTML = `<div class="scan-header scan-critical">Scan failed: ${escapeHtml(err.message)}</div>`;
      scanPanel.classList.add('active');
      btn.textContent = 'Scan';
    } finally {
      btn.disabled = false;
    }
  }

  // ----- AI Analysis -----
  var _aiResults = {}
  var _aiExplanations = {}
  async function analyzePR(prNumber, btn) {
    const aiPanel = document.getElementById('ai-panel-' + prNumber);
    if (!aiPanel) {
      btn.disabled = false;
      btn.textContent = 'AI Analyze';
      return;
    }
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner"></span> Analyzing...';
    try {
      const result = await api('/api/prs/' + prNumber + '/ai-analyze', { method: 'POST' });
      _aiResults[prNumber] = result
      // Also call the text-based explanation endpoint
      btn.innerHTML = '<span class="spinner"></span> AI explaining...';
      try {
        const explanation = await api('/api/prs/' + prNumber + '/ai-explain', { method: 'POST' });
        _aiExplanations[prNumber] = explanation
      } catch (explainErr) {
        console.warn('AI explain failed, will use analysis data:', explainErr);
      }
      const p = result.priority || {};
      const prioClass = p.reviewPriority === 'critical' ? 'risk-critical' : p.reviewPriority === 'high' ? 'risk-high' : p.reviewPriority === 'medium' ? 'risk-medium' : 'risk-low';
      aiPanel.style.display = 'none';
      btn.textContent = 'Re-analyze';
      // Show "VER INFORME" button
      var viewBtn = document.getElementById('ai-view-btn-' + prNumber);
      if (!viewBtn) {
        viewBtn = document.createElement('button');
        viewBtn.id = 'ai-view-btn-' + prNumber;
        viewBtn.className = 'view-ai-btn';
        viewBtn.textContent = 'VER INFORME IA';
        btn.parentNode.insertBefore(viewBtn, btn.nextSibling);
      }
      viewBtn.style.display = 'inline-block';
      viewBtn.onclick = function() { showAIReport(prNumber); };
      // Update badge
      var badge = document.getElementById('ai-badge-' + prNumber);
      if (badge) {
        badge.className = 'badge ' + prioClass;
        badge.textContent = 'AI: ' + (p.reviewPriority || 'low').toUpperCase();
      }
    } catch (err) {
      console.error('AI analysis failed for PR #' + prNumber + ':', err);
      btn.textContent = 'AI Analyze';
    } finally {
      btn.disabled = false;
    }
  }

  function inlineMarkdown(text) {
    if (!text) return ''
    var s = escapeHtml(text)
    s = s.replace(/`([^`]+)`/g, '<code>$1</code>')
    s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    s = s.replace(/\*([^*]+)\*/g, '<em>$1</em>')
    return s
  }

  function simpleMarkdown(text) {
    if (!text) return ''
    var s = inlineMarkdown(text)
    s = s.replace(/\n\n+/g, '</p><p>')
    s = s.replace(/\n/g, '<br>')
    s = s.replace(/<br><\/p>/g, '</p>')
    s = s.replace(/<p><br>/g, '<p>')
    return '<p>' + s + '</p>'
  }

  function showAIReport(prNumber) {
    var result = _aiResults[prNumber];
    if (!result) return;
    var explanation = _aiExplanations[prNumber];
    var p = result.priority || {};
    var prioClass = p.reviewPriority === 'critical' ? 'risk-critical' : p.reviewPriority === 'high' ? 'risk-high' : p.reviewPriority === 'medium' ? 'risk-medium' : 'risk-low';
    var injCount = (result.instructionManipulation || []).length;
    var modal = document.getElementById('ai-report-modal');
    var prEl = document.getElementById('ai-report-pr');
    var body = document.getElementById('ai-report-body');
    if (!modal || !body) return;
    _currentAiPrNumber = prNumber;
    var footer = document.getElementById('ai-report-footer');
    if (footer) footer.style.display = 'flex';
    prEl.textContent = 'PR #' + prNumber;

    // Build ANÁLISIS tab content — use AI explanation if available, else fallback to analysis data
    var analysisSummaryHtml = '';
    if (explanation && explanation.summary && explanation.summary.length > 0) {
      analysisSummaryHtml = '<ul class="ai-summary-list">' + explanation.summary.map(function(s) {
        return '<li>' + inlineMarkdown(s) + '</li>';
      }).join('') + '</ul>';
    } else if ((result.executiveSummary || []).length > 0) {
      analysisSummaryHtml = '<ul class="ai-summary-list">' + result.executiveSummary.map(function(s) {
        var isWarn = s.indexOf('\u26a0') !== -1 || s.indexOf('manipulation') !== -1;
        return '<li class="' + (isWarn ? 'ai-warn' : '') + '">' + inlineMarkdown(s) + '</li>';
      }).join('') + '</ul>';
    } else {
      analysisSummaryHtml = '<p class="empty">No summary available.</p>';
    }

    // Build ARGUMENTACIÓN tab content
    var argumentationHtml = '';
    if (explanation && explanation.argumentation) {
      argumentationHtml = '<div class="ai-arg-text">' + simpleMarkdown(explanation.argumentation) + '</div>';
    } else if ((result.reviewerNotes || []).length > 0) {
      argumentationHtml = '<div class="ai-arg-text">' + result.reviewerNotes.map(function(n) { return simpleMarkdown(n); }).join('') + '</div>';
    } else {
      argumentationHtml = '<p class="ai-arg-text">El an\u00e1lisis se bas\u00f3 en ' + (result.filesOfInterest || []).length + ' archivos modificados con sus diffs. Revisar los puntos cr\u00edticos listados en la pesta\u00f1a de An\u00e1lisis.</p>';
    }

    // Security and injection sections (kept from original)
    var securityHtml = '';
    if ((result.securityRelevantChanges || []).length > 0) {
      securityHtml = '<div class="ai-report-subsection">' +
        '<div class="ai-subsection-title">SEGURIDAD</div>' +
        result.securityRelevantChanges.map(function(c) {
          return '<div class="scan-finding-card severity-high"><div class="finding-card-header"><h4 class="finding-title">' + inlineMarkdown(c.title) + '</h4></div><div class="finding-card-body"><p class="finding-desc">' + inlineMarkdown(c.description) + '</p></div></div>';
        }).join('') + '</div>';
    }

    var injectionHtml = '';
    if (injCount > 0) {
      injectionHtml = '<div class="ai-report-subsection">' +
        '<div class="ai-subsection-title" style="color:var(--accent-red)">MANIPULACI\u00d3N DETECTADA</div>' +
        (result.instructionManipulation || []).map(function(i) {
          var sevClass = i.severity === 'critical' ? 'high' : i.severity || 'medium';
          return '<div class="scan-finding-card severity-' + sevClass + '"><div class="finding-card-header"><span class="finding-badge badge-' + sevClass + '">' + (i.severity || '').toUpperCase() + '</span><h4 class="finding-title">' + inlineMarkdown(i.type.replace(/_/g, ' ')) + '</h4></div><div class="finding-card-body"><p class="finding-desc">' + inlineMarkdown(i.description) + '</p><div class="finding-location"><span class="location-path">FILE // ' + escapeHtml(i.evidence?.file || '') + '</span></div></div></div>';
        }).join('') + '</div>';
    }

    body.innerHTML = '\
      <div class="ai-report-section">\
        <div class="ai-report-tabs">\
          <button class="ai-tab-btn active" data-tab="modal-analysis-' + prNumber + '">AN\u00c1LISIS</button>\
          <button class="ai-tab-btn" data-tab="modal-argumentacion-' + prNumber + '">ARGUMENTACI\u00d3N</button>\
        </div>\
        <div class="ai-tab-content" id="tab-modal-analysis-' + prNumber + '">\
          <div class="ai-report-subsection">\
            <div class="ai-subsection-title">RESUMEN</div>' +
            analysisSummaryHtml + '\
          </div>' +
          securityHtml +
          injectionHtml + '\
        </div>\
        <div class="ai-tab-content" id="tab-modal-argumentacion-' + prNumber + '" style="display:none">\
          <div class="ai-report-subsection">\
            <div class="ai-subsection-title">RAZONAMIENTO DE LA IA</div>\
            <div class="ai-argumentation-box">' +
              argumentationHtml + '\
            </div>\
          </div>\
        </div>\
      </div>';
    modal.style.display = 'flex';
    body.querySelectorAll('.ai-tab-btn').forEach(function(tab) {
      tab.addEventListener('click', function() {
        body.querySelectorAll('.ai-tab-btn').forEach(function(t) { t.classList.remove('active'); });
        body.querySelectorAll('.ai-tab-content').forEach(function(c) { c.style.display = 'none'; });
        this.classList.add('active');
        var target = document.getElementById('tab-' + this.dataset.tab);
        if (target) target.style.display = 'block';
      });
    });
  }

  async function analyzeScanAI(prNumber) {
    var container = document.getElementById('scan-ai-inline');
    var content = document.getElementById('scan-ai-content');
    var status = document.getElementById('scan-ai-status');
    if (!container) return;
    container.style.display = 'block';
    status.textContent = 'Analyzing...';
    content.innerHTML = '<div class="scan-ai-loading"><span class="spinner"></span> Analyzing scan results with AI...</div>';
    try {
      const result = await api('/api/prs/' + prNumber + '/ai-scan-explain', { method: 'POST' });
      status.textContent = 'Complete';

      // Build summary bullets
      var summaryHtml = '';
      if (result.summary && result.summary.length > 0) {
        summaryHtml = '<ul class="ai-summary-list">' + result.summary.map(function(s) {
          var isWarn = s.indexOf('CRITICAL') !== -1 || s.indexOf('CRÍTICO') !== -1 || s.indexOf('HIGH') !== -1;
          return '<li class="' + (isWarn ? 'ai-warn' : '') + '">' + escapeHtml(s) + '</li>';
        }).join('') + '</ul>';
      } else {
        summaryHtml = '<p class="empty">No summary available.</p>';
      }

      // Build argumentation paragraphs
      var argHtml = '';
      if (result.argumentation) {
        var paragraphs = result.argumentation.split(/\n\n+/).filter(function(p) { return p.trim().length > 0; });
        argHtml = paragraphs.map(function(para) {
          return '<p class="ai-arg-text">' + escapeHtml(para.trim()) + '</p>';
        }).join('');
      } else {
        argHtml = '<p class="ai-arg-text">No argumentation available.</p>';
      }

      content.innerHTML = '\
        <div class="ai-report-subsection">\
          <div class="ai-subsection-title">RESUMEN</div>' +
          summaryHtml + '\
        </div>\
        <div class="ai-report-subsection">\
          <div class="ai-subsection-title">ARGUMENTACI\u00d3N</div>\
          <div class="ai-argumentation-box">' +
            argHtml + '\
          </div>\
        </div>';
    } catch (err) {
      console.error('Scan AI analysis failed:', err);
      status.textContent = 'Failed';
      content.innerHTML = '<p style="color:var(--accent-red);font-size:0.7rem;">Error: ' + escapeHtml(err.message || 'Failed to analyze scan results') + '</p>';
    }
  }

  // ----- Radar Chart -----
  function renderRadarChart(canvas, intel) {
    if (!canvas || !intel) return
    var ctx = canvas.getContext('2d')
    var w = canvas.width, h = canvas.height
    var cx = w / 2, cy = h / 2
    var radius = Math.min(cx, cy) - 30

    var moduleKeys = [
      { key: 'dependencies', label: 'DEPS' },
      { key: 'endpoints', label: 'ENDPT' },
      { key: 'capabilities', label: 'CAPS' },
      { key: 'secrets', label: 'SECRETS' },
      { key: 'trustBoundaries', label: 'TRUST' },
      { key: 'auth', label: 'AUTH' },
      { key: 'crypto', label: 'CRYPTO' },
      { key: 'permissions', label: 'PERMS' },
      { key: 'infrastructure', label: 'INFRA' },
      { key: 'services', label: 'SRVCS' }
    ]
    var riskVal = { critical: 1.0, high: 0.75, medium: 0.5, low: 0.25 }
    var modules = []
    for (var i = 0; i < moduleKeys.length; i++) {
      var mk = moduleKeys[i]
      if (intel[mk.key]) {
        modules.push({ label: mk.label, value: riskVal[intel[mk.key].risk] || 0.1 })
      }
    }
    if (modules.length < 3) return

    var n = modules.length
    var angleStep = (2 * Math.PI) / n
    var startAngle = -Math.PI / 2

    ctx.clearRect(0, 0, w, h)

    // Grid rings
    ctx.strokeStyle = 'rgba(139,148,158,0.15)'
    ctx.lineWidth = 0.5
    for (var level = 1; level <= 4; level++) {
      var r = (radius / 4) * level
      ctx.beginPath()
      for (var j = 0; j <= n; j++) {
        var angle = startAngle + j * angleStep
        var px = cx + r * Math.cos(angle)
        var py = cy + r * Math.sin(angle)
        if (j === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py)
      }
      ctx.closePath()
      ctx.stroke()
    }

    // Axes
    ctx.strokeStyle = 'rgba(139,148,158,0.2)'
    for (var k = 0; k < n; k++) {
      var angle = startAngle + k * angleStep
      ctx.beginPath()
      ctx.moveTo(cx, cy)
      ctx.lineTo(cx + radius * Math.cos(angle), cy + radius * Math.sin(angle))
      ctx.stroke()
    }

    // Data polygon
    ctx.fillStyle = 'rgba(255,51,51,0.15)'
    ctx.strokeStyle = '#ff3333'
    ctx.lineWidth = 2
    ctx.beginPath()
    for (var m = 0; m < n; m++) {
      var angle = startAngle + m * angleStep
      var r = radius * modules[m].value
      var px = cx + r * Math.cos(angle)
      var py = cy + r * Math.sin(angle)
      if (m === 0) ctx.moveTo(px, py); else ctx.lineTo(px, py)
    }
    ctx.closePath()
    ctx.fill()
    ctx.stroke()

    // Dots and labels
    for (var p = 0; p < n; p++) {
      var angle = startAngle + p * angleStep
      var r = radius * modules[p].value
      var px = cx + r * Math.cos(angle)
      var py = cy + r * Math.sin(angle)
      ctx.fillStyle = '#ff3333'
      ctx.beginPath()
      ctx.arc(px, py, 3, 0, 2 * Math.PI)
      ctx.fill()
      var lx = cx + (radius + 16) * Math.cos(angle)
      var ly = cy + (radius + 16) * Math.sin(angle)
      ctx.fillStyle = '#8b949e'
      ctx.font = '9px monospace'
      ctx.textAlign = Math.cos(angle) >= 0 ? 'left' : 'right'
      ctx.textBaseline = 'middle'
      ctx.fillText(modules[p].label, lx, ly)
    }
  }

  // ----- Intel Rendering -----
  function riskBadge(risk) {
    if (!risk) return ''
    var cls = risk === 'critical' ? 'risk-critical' : risk === 'high' ? 'risk-high' : risk === 'medium' ? 'risk-medium' : 'risk-low'
    return '<span class="badge intel-badge ' + cls + '">' + risk.toUpperCase() + '</span>'
  }

  function renderIntel(intel, prNumber) {
    if (!intel) return ''
    var sections = []
    var intelId = 'intel-section-' + prNumber

    // Security Delta — summary card at top
    if (intel.securityDelta) {
      var sd = intel.securityDelta
      var riskScore = sd.totalRiskChange || 0
      var riskColor = riskScore >= 15 ? '#ff3333' : riskScore >= 10 ? '#ff7700' : riskScore >= 5 ? '#ffaa00' : '#44cc44'
      var secHtml = '<div class="intel-group security-delta-card" style="border:1px solid ' + riskColor + '20;border-left:4px solid ' + riskColor + ';background:' + riskColor + '08">'
      secHtml += '<div class="intel-header" style="border:none;font-size:0.7rem">SECURITY DELTA</div>'
      secHtml += '<div style="display:flex;gap:1rem;flex-wrap:wrap;padding:0.25rem 0.5rem 0.5rem">'
      secHtml += '<div style="flex:1;min-width:120px"><span style="font-size:1.2rem;font-weight:600;color:' + riskColor + '">' + riskScore + '</span><span style="font-size:0.55rem;color:var(--text-dark);display:block">RISK SCORE</span></div>'
      if (sd.dependsOn > 0) secHtml += '<div class="delta-pill">' + escapeHtml(sd.dependsOn) + ' dependencies changed</div>'
      if (sd.permissionsOn) secHtml += '<div class="delta-pill risk-medium">Permissions changed</div>'
      if (sd.endpointsAdded > 0) secHtml += '<div class="delta-pill risk-high">' + sd.endpointsAdded + ' endpoint' + (sd.endpointsAdded > 1 ? 's' : '') + ' added</div>'
      if (sd.endpointsSuspicious > 0) secHtml += '<div class="delta-pill risk-critical">' + sd.endpointsSuspicious + ' suspicious endpoint' + (sd.endpointsSuspicious > 1 ? 's' : '') + '</div>'
      if (sd.authBypass) secHtml += '<div class="delta-pill risk-critical">Auth bypass risk</div>'
      if (sd.trustViolations > 0) secHtml += '<div class="delta-pill risk-high">' + sd.trustViolations + ' trust violation' + (sd.trustViolations > 1 ? 's' : '') + '</div>'
      if (sd.cryptoWeakness) secHtml += '<div class="delta-pill risk-medium">Crypto changes</div>'
      if (sd.infraDrift) secHtml += '<div class="delta-pill risk-medium">Infrastructure drift</div>'
      if (sd.secretExposure) secHtml += '<div class="delta-pill risk-critical">Secret exposure</div>'
      if (sd.servicesAdded && sd.servicesAdded.length) secHtml += '<div class="delta-pill">Services: ' + sd.servicesAdded.join(', ') + '</div>'
      if (sd.capabilitiesAdded && sd.capabilitiesAdded.length) secHtml += '<div class="delta-pill risk-medium">Capabilities: ' + sd.capabilitiesAdded.join(', ') + '</div>'
      secHtml += '</div>'
      secHtml += '<div style="padding:0 0.5rem 0.4rem;font-size:0.6rem;color:var(--text-dark)">' + escapeHtml(sd.summary) + '</div>'
      secHtml += '</div>'
      sections.push(secHtml)
    }

    // Dependencies
    if (intel.dependencies) {
      var d = intel.dependencies
      var html = '<div class="intel-group">'
      html += '<span class="token-label intel-toggle" data-target="' + intelId + '-deps">[▼] DEPENDENCIES ' + riskBadge(d.risk) + '</span>'
      html += '<div id="' + intelId + '-deps" class="files-detail intel-detail">'
      html += '<div class="intel-summary">' + escapeHtml(d.summary) + '</div>'
      if (d.added && d.added.length) {
        html += '<div class="intel-subsection"><strong>Added:</strong></div>'
        d.added.forEach(function (a) { html += '<div class="intel-item"><span class="intel-plus">+</span> ' + escapeHtml(a.name) + '@' + escapeHtml(a.version) + '</div>' })
      }
      if (d.updated && d.updated.length) {
        html += '<div class="intel-subsection"><strong>Updated:</strong></div>'
        d.updated.forEach(function (u) { html += '<div class="intel-item"><span class="intel-update">→</span> ' + escapeHtml(u.name) + ' ' + escapeHtml(u.fromVersion) + ' → ' + escapeHtml(u.toVersion) + (u.isMajor ? ' ' + riskBadge('high') : '') + '</div>' })
      }
      if (d.removed && d.removed.length) {
        html += '<div class="intel-subsection"><strong>Removed:</strong></div>'
        d.removed.forEach(function (r) { html += '<div class="intel-item"><span class="intel-minus">−</span> ' + escapeHtml(r.name) + '@' + escapeHtml(r.version) + '</div>' })
      }
      if (d.riskSignals && d.riskSignals.length) {
        html += '<div class="intel-subsection"><strong>Risk Signals:</strong></div>'
        d.riskSignals.forEach(function (s) { html += '<div class="intel-item">' + riskBadge(s.risk) + ' ' + escapeHtml(s.package) + ': ' + escapeHtml(s.signal) + '</div>' })
      }
      if (d.newToRepo && d.newToRepo.length) {
        html += '<div class="intel-subsection"><strong>New to repository:</strong></div>'
        d.newToRepo.forEach(function (n) { html += '<div class="intel-item"><span class="intel-warn">\u26A0</span> ' + escapeHtml(n) + '</div>' })
      }
      html += '</div></div>'
      sections.push(html)
    }

    // Dependency Delta (deep scan)
    if (intel.dependencyDelta) {
      var dd = intel.dependencyDelta
      var ddHtml = '<div class="intel-group">'
      ddHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-deep-dep">[▼] DEPENDENCY DEEP SCAN ' + riskBadge(dd.risk) + '</span>'
      ddHtml += '<div id="' + intelId + '-deep-dep" class="files-detail intel-detail">'
      ddHtml += '<div class="intel-summary">' + escapeHtml(dd.packageName) + ' ' + escapeHtml(dd.fromVersion) + ' → ' + escapeHtml(dd.toVersion) + '</div>'
      ddHtml += '<div style="display:flex;gap:0.5rem;flex-wrap:wrap;margin:0.5rem 0">'
      ddHtml += '<span class="delta-pill">Files changed: ' + dd.filesChanged + '</span>'
      if (dd.newDomains && dd.newDomains.length) ddHtml += '<span class="delta-pill risk-high">' + dd.newDomains.length + ' new domains</span>'
      if (dd.networkCalls > 0) ddHtml += '<span class="delta-pill">' + dd.networkCalls + ' network calls</span>'
      if (dd.newCapabilities && dd.newCapabilities.length) ddHtml += '<span class="delta-pill risk-medium">Caps: ' + dd.newCapabilities.join(', ') + '</span>'
      if (dd.newBinaries && dd.newBinaries.length) ddHtml += '<span class="delta-pill risk-critical">' + dd.newBinaries.length + ' binaries</span>'
      if (dd.newScripts && dd.newScripts.length) ddHtml += '<span class="delta-pill risk-high">' + dd.newScripts.length + ' scripts</span>'
      ddHtml += '</div>'
      if (dd.newDomains && dd.newDomains.length) {
        ddHtml += '<div class="intel-subsection"><strong>New domains:</strong></div>'
        dd.newDomains.forEach(function (dom) { ddHtml += '<div class="intel-item"><span class="intel-warn">\u26A0</span> ' + escapeHtml(dom) + '</div>' })
      }
      if (dd.newScripts && dd.newScripts.length) {
        ddHtml += '<div class="intel-subsection"><strong>New scripts:</strong></div>'
        dd.newScripts.forEach(function (s) { ddHtml += '<div class="intel-item"><span class="intel-plus">+</span> ' + escapeHtml(s) + '</div>' })
      }
      ddHtml += '</div></div>'
      sections.push(ddHtml)
    }

    // Endpoints
    if (intel.endpoints) {
      var ep = intel.endpoints
      var epHtml = '<div class="intel-group">'
      epHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-endpoints">[▼] ENDPOINT INVENTORY ' + riskBadge(ep.risk) + '</span>'
      epHtml += '<div id="' + intelId + '-endpoints" class="files-detail intel-detail">'
      epHtml += '<div class="intel-summary">' + escapeHtml(ep.summary) + '</div>'
      if (ep.added && ep.added.length) {
        ep.added.forEach(function (a) { epHtml += '<div class="intel-item"><span class="intel-plus">+</span> <a href="' + escapeHtml(a.url) + '" target="_blank">' + escapeHtml(a.url) + '</a> <span class="intel-file">// ' + escapeHtml(a.file) + ':' + a.line + '</span></div>' })
      }
      if (ep.suspicious && ep.suspicious.length) {
        epHtml += '<div class="intel-subsection"><strong>Suspicious endpoints:</strong></div>'
        ep.suspicious.forEach(function (s) { epHtml += '<div class="intel-item">' + riskBadge('high') + ' <a href="' + escapeHtml(s.url) + '" target="_blank">' + escapeHtml(s.url) + '</a> <span class="intel-reason">(' + escapeHtml(s.reason) + ')</span> <span class="intel-file">// ' + escapeHtml(s.file) + ':' + s.line + '</span></div>' })
      }
      epHtml += '</div></div>'
      sections.push(epHtml)
    }

    // Services / SDK
    if (intel.services) {
      var sv = intel.services
      var svHtml = '<div class="intel-group">'
      svHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-services">[▼] EXTERNAL SERVICES ' + riskBadge(sv.risk) + '</span>'
      svHtml += '<div id="' + intelId + '-services" class="files-detail intel-detail">'
      svHtml += '<div class="intel-summary">' + escapeHtml(sv.summary) + '</div>'
      if (sv.added && sv.added.length) {
        sv.added.forEach(function (a) { svHtml += '<div class="intel-item"><span class="intel-plus">+</span> ' + escapeHtml(a.name) + ' <span class="intel-file">// ' + escapeHtml(a.package) + '</span> <span class="intel-file">' + escapeHtml(a.file) + ':' + a.line + '</span></div>' })
      }
      svHtml += '</div></div>'
      sections.push(svHtml)
    }

    // Permissions
    if (intel.permissions) {
      var pm = intel.permissions
      var pmHtml = '<div class="intel-group">'
      pmHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-perms">[▼] PERMISSION DELTA ' + riskBadge(pm.risk) + '</span>'
      pmHtml += '<div id="' + intelId + '-perms" class="files-detail intel-detail">'
      pmHtml += '<div class="intel-summary">' + escapeHtml(pm.summary) + '</div>'
      if (pm.addedPermissions && pm.addedPermissions.length) {
        pmHtml += '<div class="intel-subsection"><strong>Added permissions (write):</strong></div>'
        pm.addedPermissions.forEach(function (p) { pmHtml += '<div class="intel-item"><span class="intel-plus">+</span> ' + escapeHtml(p) + ': write</div>' })
      }
      if (pm.removedPermissions && pm.removedPermissions.length) {
        pmHtml += '<div class="intel-subsection"><strong>Removed permissions:</strong></div>'
        pm.removedPermissions.forEach(function (p) { pmHtml += '<div class="intel-item"><span class="intel-minus">−</span> ' + escapeHtml(p) + '</div>' })
      }
      pmHtml += '<div class="intel-subsection"><strong>After permissions:</strong></div>'
      for (var pk in pm.after) {
        pmHtml += '<div class="intel-item">' + escapeHtml(pk) + ': ' + escapeHtml(pm.after[pk]) + '</div>'
      }
      pmHtml += '</div></div>'
      sections.push(pmHtml)
    }

    // Capabilities
    if (intel.capabilities) {
      var cap = intel.capabilities
      var capHtml = '<div class="intel-group">'
      capHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-caps">[▼] CAPABILITY MATRIX ' + riskBadge(cap.risk) + '</span>'
      capHtml += '<div id="' + intelId + '-caps" class="files-detail intel-detail">'
      capHtml += '<div class="intel-summary">' + escapeHtml(cap.summary) + '</div>'
      capHtml += '<table class="cap-matrix"><tr><th>Capability</th><th>Used</th><th>Files</th></tr>'
      capHtml += '<tr><td>Filesystem</td><td>' + (cap.filesystem.length ? '<span class="badge intel-badge risk-high">Yes</span>' : '<span class="badge intel-badge risk-low">No</span>') + '</td><td class="intel-files-cell">' + cap.filesystem.map(function (f) { return escapeHtml(f) }).join(', ') + '</td></tr>'
      capHtml += '<tr><td>Network</td><td>' + (cap.network.length ? '<span class="badge intel-badge risk-high">Yes</span>' : '<span class="badge intel-badge risk-low">No</span>') + '</td><td class="intel-files-cell">' + cap.network.map(function (f) { return escapeHtml(f) }).join(', ') + '</td></tr>'
      capHtml += '<tr><td>Shell</td><td>' + (cap.shell.length ? '<span class="badge intel-badge risk-critical">Yes</span>' : '<span class="badge intel-badge risk-low">No</span>') + '</td><td class="intel-files-cell">' + cap.shell.map(function (f) { return escapeHtml(f) }).join(', ') + '</td></tr>'
      capHtml += '<tr><td>Dynamic Code</td><td>' + (cap.dynamicCode.length ? '<span class="badge intel-badge risk-high">Yes</span>' : '<span class="badge intel-badge risk-low">No</span>') + '</td><td class="intel-files-cell">' + cap.dynamicCode.map(function (f) { return escapeHtml(f) }).join(', ') + '</td></tr>'
      capHtml += '<tr><td>Database</td><td>' + (cap.database.length ? '<span class="badge intel-badge risk-medium">Yes</span>' : '<span class="badge intel-badge risk-low">No</span>') + '</td><td class="intel-files-cell">' + cap.database.map(function (f) { return escapeHtml(f) }).join(', ') + '</td></tr>'
      capHtml += '<tr><td>Crypto</td><td>' + (cap.crypto.length ? '<span class="badge intel-badge risk-medium">Yes</span>' : '<span class="badge intel-badge risk-low">No</span>') + '</td><td class="intel-files-cell">' + cap.crypto.map(function (f) { return escapeHtml(f) }).join(', ') + '</td></tr>'
      capHtml += '</table></div></div>'
      sections.push(capHtml)
    }

    // Secrets
    if (intel.secrets) {
      var sc = intel.secrets
      var scHtml = '<div class="intel-group">'
      scHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-secrets">[▼] SECRET SURFACE ' + riskBadge(sc.risk) + '</span>'
      scHtml += '<div id="' + intelId + '-secrets" class="files-detail intel-detail">'
      scHtml += '<div class="intel-summary">' + escapeHtml(sc.summary) + '</div>'
      if (sc.sources && sc.sources.length) {
        scHtml += '<div class="intel-subsection"><strong>Sensitive variables accessed:</strong></div>'
        sc.sources.forEach(function (s) { scHtml += '<div class="intel-item">' + riskBadge('high') + ' ' + escapeHtml(s.var) + ' <span class="intel-file">// ' + escapeHtml(s.file) + ':' + s.line + '</span></div>' })
      }
      scHtml += '</div></div>'
      sections.push(scHtml)
    }

    // Trust Boundaries
    if (intel.trustBoundaries) {
      var tb = intel.trustBoundaries
      var tbHtml = '<div class="intel-group">'
      tbHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-trust">[▼] TRUST BOUNDARIES ' + riskBadge(tb.risk) + '</span>'
      tbHtml += '<div id="' + intelId + '-trust" class="files-detail intel-detail">'
      tbHtml += '<div class="intel-summary">' + escapeHtml(tb.summary) + '</div>'
      if (tb.flows && tb.flows.length) {
        tb.flows.forEach(function (fl) {
          tbHtml += '<div class="intel-item">' + riskBadge('high') + ' ' + escapeHtml(fl.source) + ' → ' + escapeHtml(fl.sink) + ' <span class="intel-file">// ' + escapeHtml(fl.file) + ':' + fl.line + '</span></div>'
        })
      }
      tbHtml += '</div></div>'
      sections.push(tbHtml)
    }

    // Crypto
    if (intel.crypto) {
      var cr = intel.crypto
      var crHtml = '<div class="intel-group">'
      crHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-crypto">[▼] CRYPTO CHANGES ' + riskBadge(cr.risk) + '</span>'
      crHtml += '<div id="' + intelId + '-crypto" class="files-detail intel-detail">'
      crHtml += '<div class="intel-summary">' + escapeHtml(cr.summary) + '</div>'
      if (cr.changes && cr.changes.length) {
        cr.changes.forEach(function (c) {
          crHtml += '<div class="intel-item">' + riskBadge('medium') + ' <strong>' + escapeHtml(c.parameter) + ':</strong> ' + escapeHtml(c.before) + ' → ' + escapeHtml(c.after) + '<br><span class="intel-reason">' + escapeHtml(c.impact) + '</span></div>'
        })
      }
      crHtml += '</div></div>'
      sections.push(crHtml)
    }

    // Auth
    if (intel.auth) {
      var au = intel.auth
      var auHtml = '<div class="intel-group">'
      auHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-auth">[▼] AUTH SURFACE ' + riskBadge(au.risk) + '</span>'
      auHtml += '<div id="' + intelId + '-auth" class="files-detail intel-detail">'
      auHtml += '<div class="intel-summary">' + escapeHtml(au.summary) + '</div>'
      if (au.newRoutes && au.newRoutes.length) {
        auHtml += '<div class="intel-subsection"><strong>New routes:</strong></div>'
        au.newRoutes.forEach(function (r) { auHtml += '<div class="intel-item"><span class="intel-plus">+</span> ' + escapeHtml(r.method) + ' ' + escapeHtml(r.path) + ' <span class="intel-file">// ' + escapeHtml(r.file) + ':' + r.line + '</span></div>' })
      }
      if (au.removedMiddleware && au.removedMiddleware.length) {
        auHtml += '<div class="intel-subsection"><strong>Removed middleware (possible auth bypass):</strong></div>'
        au.removedMiddleware.forEach(function (m) { auHtml += '<div class="intel-item">' + riskBadge('critical') + ' ' + escapeHtml(m.name) + ' <span class="intel-file">// ' + escapeHtml(m.file) + ':' + m.line + '</span></div>' })
      }
      if (au.changes && au.changes.length) {
        auHtml += '<div class="intel-subsection"><strong>Auth changes:</strong></div>'
        au.changes.forEach(function (c) { auHtml += '<div class="intel-item">' + riskBadge('high') + ' ' + escapeHtml(c.description) + ' <span class="intel-file">// ' + escapeHtml(c.file) + ':' + c.line + '</span></div>' })
      }
      auHtml += '</div></div>'
      sections.push(auHtml)
    }

    // Infrastructure
    if (intel.infrastructure) {
      var inf = intel.infrastructure
      var infHtml = '<div class="intel-group">'
      infHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-infra">[▼] INFRASTRUCTURE DRIFT ' + riskBadge(inf.risk) + '</span>'
      infHtml += '<div id="' + intelId + '-infra" class="files-detail intel-detail">'
      infHtml += '<div class="intel-summary">' + escapeHtml(inf.summary) + '</div>'
      if (inf.changes && inf.changes.length) {
        inf.changes.forEach(function (c) {
          infHtml += '<div class="intel-item">' + riskBadge('medium') + ' <strong>' + escapeHtml(c.aspect) + ':</strong> ' + escapeHtml(c.impact) + '</div>'
        })
      }
      infHtml += '</div></div>'
      sections.push(infHtml)
    }

    // Workflow Intelligence
    if (intel.workflowIntel) {
      var wi = intel.workflowIntel
      var wiHtml = '<div class="intel-group">'
      wiHtml += '<span class="token-label intel-toggle" data-target="' + intelId + '-wf">[▼] WORKFLOW INTELLIGENCE ' + riskBadge(wi.risk) + '</span>'
      wiHtml += '<div id="' + intelId + '-wf" class="files-detail intel-detail">'
      wiHtml += '<div class="intel-summary">' + escapeHtml(wi.summary) + '</div>'
      if (wi.baselines && wi.baselines.length) {
        wiHtml += '<div class="intel-subsection"><strong>Workflow baselines:</strong></div>'
        wiHtml += '<table class="cap-matrix"><tr><th>Check</th><th>Avg</th><th>Min</th><th>Max</th><th>StdDev</th><th>Samples</th></tr>'
        wi.baselines.forEach(function (b) {
          var avgMin = Math.floor(b.avgDurationMs / 60000)
          var avgSec = Math.floor((b.avgDurationMs % 60000) / 1000)
          wiHtml += '<tr><td>' + escapeHtml(b.checkName) + '</td><td>' + avgMin + 'm ' + avgSec + 's</td><td>' + Math.floor(b.minDurationMs / 1000) + 's</td><td>' + Math.floor(b.maxDurationMs / 1000) + 's</td><td>' + escapeHtml(b.stdDevMs) + 'ms</td><td>' + b.sampleCount + '</td></tr>'
        })
        wiHtml += '</table>'
      }
      if (wi.anomalousPRs && wi.anomalousPRs.length) {
        wiHtml += '<div class="intel-subsection"><strong>Anomalous runs:</strong></div>'
        wi.anomalousPRs.forEach(function (a) {
          var devColor = a.deviationPct > 0 ? '#ff4444' : '#44cc44'
          wiHtml += '<div class="intel-item"><span style="color:' + devColor + ';font-weight:600">' + (a.deviationPct > 0 ? '+' : '') + a.deviationPct + '%</span> PR #' + a.prNumber + ' <span class="intel-file">' + escapeHtml(a.checkpoint) + '</span> <span class="intel-reason">baseline: ' + Math.floor(a.baselineAvg / 1000) + 's, actual: ' + Math.floor(a.durationMs / 1000) + 's</span></div>'
        })
      }
      wiHtml += '</div></div>'
      sections.push(wiHtml)
    }

    if (sections.length === 0) return ''

    var container = '<div class="intel-container"><div class="intel-header">INTELLIGENCE</div>'
    container += sections.join('')
    container += '</div>'
    return container
  }

  // Full Scan Report Modal
  async function showScanReport(prNumber) {
    const result = lastScanResult
    if (!result || !result.findings) return

    const modal = document.getElementById('scan-report-modal')
    if (!modal) return

    // Set PR info
    document.getElementById('scan-report-pr').textContent = '#' + (result.prNumber || prNumber) + ' ' + (result.prTitle || '')
    const body = document.getElementById('scan-report-body')
    if (!body) return

    const severityClass = result.critical > 0 || result.high > 0 ? 'risk-critical' : result.medium > 0 ? 'risk-medium' : 'risk-low'
    const severityLabel = result.critical > 0 ? 'CRITICAL' : result.high > 0 ? 'HIGH' : result.medium > 0 ? 'MEDIUM' : 'LOW'
    const scannedAt = result.scannedAt ? new Date(result.scannedAt).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '—'
    const totalFindings = result.critical + result.high + result.medium + result.low
    const maxSeverity = result.critical > 0 ? result.critical : result.high > 0 ? result.high : result.medium > 0 ? result.medium : result.low
    const maxBar = Math.max(totalFindings, 1)

    // Category breakdown
    const catCount = {}
    for (const f of result.findings) {
      catCount[f.category] = (catCount[f.category] || 0) + 1
    }

    body.innerHTML = `
      <!-- Executive Summary -->
      <div class="report-exec-summary">
        <div class="report-score-ring">
          <span class="report-score-value ${severityClass}">${result.riskScore}</span>
          <span class="report-score-label">RISK SCORE</span>
          <span class="report-score-meta">${result.findings.length} findings</span>
        </div>
        <div class="report-metrics-grid">
          <div class="report-metric-cell">
            <span class="report-metric-label">Scanned PR</span>
            <span class="report-metric-value">#${escapeHtml(String(result.prNumber || prNumber))}</span>
          </div>
          <div class="report-metric-cell">
            <span class="report-metric-label">Risk State</span>
            <span class="report-metric-value summary-${result.critical > 0 ? 'critical' : result.high > 0 ? 'high' : 'low'}">${severityLabel}</span>
          </div>
          <div class="report-metric-cell">
            <span class="report-metric-label">Author</span>
            <span class="report-metric-value">${escapeHtml(result.prAuthor || '—')}</span>
          </div>
          <div class="report-metric-cell">
            <span class="report-metric-label">Scanned At</span>
            <span class="report-metric-value" style="font-family:var(--font-mono);font-size:0.6rem;">${scannedAt}</span>
          </div>
          <div class="report-metric-cell">
            <span class="report-metric-label">Auth Status</span>
            <span class="report-metric-value">${(result.prAuthStatus || 'pending').toUpperCase()}</span>
          </div>
          <div class="report-metric-cell">
            <span class="report-metric-label">Scan Duration</span>
            <span class="report-metric-value">${result.scanDuration || '—'}ms</span>
          </div>
        </div>
      </div>

      <!-- Risk Breakdown -->
      <div class="report-section">
        <div class="report-section-title">Risk Breakdown</div>
        <div class="report-risk-bars">
          <div class="report-risk-bar-row">
            <span class="report-risk-bar-label" style="color:var(--accent-red);">CRITICAL</span>
            <div class="report-risk-bar-track"><div class="report-risk-bar-fill severity-critical" style="width:${(result.critical / maxBar * 100).toFixed(1)}%"></div></div>
            <span class="report-risk-bar-count">${result.critical}</span>
          </div>
          <div class="report-risk-bar-row">
            <span class="report-risk-bar-label" style="color:var(--accent-orange);">HIGH</span>
            <div class="report-risk-bar-track"><div class="report-risk-bar-fill severity-high" style="width:${(result.high / maxBar * 100).toFixed(1)}%"></div></div>
            <span class="report-risk-bar-count">${result.high}</span>
          </div>
          <div class="report-risk-bar-row">
            <span class="report-risk-bar-label" style="color:var(--accent-blue);">MEDIUM</span>
            <div class="report-risk-bar-track"><div class="report-risk-bar-fill severity-medium" style="width:${(result.medium / maxBar * 100).toFixed(1)}%"></div></div>
            <span class="report-risk-bar-count">${result.medium}</span>
          </div>
          <div class="report-risk-bar-row">
            <span class="report-risk-bar-label" style="color:var(--text-dark);">LOW</span>
            <div class="report-risk-bar-track"><div class="report-risk-bar-fill severity-low" style="width:${(result.low / maxBar * 100).toFixed(1)}%"></div></div>
            <span class="report-risk-bar-count">${result.low}</span>
          </div>
        </div>
      </div>

      <!-- Attack Surface Impact -->
      <div class="report-section">
        <div class="report-section-title">Attack Surface Impact</div>
        <div class="report-surface-grid">
          ${['secret', 'workflow', 'dependency', 'config', 'code', 'supply_chain'].map(cat => {
            const count = catCount[cat] || 0
            const catLabels = { secret: 'Credentials', workflow: 'CI/CD', dependency: 'Dependencies', config: 'Configuration', code: 'Code Analysis', supply_chain: 'Supply Chain' }
            return `
              <div class="report-surface-card">
                <div class="report-surface-card-label">${catLabels[cat] || cat}</div>
                <div class="report-surface-card-value">${count} finding${count !== 1 ? 's' : ''}</div>
              </div>
            `
          }).join('')}
        </div>
      </div>

      ${result.buildIntel ? `
      <!-- Build Intelligence -->
      <div class="report-section">
        <div class="report-section-title">Build Intelligence</div>
        <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:0.75rem;margin-bottom:1rem;">
          <div class="report-metric-cell">
            <span class="report-metric-label">Verdict</span>
            <span class="report-metric-value summary-${result.buildIntel.verdict === 'CRITICAL' ? 'critical' : result.buildIntel.verdict === 'REVIEW' ? 'high' : 'low'}">${result.buildIntel.verdict}</span>
          </div>
          <div class="report-metric-cell">
            <span class="report-metric-label">Trust Score</span>
            <span class="report-metric-value">${result.buildIntel.trustScore}/100</span>
          </div>
          <div class="report-metric-cell">
            <span class="report-metric-label">Risk Level</span>
            <span class="report-metric-value summary-${result.buildIntel.risk === 'high' ? 'high' : 'low'}">${result.buildIntel.risk.toUpperCase()}</span>
          </div>
        </div>
        <div style="font-size:0.6rem;color:var(--text-main);margin-bottom:0.75rem;">${escapeHtml(result.buildIntel.story.narrative)}</div>

        <!-- Trust Dimensions -->
        <div style="margin-bottom:1rem;">
          <div style="font-size:0.6rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);margin-bottom:0.3rem;">Trust Dimensions</div>
          <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:0.5rem;">
            ${result.buildIntel.trust.dimensions.map(d => `
              <div style="text-align:center;padding:0.5rem;border-radius:4px;border:1px solid var(--border);background:var(--bg-input);">
                <div style="font-size:0.5rem;color:var(--text-dark);text-transform:uppercase;margin-bottom:0.2rem;">${d.name.replace(/_/g, ' ')}</div>
                <div style="font-size:0.8rem;font-weight:700;color:${d.score >= 70 ? 'var(--accent-green)' : d.score >= 50 ? 'var(--accent-orange)' : 'var(--accent-red)'};">${d.score}</div>
                <div style="font-size:0.45rem;color:var(--text-dark);">weight ${(d.weight * 100).toFixed(0)}%</div>
              </div>
            `).join('')}
          </div>
        </div>

        ${result.buildIntel.buildSurface.tools.length > 0 ? `
        <div style="margin-bottom:0.75rem;">
          <div style="font-size:0.6rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);margin-bottom:0.3rem;">Build Surface — Tools (${result.buildIntel.buildSurface.tools.length})</div>
          <table class="report-findings-table">
            <thead><tr><th>Tool</th><th>File</th><th>Risk</th><th>Evidence</th></tr></thead>
            <tbody>
              ${result.buildIntel.buildSurface.tools.map(t => `<tr><td>${escapeHtml(t.name)}</td><td>${escapeHtml(t.file)}</td><td><span class="report-finding-severity-badge ${t.risk}">${t.risk.toUpperCase()}</span></td><td style="font-size:0.5rem;">${t.evidence.map(e => escapeHtml(e)).join('<br>')}</td></tr>`).join('')}
            </tbody>
          </table>
        </div>
        ` : ''}

        ${result.buildIntel.buildSurface.scripts.length > 0 ? `
        <div style="margin-bottom:0.75rem;">
          <div style="font-size:0.6rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);margin-bottom:0.3rem;">Build Surface — Scripts (${result.buildIntel.buildSurface.scripts.length})</div>
          <table class="report-findings-table">
            <thead><tr><th>Script</th><th>Command</th><th>Shell</th><th>Network</th><th>Risk</th></tr></thead>
            <tbody>
              ${result.buildIntel.buildSurface.scripts.map(s => `<tr><td>${escapeHtml(s.name)}</td><td><code style="font-size:0.5rem;">${escapeHtml(s.command)}</code></td><td>${s.containsShellExec ? '⚠ YES' : 'no'}</td><td>${s.containsNetwork ? '⚠ YES' : 'no'}</td><td><span class="report-finding-severity-badge ${s.risk}">${s.risk.toUpperCase()}</span></td></tr>`).join('')}
            </tbody>
          </table>
        </div>
        ` : ''}

        ${result.buildIntel.buildSurface.dependencies.length > 0 ? `
        <div style="margin-bottom:0.75rem;">
          <div style="font-size:0.6rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);margin-bottom:0.3rem;">Build Surface — Dependencies (${result.buildIntel.buildSurface.dependencies.length})</div>
          <table class="report-findings-table">
            <thead><tr><th>Package</th><th>Version</th><th>Change</th><th>Risk</th></tr></thead>
            <tbody>
              ${result.buildIntel.buildSurface.dependencies.map(d => `<tr><td>${escapeHtml(d.name)}</td><td>${escapeHtml(d.version || '?')}</td><td>${d.changeType}</td><td><span class="report-finding-severity-badge ${d.risk}">${d.risk.toUpperCase()}</span></td></tr>`).join('')}
            </tbody>
          </table>
        </div>
        ` : ''}

        ${result.buildIntel.buildChain.steps.length > 0 ? `
        <div style="margin-bottom:0.75rem;">
          <div style="font-size:0.6rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);margin-bottom:0.3rem;">Build Chain</div>
          <div style="font-size:0.55rem;color:var(--text-main);margin-bottom:0.3rem;">Expected flow: ${result.buildIntel.buildChain.expectedFlow.join(' → ') || 'N/A'}</div>
          ${result.buildIntel.buildChain.deviations.length > 0 ? `
            <div style="font-size:0.55rem;color:var(--accent-orange);margin-bottom:0.3rem;">Deviations: ${result.buildIntel.buildChain.deviations.length}</div>
            ${result.buildIntel.buildChain.deviations.map(d => `<div style="font-size:0.55rem;color:var(--text-main);padding:0.1rem 0;border-bottom:1px solid var(--border);">⚠ ${escapeHtml(d)}</div>`).join('')}
          ` : '<div style="font-size:0.55rem;color:var(--accent-green);">No deviations from expected build chain</div>'}
        </div>
        ` : ''}

        ${result.buildIntel.expectedGraph.newNodes.length > 0 || result.buildIntel.expectedGraph.removedNodes.length > 0 ? `
        <div style="margin-bottom:0.75rem;">
          <div style="font-size:0.6rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);margin-bottom:0.3rem;">Expected Build Graph — Changes</div>
          ${result.buildIntel.expectedGraph.newNodes.length > 0 ? `<div style="font-size:0.55rem;color:var(--text-main);">+ ${result.buildIntel.expectedGraph.newNodes.length} new node(s): ${result.buildIntel.expectedGraph.newNodes.slice(0, 5).map(n => escapeHtml(n)).join(', ')}${result.buildIntel.expectedGraph.newNodes.length > 5 ? '...' : ''}</div>` : ''}
          ${result.buildIntel.expectedGraph.removedNodes.length > 0 ? `<div style="font-size:0.55rem;color:var(--text-main);">- ${result.buildIntel.expectedGraph.removedNodes.length} removed node(s): ${result.buildIntel.expectedGraph.removedNodes.slice(0, 5).map(n => escapeHtml(n)).join(', ')}${result.buildIntel.expectedGraph.removedNodes.length > 5 ? '...' : ''}</div>` : ''}
        </div>
        ` : ''}

        ${result.buildIntel.story.events.length > 0 ? `
        <div>
          <div style="font-size:0.6rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);margin-bottom:0.3rem;">Build Story (${result.buildIntel.story.events.length} event${result.buildIntel.story.events.length !== 1 ? 's' : ''})</div>
          <table class="report-findings-table">
            <thead><tr><th>Severity</th><th>Event</th><th>File</th><th>Detail</th></tr></thead>
            <tbody>
              ${result.buildIntel.story.events.map(e => `<tr><td><span class="report-finding-severity-badge ${e.severity === 'critical' ? 'critical' : e.severity === 'high' ? 'high' : e.severity === 'warning' ? 'medium' : 'low'}">${e.severity.toUpperCase()}</span></td><td>${escapeHtml(e.label)}</td><td>${escapeHtml(e.file)}</td><td style="font-size:0.5rem;">${escapeHtml(e.detail)}</td></tr>`).join('')}
            </tbody>
          </table>
        </div>
        ` : ''}

        ${result.buildIntel.evidenceGraph.nodes.length > 0 ? `
        <div style="margin-top:0.75rem;">
          <div style="font-size:0.6rem;color:var(--text-dark);text-transform:uppercase;font-family:var(--font-mono);margin-bottom:0.3rem;">Evidence Graph (${result.buildIntel.evidenceGraph.nodes.length} nodes, ${result.buildIntel.evidenceGraph.edges.length} edges)</div>
          <div style="font-size:0.55rem;color:var(--text-main);">Confidence-weighted evidence chain from diff analysis. Nodes represent observed changes; edges represent causal relationships between build components.</div>
        </div>
        ` : ''}
      </div>
      ` : ''}

      <!-- Detailed Findings -->
      <div class="report-section">
        <div class="report-section-title">Detailed Findings (${result.findings.length})</div>
        ${result.findings.length === 0 ? '<p style="font-size:0.65rem;color:var(--text-dark);">No findings to display.</p>' : `
        <table class="report-findings-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Severity</th>
              <th>Category</th>
              <th>Finding</th>
              <th>Location</th>
              <th>Conf.</th>
              <th>CWE</th>
            </tr>
          </thead>
          <tbody>
            ${result.findings.map(f => `
              <tr>
                <td><span class="report-finding-id">${escapeHtml(f.findingId || '—')}</span></td>
                <td><span class="report-finding-severity-badge ${f.severity}">${f.severity.toUpperCase()}</span></td>
                <td><span class="report-finding-category">${f.category}</span></td>
                <td>
                  <strong style="font-size:0.65rem;color:var(--text-bright);">${escapeHtml(f.title)}</strong>
                  <div style="margin-top:0.15rem;font-size:0.6rem;color:var(--text-main);">${escapeHtml(f.description)}</div>
                  ${f.code ? `<pre class="report-finding-code">${escapeHtml(f.code)}</pre>` : ''}
                  <p class="report-finding-impact"><strong style="color:var(--accent-orange);">Impact:</strong> ${escapeHtml(f.businessImpact || '')}</p>
                  <p class="report-finding-recommendation"><strong style="color:var(--accent-blue);">Recommendation:</strong> ${escapeHtml(f.recommendation || '')}</p>
                </td>
                <td>${f.file ? escapeHtml(f.file) + (f.line != null ? ':' + f.line : '') : '—'}</td>
                <td><span class="report-finding-confidence">${f.confidence != null ? f.confidence + '%' : '—'}</span></td>
                <td><span class="report-finding-cwe">${escapeHtml(f.cwe || '—')}</span></td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        `}
      </div>

      <!-- Timeline -->
      <div class="report-section">
        <div class="report-section-title">Timeline</div>
        <div class="report-timeline">
          <div class="report-timeline-row">
            <div class="report-timeline-dot dot-created"></div>
            <div class="report-timeline-content">
              <div class="report-timeline-event">PR Created</div>
              <div class="report-timeline-time">${result.prCreatedAt ? new Date(result.prCreatedAt).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : '—'}</div>
            </div>
          </div>
          <div class="report-timeline-row">
            <div class="report-timeline-dot dot-scanned"></div>
            <div class="report-timeline-content">
              <div class="report-timeline-event">Security Scan Executed</div>
              <div class="report-timeline-time">${scannedAt} (${result.scanDuration || '—'}ms)</div>
            </div>
          </div>
          ${result.prAuthorizedAt ? `
          <div class="report-timeline-row">
            <div class="report-timeline-dot dot-authorized"></div>
            <div class="report-timeline-content">
              <div class="report-timeline-event">Authorization Decision</div>
              <div class="report-timeline-time">${new Date(result.prAuthorizedAt).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC')}</div>
            </div>
          </div>
          ` : ''}
        </div>
      </div>
    `

    modal.style.display = 'flex'

    // Wire AI ANALYZE button — shows results inline in the scan modal
    const aiBtn = document.getElementById('scan-report-ai-btn')
    if (aiBtn) {
      aiBtn.onclick = function() { analyzeScanAI(result.prNumber) }
    }
  }

  // SARIF v2.1.0 export builder
  function buildSARIF(result) {
    var results = (result.findings || []).map(function (f) {
      var loc = {}
      if (f.file) {
        loc.uri = f.file
        if (f.line != null) {
          loc.startLine = f.line
        }
      }
      var r = {
        ruleId: f.findingId || 'SNT-000',
        level: f.severity === 'critical' ? 'error' : f.severity === 'high' ? 'error' : f.severity === 'medium' ? 'warning' : 'note',
        message: {
          text: f.title + ': ' + f.description
        },
        properties: {
          category: f.category,
          confidence: f.confidence,
          businessImpact: f.businessImpact,
          recommendation: f.recommendation,
          cwe: f.cwe
        }
      }
      if (f.file) {
        r.locations = [{
          physicalLocation: {
            artifactLocation: { uri: f.file },
            region: f.line != null ? { startLine: f.line } : undefined
          }
        }]
      }
      if (f.code) {
        r.codeSnippets = [{ text: f.code }]
      }
      return r
    })
    return {
      $schema: 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'Sentinel Oracle',
            informationUri: 'https://github.com/anomalyco/sentinel-oracle',
            version: '1.0.0',
            rules: (result.findings || []).map(function (f) {
              return {
                id: f.findingId || 'SNT-000',
                name: f.title,
                shortDescription: { text: f.title },
                fullDescription: { text: f.description },
                defaultConfiguration: { level: f.severity === 'critical' ? 'error' : 'warning' },
                properties: { category: f.category, cwe: f.cwe, confidence: f.confidence }
              }
            })
          }
        },
        invocations: [{
          executionSuccessful: true,
          startTimeUtc: result.scannedAt ? new Date(result.scannedAt - (result.scanDuration || 0)).toISOString() : new Date().toISOString(),
          endTimeUtc: result.scannedAt ? new Date(result.scannedAt).toISOString() : new Date().toISOString()
        }],
        results: results
      }]
    }
  }

  // Devices
  async function loadDevices() {
    if (!authenticated) return;
    const deviceList = document.getElementById('device-list');

    try {
      const devices = await api('/api/devices');
      if (devices.length === 0) {
        deviceList.innerHTML = '<p class="empty">No devices registered.</p>';
        return;
      }

      deviceList.innerHTML = '';
      for (const device of devices) {
        const div = document.createElement('div');
        div.className = 'device-row';
        div.innerHTML = `
          <span><strong>${escapeHtml(device.name)}</strong></span>
          <span class="meta">Registered ${new Date(device.createdAt).toLocaleDateString()}</span>
          <button class="revoke-btn" data-credential="${device.credentialId}">Revoke</button>
        `;
        deviceList.appendChild(div);
      }

      document.querySelectorAll('.revoke-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          var reAssertToken = await requireReAssertion('revoke_device')
          if (!reAssertToken) return
          const credentialId = e.target.dataset.credential;
          const row = e.target.closest('.device-row');
          e.target.disabled = true;
          try {
            await api(`/api/devices/${encodeURIComponent(credentialId)}/revoke`, {
              method: 'POST',
              body: JSON.stringify({ reAssertToken: reAssertToken }),
            });
            row.style.display = 'none';
          } catch (err) {
            setStatus('device-list', `Revoke failed: ${err.message}`, 'error');
          }
        });
      });
    } catch (err) {
      deviceList.innerHTML = `<p class="empty">Error loading devices: ${escapeHtml(err.message)}</p>`;
    }
  }

  // Token Info
  async function loadTokenInfo() {
    if (!authenticated) return;
    const el = document.getElementById('token-info');
    try {
      const info = await api('/api/github/token-info');
      const scopeBadges = info.scopes.length
        ? info.scopes.map(s => `<span class="badge scope-badge ${getScopeLevel(s)}">${escapeHtml(s)}</span>`).join(' ')
        : '<span class="badge scope-badge low">granular (fine-grained)</span>';
      const riskBadge = info.riskScore === 'high' ? 'HIGH' : info.riskScore === 'medium' ? 'MEDIUM' : 'LOW';
      const riskClass = info.riskScore === 'high' ? 'error' : info.riskScore === 'medium' ? 'warning' : 'success';
      const reasons = info.riskReasons.length
        ? `<ul class="risk-reasons">${info.riskReasons.map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>`
        : '';
      el.innerHTML = `
        <div class="token-header">
          <img src="${escapeHtml(info.avatarUrl)}" alt="" class="token-avatar" width="40" height="40">
          <div>
            <strong>${escapeHtml(info.name)}</strong>
            <span class="meta">@${escapeHtml(info.login)}</span>
          </div>
          <span class="badge risk-badge ${riskClass}">${riskBadge} RISK</span>
        </div>
        <div class="token-detail"><span class="token-label">Token</span><code>${escapeHtml(info.tokenPrefix)}</code></div>
        <div class="token-detail"><span class="token-label">Type</span>${info.tokenType === 'classic' ? 'Classic PAT (broad scopes)' : 'Fine-Grained PAT (granular)'}</div>
        <div class="token-detail"><span class="token-label">Scopes</span><div class="scope-list">${scopeBadges}</div></div>
        ${reasons ? `<div class="token-detail"><span class="token-label">Risks</span>${reasons}</div>` : ''}
        <div class="token-footer">
          <a href="https://github.com/settings/tokens" target="_blank" rel="noopener">Manage tokens on GitHub →</a>
        </div>
      `;
      document.getElementById('token-section').style.display = 'block';
    } catch (err) {
      document.getElementById('token-section').style.display = 'none';
    }
  }

  function getScopeLevel(scope) {
    if (['admin:org', 'repo', 'delete_repo', 'workflow', 'admin:repo_hook'].includes(scope)) return 'high';
    if (['write:org', 'write:repo_hook', 'user', 'repo:invite'].includes(scope)) return 'medium';
    return 'low';
  }

  // Lockdown
  document.getElementById('lockdown-btn').addEventListener('click', async () => {
    var reAssertToken = await requireReAssertion('lockdown')
    if (!reAssertToken) return
    const btn = document.getElementById('lockdown-btn');
    const unlockBtn = document.getElementById('unlock-btn');
    btn.disabled = true;
    setStatus('lockdown-status', 'Activating lockdown...', 'info');

    try {
      await api('/api/lockdown', { method: 'POST', body: JSON.stringify({ reAssertToken: reAssertToken }) });
      setStatus('lockdown-status', 'Lockdown active — all merges blocked', 'success');
      btn.style.display = 'none';
      unlockBtn.style.display = 'inline-block';
      updateLockdownBanner(true);
    } catch (err) {
      setStatus('lockdown-status', err.message, 'error');
      btn.disabled = false;
    }
  });

  document.getElementById('unlock-btn').addEventListener('click', async () => {
    var reAssertToken = await requireReAssertion('unlock')
    if (!reAssertToken) return
    const btn = document.getElementById('unlock-btn');
    const lockdownBtn = document.getElementById('lockdown-btn');
    btn.disabled = true;
    setStatus('lockdown-status', 'Deactivating lockdown...', 'info');

    try {
      await api('/api/unlock', { method: 'POST', body: JSON.stringify({ reAssertToken: reAssertToken }) });
      setStatus('lockdown-status', 'Lockdown deactivated', 'success');
      btn.style.display = 'none';
      lockdownBtn.style.display = 'inline-block';
      lockdownBtn.disabled = false;
      updateLockdownBanner(false);
      await loadPRs();
    } catch (err) {
      setStatus('lockdown-status', err.message, 'error');
      btn.disabled = false;
    }
  });

  // Password strength evaluation
  function evaluatePasswordStrength(password) {
    if (!password) return { score: 0, label: 'Enter a password', color: 'var(--border-color)' }
    let score = 0
    if (password.length >= 8) score++
    if (password.length >= 12) score++
    if (/[A-Z]/.test(password)) score++
    if (/[a-z]/.test(password)) score++
    if (/[0-9]/.test(password)) score++
    if (/[^A-Za-z0-9]/.test(password)) score++
    const levels = [
      { label: 'Very weak', color: 'var(--accent-red)' },
      { label: 'Weak', color: '#c17c2e' },
      { label: 'Fair', color: '#b8860b' },
      { label: 'Good', color: 'var(--accent-green)' },
      { label: 'Strong', color: 'var(--accent-green)' },
    ]
    if (score <= 1) return { score: 20, label: 'Very weak', color: 'var(--accent-red)' }
    if (score === 2) return { score: 40, label: 'Weak', color: '#c17c2e' }
    if (score <= 4) return { score: 60, label: 'Fair', color: '#b8860b' }
    if (score === 5) return { score: 80, label: 'Good', color: 'var(--accent-green)' }
    return { score: 100, label: 'Strong', color: 'var(--accent-green)' }
  }

  function updatePasswordStrength(password) {
    const fill = document.getElementById('password-strength-fill')
    const text = document.getElementById('password-strength-text')
    if (!fill || !text) return
    const result = evaluatePasswordStrength(password)
    fill.style.width = result.score + '%'
    fill.style.background = result.color
    text.textContent = result.label
    text.style.color = result.color
  }

  let passwordResetMode = false

  async function loadPasswordSection() {
    try {
      const status = await api('/api/status');
      const hasPassword = !!status.passwordRequired;
      const curGroup = document.getElementById('password-current-group');
      const forgotArea = document.getElementById('password-forgot-area');
      const title = document.getElementById('password-title');
      const btn = document.getElementById('password-btn');
      const pwdField = document.getElementById('new-password');
      const confirmField = document.getElementById('confirm-password');
      passwordResetMode = false
      if (curGroup) curGroup.style.display = hasPassword ? '' : 'none'
      if (forgotArea) forgotArea.style.display = hasPassword ? '' : 'none'
      if (title) title.textContent = hasPassword ? 'Change Authorization Password' : 'Set Authorization Password'
      if (btn) btn.textContent = hasPassword ? 'Change Password' : 'Set Password'
      if (pwdField) pwdField.value = ''
      if (confirmField) confirmField.value = ''
      updatePasswordStrength('')
      setStatus('password-status', '', '')
    } catch {}
  }

  // Password form submit
  const passwordForm = document.getElementById('password-form');
  if (passwordForm) {
    passwordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('password-btn');
      const pwd = document.getElementById('new-password').value;
      const confirm = document.getElementById('confirm-password').value;

      if (pwd !== confirm) {
        setStatus('password-status', 'Passwords do not match', 'error');
        return;
      }
      const strength = evaluatePasswordStrength(pwd);
      if (strength.score < 60) {
        setStatus('password-status', 'Password is too weak — use at least 8 characters with uppercase, lowercase, digit, and symbol', 'error');
        return;
      }

      btn.disabled = true;
      setStatus('password-status', 'Saving password...', 'info');

      try {
        if (passwordResetMode) {
          await api('/api/config/password/reset', {
            method: 'POST',
            body: JSON.stringify({ newPassword: pwd, reAssertToken: passwordResetMode }),
          });
        } else {
          const cur = document.getElementById('current-password').value;
          await api('/api/config/password', {
            method: 'POST',
            body: JSON.stringify({ currentPassword: cur, newPassword: pwd }),
          });
        }
        setStatus('password-status', 'Authorization password updated', 'success');
        document.getElementById('current-password').value = '';
        document.getElementById('new-password').value = '';
        document.getElementById('confirm-password').value = '';
        updatePasswordStrength('');
        loadPasswordSection();
      } catch (err) {
        setStatus('password-status', err.message, 'error');
      } finally {
        btn.disabled = false;
      }
    });
  }

  // Password visibility toggle
  const visToggle = document.getElementById('password-visibility-toggle');
  if (visToggle) {
    visToggle.addEventListener('click', function () {
      const fields = [
        document.getElementById('current-password'),
        document.getElementById('new-password'),
        document.getElementById('confirm-password'),
      ];
      const show = this.textContent === 'show';
      for (const f of fields) {
        if (f) f.type = show ? 'text' : 'password';
      }
      this.textContent = show ? 'hide' : 'show';
    });
  }

  // Real-time strength validation
  const pwdField = document.getElementById('new-password');
  if (pwdField) {
    pwdField.addEventListener('input', function () {
      updatePasswordStrength(this.value);
    });
  }

  // Forgot password flow
  const forgotBtn = document.getElementById('forgot-password-btn');
  if (forgotBtn) {
    forgotBtn.addEventListener('click', async function () {
      const token = await requireReAssertion('password_reset');
      if (!token) {
        setStatus('password-status', 'Verification failed or cancelled', 'error');
        return;
      }
      passwordResetMode = token;
      document.getElementById('password-current-group').style.display = 'none';
      document.getElementById('password-forgot-area').style.display = 'none';
      document.getElementById('password-title').textContent = 'Reset Authorization Password';
      document.getElementById('password-btn').textContent = 'Reset Password';
      document.getElementById('current-password').value = '';
      document.getElementById('new-password').value = '';
      document.getElementById('confirm-password').value = '';
      updatePasswordStrength('');
      setStatus('password-status', 'Identity verified. Enter a new password.', 'info');
    });
  }

  // Audit
  async function loadAudit() {
    try {
      const log = await api('/api/audit');
      const el = document.getElementById('audit-log');
      if (log.length === 0) {
        el.innerHTML = '<p class="empty">No audit entries yet.</p>';
        return;
      }
      el.innerHTML = log.map(entry => `
        <div class="audit-entry">
          <span class="time">${new Date(entry.timestamp).toLocaleString()}</span>
          <span class="action">${escapeHtml(entry.action)}</span>
          ${entry.prNumber ? `<span class="detail">PR #${entry.prNumber}</span>` : ''}
          <span class="detail">${escapeHtml(entry.detail)}</span>
        </div>
      `).join('');
    } catch {}
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  // Auth Mode Display
  async function loadAuthMode() {
    if (!authenticated) return;
    const el = document.getElementById('auth-mode-display');
    try {
      const status = await api('/api/status');
      currentStatus = status;
      const mode = status.authMode || 'unknown';
      let label, cls;
      if (mode === 'github_app') {
        label = '🔐 GitHub App';
        cls = 'success';
      } else if (mode === 'pat') {
        label = '🔑 PAT';
        cls = 'warning';
      } else {
        label = 'ℹ️ ' + mode;
        cls = 'info';
      }
      el.innerHTML = '<span class="badge risk-badge ' + cls + '">' + label + '</span>';
    } catch (err) {
      el.innerHTML = '<span class="badge risk-badge info">Unknown</span>';
    }
  }

  // Branch Protection Status
  async function loadBranchProtection() {
    if (!authenticated) return;
    const el = document.getElementById('branch-protection-info');
    try {
      const data = await api('/api/status/branch-protection');
      const hasIssues = data.issues && data.issues.length > 0;
      const overallClass = hasIssues ? 'error' : 'success';
      const overallText = hasIssues ? 'Issues Found' : 'Secure';

      let html = '<div class="token-header"><span class="badge risk-badge ' + overallClass + ' overall-badge">' + overallText + '</span></div>';

      if (data.issues && data.issues.length > 0) {
        html += '<ul class="risk-reasons">';
        data.issues.forEach(function (issue) {
          html += '<li>' + escapeHtml(issue) + '</li>';
        });
        html += '</ul>';
      }

      if (data.requiredStatusChecks && data.requiredStatusChecks.length > 0) {
        html += '<div class="token-detail"><span class="token-label">Checks</span><div class="scope-list">';
        html += data.requiredStatusChecks.map(function (c) { return '<span class="badge scope-badge low">' + escapeHtml(c) + '</span>'; }).join(' ');
        html += '</div></div>';
      }

      if (data.adminEnforcement !== undefined) {
        html += '<div class="token-detail"><span class="token-label">Enforcement</span>';
        html += data.adminEnforcement ? '<span class="badge risk-badge success">On</span>' : '<span class="badge risk-badge error">Off</span>';
        html += '</div>';
      }

      el.innerHTML = html;
    } catch (err) {
      el.innerHTML = '<p class="empty">Error loading branch protection</p>';
    }
  }

  // PR Check Details
  async function togglePRChecks(prNumber, btn) {
    const section = document.getElementById('checks-section-' + prNumber);
    if (section.style.display !== 'none') {
      section.style.display = 'none';
      btn.textContent = 'Show Checks';
      return;
    }
    try {
      section.innerHTML = '<p class="loading-msg">Loading checks...</p>';
      section.style.display = 'block';
      btn.textContent = 'Hide Checks';

      const [data, scanData] = await Promise.all([
        api('/api/prs/' + prNumber + '/checks'),
        api('/api/prs/' + prNumber + '/scan-result').catch(function() { return null })
      ]);
      var intel = null;
      if (scanData && scanData.intel) {
        intel = scanData.intel;
        _intelData[prNumber] = intel;
      } else if (_intelData[prNumber]) {
        intel = _intelData[prNumber];
      }

      let html = '<div class="checks-table">';
      html += '<table><thead><tr>';
      html += '<th>Check</th>';
      html += '<th>Conclusion</th>';
      html += '<th>Duration</th></tr></thead><tbody>';

      if (data.checks && data.checks.length > 0) {
        var ciChecks = 0
        data.checks.forEach(function (check) {
          var conclusionClass = check.conclusion === 'success' ? 'success' : check.conclusion === 'failure' ? 'error' : 'warning';
          html += '<tr>';
          html += '<td>' + escapeHtml(check.name) + '</td>';
          html += '<td><span class="badge ' + conclusionClass + '">' + escapeHtml(check.conclusion || 'pending') + '</span></td>';
          html += '<td class="duration">' + (check.durationMs != null ? Math.round(check.durationMs / 1000) + 's' : check.duration ? check.duration + 's' : '-') + '</td>';
          html += '</tr>';
          if (check.name !== 'Sentinel Authorization' && check.name !== 'Vercel Preview Comments') ciChecks++
        });
        if (ciChecks === 0) {
          html += '<tr><td colspan="3" class="empty">No CI workflows ran for this PR commit (workflow may have been added after PR creation)</td></tr>';
        }
      } else {
        html += '<tr><td colspan="3" class="empty">No checks found</td></tr>';
      }
      html += '</tbody></table>';

      if (data.diff) {
        html += '<div class="token-detail diff-section"><span class="token-label">Diff</span>';
        html += '<span>' + data.diff.files + ' files changed, <span class="additions">+' + data.diff.additions + '</span> <span class="deletions">-' + data.diff.deletions + '</span></span>';
        html += '</div>';

        if (data.diff.fileDetails && data.diff.fileDetails.length > 0) {
          html += '<div class="files-section">';
          html += '<span class="token-label files-toggle" data-target="files-detail-' + prNumber + '">Files per file &#9660;</span>';
          html += '<div id="files-detail-' + prNumber + '" class="files-detail">';
          html += '<table><thead><tr>';
          html += '<th class="file-col">File</th>';
          html += '<th class="num-col">+/−</th>';
          html += '<th class="num-col">KB</th>';
          html += '<th class="num-col">Chg</th>';
          html += '</tr></thead><tbody>';
          var maxKB = 0
          data.diff.fileDetails.forEach(function (f) { if (f.sizeBytes > maxKB) maxKB = f.sizeBytes })
          data.diff.fileDetails.forEach(function (f) {
            var kb = (f.sizeBytes / 1024).toFixed(1)
            var isMaxClass = f.sizeBytes === maxKB && maxKB > 0 ? ' max-file' : ''
            html += '<tr class="file-row' + isMaxClass + '">';
            html += '<td class="file-col">' + escapeHtml(f.filename);
            html += ' <span class="file-history-btn" data-pr="' + prNumber + '" data-file="' + escapeHtml(f.filename) + '">[chart]</span>';
            html += '</td>';
            html += '<td class="num-col add">+' + f.additions + ' <span class="del">−' + f.deletions + '</span></td>';
            html += '<td class="num-col kb' + isMaxClass + '">' + kb + '</td>';
            html += '<td class="num-col chg">' + f.changes + '</td>';
            html += '</tr>';
          });
          html += '</tbody></table></div></div>';
        }
      }

      if (data.history && data.history.length > 0) {
        html += '<div class="history-summary">';
        html += '<span class="token-label hist-label">Historical avg for ' + escapeHtml(data.history[0].filename) + '</span>';
        var avgAdd = Math.round(data.history.reduce(function (s, h) { return s + h.additions }, 0) / data.history.length)
        var avgDel = Math.round(data.history.reduce(function (s, h) { return s + h.deletions }, 0) / data.history.length)
        html += '<span class="additions">+' + avgAdd + '</span> <span class="deletions">−' + avgDel + '</span>';
        html += '<span class="over-label">over ' + data.history.length + ' past PRs</span>';
        html += '</div>';
      }

      html += '</div>';

      // Render radar chart and intel sections if scan data available
      if (intel) {
        html += '<div class="intel-radar-wrapper"><div class="intel-header">SECURITY RADAR</div>';
        html += '<canvas id="radar-chart-' + prNumber + '" width="280" height="280" class="radar-canvas"></canvas>';
        html += '</div>';
        html += renderIntel(intel, prNumber);
      }

      section.innerHTML = html;
      section.querySelectorAll('.files-toggle').forEach(function (el) {
        el.addEventListener('click', function () {
          var target = document.getElementById(this.dataset.target)
          if (target) target.style.display = target.style.display === 'none' ? 'block' : 'none'
        })
      })
      section.querySelectorAll('.file-history-btn').forEach(function (el) {
        el.addEventListener('click', function () {
          var pr = this.dataset.pr
          var file = this.dataset.file
          var containerId = 'file-chart-' + pr + '-' + file.replace(/[^a-zA-Z0-9_-]/g, '_')
          var existing = document.getElementById(containerId)
          if (existing) {
            existing.style.display = existing.style.display === 'none' ? 'block' : 'none'
            return
          }
          var div = document.createElement('div')
          div.id = containerId
          div.className = 'chart-container'
          div.innerHTML = '<span class="loading-msg">Loading history...</span>'
          this.parentElement.appendChild(div)
          api('/api/prs/' + pr + '/file-history/' + encodeURIComponent(file)).then(function (data) {
            if (!data.history || data.history.length < 2) {
              div.innerHTML = '<span class="loading-msg">Not enough historical data for this file</span>'
              return
            }
            var hist = data.history
            var w = 320, h = 120, pad = { t: 16, r: 10, b: 22, l: 40 }
            var cw = w - pad.l - pad.r, ch = h - pad.t - pad.b
            var max = Math.max(data.maxChanges, 1)
            var n = hist.length

            // compute linear regression
            var sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0
            for (var i = 0; i < n; i++) {
              var v = hist[i].totalChanges
              sumX += i; sumY += v; sumXY += i * v; sumX2 += i * i
            }
            var slope = (n * sumXY - sumX * sumY) / (n * sumX2 - sumX * sumX)
            var intercept = (sumY - slope * sumX) / n

            var points = hist.map(function (e, i) {
              var x = pad.l + (i / Math.max(n - 1, 1)) * cw
              var bh = (e.totalChanges / max) * ch
              return { x: x, y: h - pad.b - bh, val: e.totalChanges, label: 'PR #' + e.prNumber + ': ' + e.totalChanges + ' chg' }
            })
            var trendY0 = h - pad.b - (Math.max(intercept, 0) / max) * ch
            var trendY1 = h - pad.b - (Math.max(slope * (n - 1) + intercept, 0) / max) * ch

            var dotR = n > 40 ? 1.5 : 3
            var fill = n > 40 ? '#58a6ff' : '#58a6ff'

            var svg = '<svg width="' + w + '" height="' + h + '" viewBox="0 0 ' + w + ' ' + h + '" xmlns="http://www.w3.org/2000/svg" class="chart-svg">'
            svg += '<rect width="100%" height="100%" fill="#07080a" rx="2"/>'
            svg += '<text x="' + (w / 2) + '" y="12" text-anchor="middle" fill="#8b949e" font-size="10">Changes: ' + escapeHtml(file) + '</text>'

            var yTicks = 4
            for (var t = 0; t <= yTicks; t++) {
              var yVal = Math.round((max / yTicks) * (yTicks - t))
              var yPos = pad.t + (ch / yTicks) * t
              svg += '<line x1="' + pad.l + '" y1="' + yPos + '" x2="' + (w - pad.r) + '" y2="' + yPos + '" stroke="#21262d" stroke-width="0.5"/>'
              svg += '<text x="' + (pad.l - 4) + '" y="' + (yPos + 3) + '" text-anchor="end" fill="#484f58" font-size="8">' + yVal + '</text>'
            }

            // trend line
            svg += '<line x1="' + points[0].x + '" y1="' + trendY0 + '" x2="' + points[n - 1].x + '" y2="' + trendY1 + '" stroke="#d29922" stroke-width="1.5" stroke-dasharray="3,2"/>'

            // data points: lines for sparse, dots otherwise
            if (n <= 40) {
              points.forEach(function (p) {
                svg += '<rect x="' + (p.x - dotR) + '" y="' + (p.y - dotR) + '" width="' + (dotR * 2) + '" height="' + (dotR * 2) + '" rx="' + dotR + '" fill="' + fill + '">'
                svg += '<title>' + escapeHtml(p.label) + '</title>'
                svg += '</rect>'
              })
            }
            svg += '</svg>'
            div.innerHTML = svg
          }).catch(function (err) {
            div.innerHTML = '<span class="error-msg">Error: ' + escapeHtml(err.message) + '</span>'
          })
        })
      })
      // Render radar chart and wire intel toggles in checks drawer
      if (intel) {
        var radarCanvas = document.getElementById('radar-chart-' + prNumber)
        if (radarCanvas) renderRadarChart(radarCanvas, intel)
        section.querySelectorAll('.intel-toggle').forEach(function (el) {
          el.addEventListener('click', function () {
            var target = document.getElementById(this.dataset.target)
            if (target) target.style.display = target.style.display === 'none' ? 'block' : 'none'
          })
        })
      }
    } catch (err) {
      section.innerHTML = '<p class="empty">Error: ' + escapeHtml(err.message) + '</p>';
      btn.textContent = 'Show Checks';
    }
  }

  // SOC Security Posture Dashboard
  async function loadSOC() {
    if (!authenticated) return
    const el = document.getElementById('soc-display')
    if (!el) return
    try {
      const status = currentStatus || await api('/api/status')
      // Gather scan data from all PRs
      const prs = await api('/api/prs')
      const allHistory = await api('/api/prs/history')
      const allPRs = prs.concat(allHistory)
      var totalCritical = 0, totalHigh = 0, totalMedium = 0, totalLow = 0
      var totalRisk = 0, scannedCount = 0, maxRiskPR = null
      var allFindings = []
      for (const pr of allPRs) {
        try {
          const scanRes = await api('/api/prs/' + pr.prNumber + '/scan-result')
          if (scanRes && scanRes.findings) {
            totalCritical += scanRes.critical || 0
            totalHigh += scanRes.high || 0
            totalMedium += scanRes.medium || 0
            totalLow += scanRes.low || 0
            totalRisk += scanRes.riskScore || 0
            scannedCount++
            for (const f of scanRes.findings) {
              allFindings.push({ finding: f, pr: scanRes })
            }
            if (!maxRiskPR || (scanRes.riskScore || 0) > (maxRiskPR.riskScore || 0)) {
              maxRiskPR = { ...scanRes, prNumber: pr.prNumber, prTitle: pr.title }
            }
          }
        } catch {}
      }
      var avgRisk = scannedCount > 0 ? Math.round(totalRisk / scannedCount) : 0
      // Active risks: critical + high findings
      var activeRisks = allFindings.filter(function (f) {
        return f.finding.severity === 'critical' || f.finding.severity === 'high'
      })
      activeRisks.sort(function (a, b) {
        var order = { critical: 0, high: 1 }
        return (order[a.finding.severity] || 0) - (order[b.finding.severity] || 0)
      })
      // Protected branches (from branch protection)
      var protectedBranches = 100
      // Trend placeholder (no historical data yet)
      var trend = scannedCount > 0 ? 'Baseline established' : 'No data'

      var html = '<div class="posture-grid">'
      html += '<div class="posture-card"><div class="posture-value ' + (avgRisk > 60 ? 'critical' : avgRisk > 30 ? 'high' : 'ok') + '">' + avgRisk + '</div><div class="posture-label">Avg Risk Score</div><div class="posture-trend up">' + trend + '</div></div>'
      html += '<div class="posture-card"><div class="posture-value ' + (totalCritical > 0 ? 'critical' : 'ok') + '">' + (totalCritical + totalHigh + totalMedium + totalLow) + '</div><div class="posture-label">Open Findings</div></div>'
      html += '<div class="posture-card"><div class="posture-value ' + (totalCritical > 0 ? 'critical' : totalHigh > 0 ? 'high' : 'ok') + '">' + totalCritical + '</div><div class="posture-label">Critical Findings</div></div>'
      html += '<div class="posture-card"><div class="posture-value neutral">' + status.pendingPRs + '</div><div class="posture-label">Pending PRs</div></div>'
      html += '</div>'

      // Active Risks section
      html += '<div class="soc-subtitle">Active Risks (' + activeRisks.length + ')</div>'
      if (activeRisks.length > 0) {
        html += '<div class="active-risks-list">'
        var shown = 0
        for (var i = 0; i < activeRisks.length && shown < 10; i++) {
          var ar = activeRisks[i]
          var sev = ar.finding.severity
          html += '<div class="active-risk-card risk-' + sev + '">'
          html += '<span class="active-risk-severity ' + sev + '">' + sev.toUpperCase() + '</span>'
          html += '<div class="active-risk-body">'
          html += '<div class="active-risk-title">' + escapeHtml(ar.finding.title) + ' — PR #' + ar.pr.prNumber + '</div>'
          html += '<div class="active-risk-meta">' + (ar.finding.file || '') + (ar.finding.line ? ':' + ar.finding.line : '') + ' | ' + escapeHtml(ar.pr.prTitle || '') + '</div>'
          html += '<div class="active-risk-desc">' + escapeHtml(ar.finding.description) + '</div>'
          html += '</div></div>'
          shown++
        }
        html += '</div>'
      } else {
        html += '<div style="font-size:0.65rem;color:var(--text-dark);padding:1rem 0;text-align:center;">No active high-severity risks.</div>'
      }

      // Quick actions footer
      html += '<div style="display:flex;gap:0.5rem;margin-top:1rem;padding-top:0.75rem;border-top:1px solid var(--border-color);">'
      html += '<button class="checklist-item" data-target="inbox-section" style="font-size:0.6rem;padding:0.3rem 0.6rem;background:transparent;border:1px solid var(--border-color);color:var(--text-main);cursor:pointer;">VIEW ALL FINDINGS</button>'
      html += '<button class="checklist-item" data-target="queue-section" style="font-size:0.6rem;padding:0.3rem 0.6rem;background:transparent;border:1px solid var(--border-color);color:var(--text-main);cursor:pointer;">OPEN ANALYST QUEUE</button>'
      html += '</div>'

      el.innerHTML = html
      // Wire quick buttons
      el.querySelectorAll('[data-target]').forEach(function (btn) {
        btn.addEventListener('click', function () {
          showPanel(this.dataset.target)
        })
      })
    } catch (err) {
      el.innerHTML = '<p class="empty">Error loading posture: ' + escapeHtml(err.message) + '</p>'
    }
  }

  // Security DNA
  async function loadDNA() {
    if (!authenticated) return
    const el = document.getElementById('dna-display')
    if (!el) return
    try {
      const data = await api('/api/dna')
      if (!data || !data.current) {
        el.innerHTML = '<p style="color:var(--text-dark)">' + escapeHtml(data?.summary || 'No repository configured') + '</p>'
        return
      }
      const fields = [
        { label: 'Network', key: 'network', color: '#58a6ff' },
        { label: 'Shell', key: 'shell', color: '#f0883e' },
        { label: 'Crypto', key: 'crypto', color: '#d29922' },
        { label: 'Filesystem', key: 'filesystem', color: '#3fb950' },
        { label: 'Dynamic Code', key: 'dynamicCode', color: '#db6d28' },
        { label: 'Database', key: 'database', color: '#bc8cff' },
        { label: 'Secrets', key: 'secrets', color: '#f85149' },
        { label: 'Runners', key: 'runners', color: '#ff7b72' },
        { label: 'Environments', key: 'environments', color: '#7ee787' },
        { label: 'Collaborators', key: 'collaborators', color: '#a5d6ff' },
        { label: 'Perm Escalations', key: 'permissionEscalations', color: '#ffa657' },
        { label: 'New Domains', key: 'newDomains', color: '#79c0ff' },
        { label: 'New Integrations', key: 'newIntegrations', color: '#c9d1d9' },
      ]
      var maxVal = 1
      for (const f of fields) { if (data.current[f.key] > maxVal) maxVal = data.current[f.key] }
      if (maxVal === 0) maxVal = 1

      var html = '<div class="dna-summary" style="margin-bottom:1rem;font-size:0.85rem;color:var(--text-dark)">' + escapeHtml(data.summary) + '</div>'

      html += '<div class="dna-bars" style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem">'
      for (const f of fields) {
        const curr = data.current[f.key] || 0
        const pct = Math.min(100, Math.round((curr / maxVal) * 100))
        const change = data.changes.find(function (c) { return c.label === f.label })
        var changeStr = ''
        if (change && change.change !== 0) {
          changeStr = '<span style="font-size:0.7rem;margin-left:0.5rem;' + (change.change > 0 ? 'color:#f85149' : 'color:#3fb950') + '">' + (change.change > 0 ? '▲' : '▼') + Math.abs(change.change) + '</span>'
        }
        html += '<div class="dna-bar-row" style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:0.6rem 0.8rem">'
        html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:0.3rem">'
        html += '<span style="font-size:0.75rem;font-weight:500;color:var(--text-dark)">' + f.label + changeStr + '</span>'
        html += '<span style="font-size:0.7rem;color:#c9d1d9">' + curr + '</span>'
        html += '</div>'
        html += '<div style="height:6px;background:#21262d;border-radius:3px;overflow:hidden">'
        html += '<div style="height:100%;width:' + pct + '%;background:' + f.color + ';border-radius:3px;transition:width 0.4s ease"></div>'
        html += '</div>'
        html += '</div>'
      }
      html += '</div>'

      // Change summary
      var changed = data.changes.filter(function (c) { return c.change !== 0 })
      if (changed.length > 0) {
        html += '<h3 style="margin-top:1.5rem;font-size:0.8rem;font-weight:600;color:var(--text-dark)">Drift since last scan</h3>'
        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:0.4rem;margin-top:0.3rem">'
        for (const c of changed) {
          var icon = c.change > 0 ? '▲' : '▼'
          var col = c.change > 0 ? '#f85149' : '#3fb950'
          html += '<div style="font-size:0.75rem;color:#c9d1d9;background:#0d1117;border:1px solid #21262d;border-radius:4px;padding:0.3rem 0.6rem">'
          html += '<span style="color:' + col + '">' + icon + '</span> '
          html += escapeHtml(c.label) + ': ' + c.previous + ' → ' + c.current + ' (' + (c.changePct > 0 ? '+' : '') + c.changePct + '%)'
          html += '</div>'
        }
        html += '</div>'
      }

      html += '<div style="margin-top:1rem;font-size:0.7rem;color:var(--text-dark);text-align:center">' + data.snapshotCount + ' snapshots recorded</div>'

      el.innerHTML = html
    } catch (err) {
      el.innerHTML = '<p class="empty">Error loading DNA: ' + escapeHtml(err.message) + '</p>'
    }
  }

  // Security Inbox
  async function loadInbox() {
    if (!authenticated) return
    const el = document.getElementById('inbox-display')
    if (!el) return
    try {
      // Get all scan results
      var grouped = { critical: [], high: [], medium: [], low: [] }
      const prs = await api('/api/prs')
      var allHistory = await api('/api/prs/history')
      var allPRs = prs.concat(allHistory)
      for (const pr of allPRs) {
        try {
          const scanRes = await api('/api/prs/' + pr.prNumber + '/scan-result')
          if (scanRes && scanRes.findings) {
            for (const f of scanRes.findings) {
              if (grouped[f.severity]) {
                grouped[f.severity].push({ finding: f, pr: { prNumber: pr.prNumber, title: pr.title } })
              }
            }
          }
        } catch {}
      }
      var html = ''
      var sevOrder = ['critical', 'high', 'medium', 'low']
      var sevLabels = { critical: 'CRITICAL', high: 'HIGH', medium: 'MEDIUM', low: 'LOW' }
      var hasItems = false
      for (var si = 0; si < sevOrder.length; si++) {
        var sev = sevOrder[si]
        var items = grouped[sev] || []
        if (items.length === 0) continue
        hasItems = true
        html += '<div class="inbox-group">'
        html += '<div class="inbox-group-header">'
        html += '<span class="inbox-group-badge ' + sev + '">' + sevLabels[sev] + '</span>'
        html += '<span class="inbox-group-count">' + items.length + ' finding' + (items.length !== 1 ? 's' : '') + '</span>'
        html += '</div>'
        for (var fi = 0; fi < items.length; fi++) {
          var item = items[fi]
          html += '<div class="inbox-item" data-pr="' + item.pr.prNumber + '">'
          html += '<span class="inbox-item-pr">#' + item.pr.prNumber + '</span>'
          html += '<span class="inbox-item-title">' + escapeHtml(item.finding.title) + '</span>'
          html += '<span class="inbox-item-file">' + (item.finding.file ? item.finding.file.split('/').pop() : '') + '</span>'
          html += '<button class="inbox-item-action" data-target="pr-section">VIEW PR</button>'
          html += '</div>'
        }
        html += '</div>'
      }
      if (!hasItems) {
        html = '<div class="inbox-empty">No findings detected. All clear.</div>'
      }
      el.innerHTML = html
      el.querySelectorAll('.inbox-item-action').forEach(function (btn) {
        btn.addEventListener('click', function () {
          showPanel('pr-section')
        })
      })
    } catch (err) {
      el.innerHTML = '<p class="empty">Error loading inbox: ' + escapeHtml(err.message) + '</p>'
    }
  }

  // Analyst Queue
  async function loadQueue() {
    if (!authenticated) return
    const el = document.getElementById('queue-display')
    if (!el) return
    try {
      const status = currentStatus || await api('/api/status')
      var pending = await api('/api/prs')
      // Get scan scores for each pending PR
      var queueItems = []
      for (const pr of pending) {
        var riskScore = 0
        try {
          const scanRes = await api('/api/prs/' + pr.prNumber + '/scan-result')
          if (scanRes) riskScore = scanRes.riskScore || 0
        } catch {}
        queueItems.push({ pr: pr, riskScore: riskScore })
      }
      // Sort by risk descending
      queueItems.sort(function (a, b) { return b.riskScore - a.riskScore })
      var html = '<div class="queue-controls">'
      html += '<span style="font-size:0.6rem;color:var(--text-dark);">' + queueItems.length + ' PR' + (queueItems.length !== 1 ? 's' : '') + ' in queue</span>'
      html += '</div>'
      if (queueItems.length === 0) {
        html += '<div class="queue-empty">No pending PRs in queue.</div>'
      } else {
        for (var qi = 0; qi < queueItems.length; qi++) {
          var qiItem = queueItems[qi]
          var riskClass = qiItem.riskScore > 60 ? 'risk-critical' : qiItem.riskScore > 30 ? 'risk-high' : qiItem.riskScore > 10 ? 'risk-medium' : 'risk-low'
          html += '<div class="queue-card" data-pr="' + qiItem.pr.prNumber + '">'
          html += '<div class="queue-risk"><div class="queue-risk-value ' + riskClass + '">' + qiItem.riskScore + '</div><div class="queue-risk-label">risk</div></div>'
          html += '<div class="queue-info">'
          html += '<div class="queue-pr-title">#' + qiItem.pr.prNumber + ' ' + escapeHtml(qiItem.pr.title) + '</div>'
          html += '<div class="queue-meta"><span>' + escapeHtml(qiItem.pr.author) + '</span><span>' + new Date(qiItem.pr.createdAt).toLocaleString() + '</span></div>'
          html += '</div>'
          html += '<div class="queue-actions">'
          html += '<button class="queue-auth-btn">AUTHORIZE</button>'
          html += '<button class="queue-reject-btn">REJECT</button>'
          html += '</div></div>'
        }
      }
      el.innerHTML = html
      // Wire authorize/reject buttons
      el.querySelectorAll('.queue-auth-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var card = this.closest('.queue-card')
          if (card) {
            // Navigate to PR section and trigger auth
            showPanel('pr-section')
          }
        })
      })
      el.querySelectorAll('.queue-reject-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
          var card = this.closest('.queue-card')
          if (card) {
            showPanel('pr-section')
          }
        })
      })
    } catch (err) {
      el.innerHTML = '<p class="empty">Error loading queue: ' + escapeHtml(err.message) + '</p>'
    }
  }

  // Metrics Section
  async function loadMetrics() {
    if (!authenticated) return;
    const el = document.getElementById('metrics-info');
    try {
      const data = await api('/api/metrics');

      let html = '<div class="metrics-header">';
      html += '<span class="badge scope-badge low"><strong>Total PRs:</strong> ' + (data.totalPrs || 0) + '</span>';
      html += '<span class="badge scope-badge low"><strong>Pending:</strong> ' + (data.pending || 0) + '</span>';
      html += '<span class="badge scope-badge low"><strong>Authorized:</strong> ' + (data.authorized || 0) + '</span>';
      html += '<span class="badge scope-badge low"><strong>Rejected:</strong> ' + (data.rejected || 0) + '</span>';
      html += '<span class="badge scope-badge low"><strong>Expired:</strong> ' + (data.expired || 0) + '</span>';
      html += '</div>';

      if (data.recentMergeTimes && data.recentMergeTimes.length > 0) {
        html += '<h3 class="metrics-subhead">Recent Merge Times</h3>';
        html += '<table class="metrics-table"><thead><tr>';
        html += '<th>PR #</th>';
        html += '<th>Title</th>';
        html += '<th>Wait Time</th></tr></thead><tbody>';
        data.recentMergeTimes.forEach(function (m) {
          html += '<tr>';
          html += '<td>#' + m.prNumber + '</td>';
          html += '<td>' + escapeHtml(m.title) + '</td>';
          html += '<td class="wait">' + (m.waitTime || '-') + '</td></tr>';
        });
        html += '</tbody></table>';
      }

      if (data.authorStats && data.authorStats.length > 0) {
        html += '<h3 class="metrics-subhead">Author Stats</h3>';
        html += '<table class="metrics-table"><thead><tr>';
        html += '<th>Author</th>';
        html += '<th>Merged</th>';
        html += '<th>Rejected</th>';
        html += '<th>Avg Wait</th></tr></thead><tbody>';
        data.authorStats.forEach(function (a) {
          html += '<tr>';
          html += '<td>' + escapeHtml(a.author) + '</td>';
          html += '<td>' + (a.merged || 0) + '</td>';
          html += '<td>' + (a.rejected || 0) + '</td>';
          html += '<td class="wait">' + (a.avgWait || '-') + '</td></tr>';
        });
        html += '</tbody></table>';
      }

      if (!data.recentMergeTimes && !data.authorStats) {
        html += '<p class="empty">No metrics data available yet.</p>';
      }

      el.innerHTML = html;
    } catch (err) {
      el.innerHTML = '<p class="empty">Error loading metrics: ' + escapeHtml(err.message) + '</p>';
    }
  }

  // Analytics
  async function loadAnalytics() {
    if (!authenticated) return;
    const tbody = document.getElementById('analytics-table-body');
    const summaryEl = document.getElementById('analytics-summary');
    try {
      const data = await api('/api/analytics/export');
      const s = data.summary || {};
      if (summaryEl) {
        summaryEl.innerHTML =
          '<div class="stat-card"><div class="stat-value">' + s.totalPRs + '</div><div class="stat-label">Total PRs</div></div>' +
          '<div class="stat-card"><div class="stat-value">' + s.authorizedPRs + '</div><div class="stat-label">Authorized</div></div>' +
          '<div class="stat-card"><div class="stat-value">' + s.rejectedPRs + '</div><div class="stat-label">Rejected</div></div>' +
          '<div class="stat-card"><div class="stat-value">' + s.registeredDevices + '</div><div class="stat-label">Devices</div></div>' +
          '<div class="stat-card"><div class="stat-value">' + s.totalAuditEntries + '</div><div class="stat-label">Audit Entries</div></div>' +
          '<div class="stat-card"><div class="stat-value">' + s.trackedFiles + '</div><div class="stat-label">Tracked Files</div></div>';
      }
      const prs = data.pullRequests || [];
      if (tbody) {
        if (prs.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="color:var(--text-dark);text-align:center">No PR data available.</td></tr>';
        } else {
          tbody.innerHTML = prs.map(function (p) {
            var d = p.createdAt ? new Date(p.createdAt).toLocaleDateString() : '-';
            var ad = p.authorizedAt ? new Date(p.authorizedAt).toLocaleDateString() : '-';
            return '<tr>' +
              '<td>#' + p.prNumber + '</td>' +
              '<td>' + escapeHtml(p.author) + '</td>' +
              '<td>' + d + '</td>' +
              '<td><span class="badge scope-badge ' + (p.ciStatus === 'passed' ? 'low' : 'medium') + '">' + p.ciStatus + '</span></td>' +
              '<td><span class="badge scope-badge ' + (p.sentinelStatus === 'checking' ? 'medium' : 'low') + '">' + p.sentinelStatus + '</span></td>' +
              '<td><span class="badge scope-badge' + (p.authStatus === 'authorized' ? ' success' : p.authStatus === 'rejected' ? ' error' : '') + '">' + p.authStatus + '</span></td>' +
              '<td>' + ad + '</td>' +
              '<td>' + escapeHtml(p.deviceName || '-') + '</td></tr>';
          }).join('');
        }
      }
      // Store raw data for download
      window.__analyticsData = data;
    } catch (err) {
      if (tbody) tbody.innerHTML = '<tr><td colspan="8" style="color:var(--accent-red);text-align:center">Error: ' + escapeHtml(err.message) + '</td></tr>';
    }
  }

  // Download analytics as JSON
  document.getElementById('analytics-download-json')?.addEventListener('click', function () {
    var data = window.__analyticsData;
    if (!data) return;
    var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'sentinel-analytics-' + new Date().toISOString().slice(0, 10) + '.json';
    a.click();
    URL.revokeObjectURL(url);
  });

  // Download analytics as CSV
  document.getElementById('analytics-download-csv')?.addEventListener('click', function () {
    var data = window.__analyticsData;
    if (!data || !data.pullRequests) return;
    var rows = data.pullRequests;
    var csv = 'PR Number,Author,Created,CI Status,Sentinel Status,Auth Status,Authorized At,Device Name\n';
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var d = r.createdAt ? new Date(r.createdAt).toISOString().slice(0, 10) : '';
      var ad = r.authorizedAt ? new Date(r.authorizedAt).toISOString().slice(0, 10) : '';
      csv += '#' + r.prNumber + ',' +
        '"' + (r.author || '').replace(/"/g, '""') + '",' +
        d + ',' +
        r.ciStatus + ',' +
        r.sentinelStatus + ',' +
        r.authStatus + ',' +
        ad + ',' +
        '"' + (r.deviceName || '').replace(/"/g, '""') + '"\n';
    }
    var blob = new Blob([csv], { type: 'text/csv' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'sentinel-analytics-' + new Date().toISOString().slice(0, 10) + '.csv';
    a.click();
    URL.revokeObjectURL(url);
  });

  // Refresh analytics
  document.getElementById('analytics-refresh')?.addEventListener('click', function () { loadAnalytics(); });

  // GitHub Config
  async function loadGithubConfig() {
    const el = document.getElementById('github-config-display');
    try {
      const cfg = await api('/api/config/github-status');
      let html = '<div class="token-header"><span class="badge risk-badge ' + (cfg.configured ? 'success' : 'error') + '">' + (cfg.configured ? 'CONFIGURED' : 'NOT CONFIGURED') + '</span></div>';
      html += '<div class="token-detail"><span class="token-label">Owner</span><code>' + escapeHtml(cfg.owner || '(not set)') + '</code></div>';
      html += '<div class="token-detail"><span class="token-label">Repository</span><code>' + escapeHtml(cfg.repo || '(not set)') + '</code></div>';
      html += '<div class="token-detail"><span class="token-label">Auth Mode</span><span>' + (cfg.hasApp ? 'GitHub App' : cfg.hasPat ? 'PAT' : 'None') + '</span></div>';
      if (cfg.hasApp) {
        html += '<div class="token-detail"><span class="token-label">App ID</span><code>' + escapeHtml(cfg.appId) + '</code></div>';
        html += '<div class="token-detail"><span class="token-label">Installation</span><code>' + escapeHtml(cfg.installationId) + '</code></div>';
        html += '<div class="token-detail"><span class="token-label">Private Key</span><span class="badge ' + (cfg.privateKeyConfigured ? 'success' : 'error') + '">' + (cfg.privateKeyConfigured ? 'Configured' : 'Not set') + '</span></div>';
      }
      // Show scanner status
      html += '<div class="token-detail"><span class="token-label">Scanner</span><span class="badge ' + (cfg.scanEnabled ? 'success' : '') + '">' + (cfg.scanEnabled ? 'Enabled' : 'Disabled') + '</span></div>';
      html += '<div class="token-detail"><span class="token-label">Webhook Secret</span><span class="badge ' + (cfg.webhookSecretConfigured ? 'success' : '') + '">' + (cfg.webhookSecretConfigured ? 'Configured' : 'Not set') + '</span></div>';
      html += '<div style="margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border-color);display:flex;gap:0.5rem;flex-wrap:wrap">';
      if (!authenticated) {
        html += '<span style="width:100%;font-size:0.6rem;color:var(--text-dark);margin-bottom:0.5rem">Use the setup wizard to configure GitHub without authentication:</span>';
      }
      html += '<a href="/setup.html" style="display:inline-flex;align-items:center;padding:0.5rem 1rem;background:transparent;border:1px solid var(--border-color);border-radius:0;color:var(--text-main);font-size:0.7rem;font-weight:500;letter-spacing:0.08em;cursor:pointer;font-family:var(--font-mono);text-transform:uppercase;transition:all 0.15s ease;text-decoration:none">Open Setup Wizard</a>';
      html += '</div>';
      el.innerHTML = html;
    } catch (err) {
      el.innerHTML = '<p class="empty">Failed to load configuration</p>';
    }
  }

  // PR Detail expand
  async function expandPRDetail(prNumber) {
    const detailEl = document.getElementById('pr-detail-' + prNumber)
    const iconEl = document.getElementById('expand-icon-' + prNumber)
    if (!detailEl) return
    if (detailEl.style.display === 'block') {
      detailEl.style.display = 'none'
      if (iconEl) iconEl.textContent = '[+]'
      return
    }
    detailEl.style.display = 'block'
    if (iconEl) iconEl.textContent = '[-]'
    if (detailEl.dataset.loaded) return
    detailEl.dataset.loaded = '1'
    detailEl.innerHTML = '<div class="spinner"></div> LOADING TELEMETRY...'
    try {
      const prData = await api('/api/prs/' + prNumber + '/checks').catch(() => null)
      let html = '<div class="pr-detail-grid">'
      html += '<div class="detail-section"><div class="detail-section-title">Evidence & Findings</div>'
      html += '<button class="scan-btn" data-pr="' + prNumber + '" style="width:100%;margin-bottom:0.75rem;font-size:0.65rem">RUN CODE SCAN</button>'
      html += '<div id="detail-evidence-' + prNumber + '"><p class="empty">Run a scan to see evidence.</p></div></div>'
      html += '<div class="detail-section"><div class="detail-section-title">Check Runs</div>'
      if (prData && prData.checks && prData.checks.length > 0) {
        html += '<div class="checks-table"><table><tr><th>Name</th><th>Status</th><th>Duration</th></tr>'
        for (const c of prData.checks) {
          html += '<tr><td>' + escapeHtml(c.name || '-') + '</td>'
          html += '<td><span class="badge ' + (c.status || 'pending') + '">' + escapeHtml(c.status || 'pending') + '</span></td>'
          html += '<td class="duration">' + (c.duration ? c.duration + 's' : '-') + '</td></tr>'
        }
        html += '</table></div>'
      } else {
        html += '<p class="empty">No check runs available.</p>'
      }
      html += '</div>'
      html += '<div class="detail-section"><div class="detail-section-title">Telemetry</div>'
      if (prData && prData.pr) {
        const p = prData.pr
        html += '<div class="token-detail"><span class="token-label">Branch</span><span>' + escapeHtml(p.branch || '-') + '</span></div>'
        html += '<div class="token-detail"><span class="token-label">Base</span><span>' + escapeHtml(p.base || '-') + '</span></div>'
        html += '<div class="token-detail"><span class="token-label">Commits</span><span>' + (p.commitCount || '-') + '</span></div>'
        html += '<div class="token-detail"><span class="token-label">Changed</span><span>' + (p.changedFiles || '-') + ' files</span></div>'
      } else {
        html += '<p class="empty">Telemetry pending.</p>'
      }
      html += '</div></div>'
      detailEl.innerHTML = html
      detailEl.querySelector('.scan-btn')?.addEventListener('click', function (e) {
        const pr = parseInt(this.dataset.pr, 10)
        if (!isNaN(pr)) scanPR(pr, this)
      })
    } catch (err) {
      detailEl.innerHTML = '<p class="empty">Error: ' + escapeHtml(err.message) + '</p>'
    }
  }

  // ----- Blacklist -----
  async function loadBlacklist() {
    var display = document.getElementById('blacklist-display')
    if (!display) return
    try {
      var list = await api('/api/blacklist')
      if (!list || list.length === 0) {
        display.innerHTML = '<p class="empty">No hay PRs en la lista negra.</p>'
        return
      }
      var html = '<div class="blacklist-list">'
      for (var i = 0; i < list.length; i++) {
        var item = list[i]
        html += '<div class="blacklist-item">'
        html += '<div class="blacklist-item-header">'
        html += '<span class="pr-number">PR-' + item.prNumber + '</span>'
        html += '<span class="pr-title">' + escapeHtml(item.title || '') + '</span>'
        html += '<button class="blacklist-remove-btn" data-pr="' + item.prNumber + '">REMOVE</button>'
        html += '</div>'
        html += '<div class="blacklist-item-meta">'
        html += '<span>Author: ' + escapeHtml(item.author || '—') + '</span>'
        if (item.reason) html += '<span class="meta-divider">//</span><span>Reason: ' + escapeHtml(item.reason) + '</span>'
        html += '</div></div>'
      }
      html += '</div>'
      display.innerHTML = html
      display.querySelectorAll('.blacklist-remove-btn').forEach(function (btn) {
        btn.addEventListener('click', async function () {
          var pr = this.dataset.pr
          try {
            await api('/api/prs/' + pr + '/blacklist', { method: 'DELETE' })
            loadBlacklist()
          } catch (err) {
            alert('Error removing from blacklist: ' + err.message)
          }
        })
      })
    } catch (err) {
      display.innerHTML = '<p class="empty">Error loading blacklist: ' + escapeHtml(err.message) + '</p>'
    }
  }

  // Onboarding Checklist
  async function loadSetupChecklist() {
    const el = document.getElementById('onboarding-checklist')
    if (!el) return
    try {
      const cfg = await api('/api/config/github-status')
      const status = currentStatus || await api('/api/status')
      const hasPassword = status.passwordRequired
      const hasDevices = status.registeredDevices > 1
      const items = [
        { label: 'GitHub configured', done: cfg.configured, target: 'github-config-section' },
        { label: 'Webhook secret set', done: cfg.webhookSecretConfigured, target: 'webhook-section' },
        { label: 'Scanner enabled', done: cfg.scanEnabled, target: 'settings-section' },
        { label: 'Authorization password set', done: hasPassword, target: 'password-section' },
        { label: 'Backup device registered', done: hasDevices, target: 'devices-section' },
      ]
      const doneCount = items.filter(i => i.done).length
      if (doneCount === items.length) {
        el.style.display = 'none'
        return
      }
      el.style.display = 'block'
      let html = '<div class="checklist-header">SYSTEM SETUP <span class="badge" style="float:right">' + doneCount + '/' + items.length + ' COMPLETE</span></div>'
      html += '<div class="checklist-items">'
      for (const item of items) {
        var clickAttr = item.done ? '' : ' data-target="' + item.target + '" style="cursor:pointer"'
        html += '<div class="checklist-item"' + clickAttr + '><span class="checklist-indicator ' + (item.done ? 'done' : 'pending') + '">' + (item.done ? '[OK]' : '[--]') + '</span><span class="checklist-label">' + item.label + '</span></div>'
      }
      html += '</div>'
      el.innerHTML = html
      el.querySelectorAll('.checklist-item[data-target]').forEach(function (item) {
        item.addEventListener('click', function () {
          showPanel(this.dataset.target)
        })
      })
    } catch (err) {
      el.style.display = 'none'
    }
  }

  // Consolidated Settings Panel
  async function loadSettingsPanel() {
    if (!authenticated) return
    const el = document.getElementById('settings-display')
    if (!el) return
    try {
      const cfg = await api('/api/config/github-status')
      const status = currentStatus || await api('/api/status')
      let html = '<div class="settings-group"><div class="settings-group-title">01 // GitHub Integration</div>'
      html += '<div class="token-detail"><span class="token-label">Status</span><span class="badge ' + (cfg.configured ? 'success' : 'error') + '">' + (cfg.configured ? 'CONFIGURED' : 'NOT CONFIGURED') + '</span></div>'
      html += '<div class="token-detail"><span class="token-label">Owner</span><code>' + escapeHtml(cfg.owner || '(not set)') + '</code></div>'
      html += '<div class="token-detail"><span class="token-label">Repository</span><code>' + escapeHtml(cfg.repo || '(not set)') + '</code></div>'
      html += '<div class="token-detail"><span class="token-label">Auth Mode</span><span>' + (cfg.hasApp ? 'GitHub App' : cfg.hasPat ? 'PAT' : 'None') + '</span></div>'
      if (cfg.hasApp) {
        html += '<div class="token-detail"><span class="token-label">App ID</span><code>' + escapeHtml(cfg.appId) + '</code></div>'
        html += '<div class="token-detail"><span class="token-label">Private Key</span><span class="badge ' + (cfg.privateKeyConfigured ? 'success' : 'error') + '">' + (cfg.privateKeyConfigured ? 'Configured' : 'Not set') + '</span></div>'
      }
      html += '<div style="margin-top:0.75rem"><a href="/setup.html" style="color:var(--accent-blue);font-size:0.65rem;text-transform:uppercase">MODIFY GITHUB CONFIG →</a></div>'
      html += '</div>'

      html += '<div class="settings-group"><div class="settings-group-title">02 // Security</div>'
      html += '<div class="token-detail"><span class="token-label">Webhook Secret</span><span class="badge ' + (cfg.webhookSecretConfigured ? 'success' : '') + '">' + (cfg.webhookSecretConfigured ? 'Configured' : 'Not set') + '</span></div>'
      html += '<div class="token-detail"><span class="token-label">Auth Password</span><span class="badge ' + (status.passwordRequired ? 'success' : '') + '">' + (status.passwordRequired ? 'Enabled' : 'Disabled') + '</span></div>'
      html += '<div class="token-detail"><span class="token-label">Lockdown</span><span class="badge ' + (status.locked ? 'error' : 'success') + '">' + (status.locked ? 'ACTIVE' : 'Inactive') + '</span></div>'
      html += '<div class="token-detail"><span class="token-label">Devices</span><span>' + status.registeredDevices + ' registered</span></div>'
      html += '</div>'

      html += '<div class="settings-group"><div class="settings-group-title">03 // Scanner & Telemetry</div>'
      html += buildToggle('scanEnabled', 'PR Scanner', 'Enable code analysis on PR diffs', status)
      html += buildToggle('autoScan', 'Auto Scan', 'Automatically scan PRs when they arrive (requires scanner)', status)
      html += buildToggle('securityInbox', 'Security Inbox', 'Show findings requiring attention in prioritized view', status)
      html += buildToggle('analystQueue', 'Analyst Queue', 'Show PRs sorted by risk score for triage workflow', status)
      html += '<div class="token-detail"><span class="token-label">Auth Mode</span><span>' + escapeHtml(status.authMode || 'none') + '</span></div>'
      html += '<div style="margin-top:0.5rem;font-size:0.55rem;color:var(--text-dark);padding:0.4rem;border:1px dashed var(--border-color);">Toggle settings above — changes apply immediately.</div>'
      html += '</div>'

      html += '<div class="settings-group"><div class="settings-group-title">04 // AI Intelligence</div>'
      html += buildToggle('aiEnabled', 'AI PR Analysis', 'Enable AI-powered PR intelligence (Map-Reduce analysis with Qwen models)', status)
      html += buildToggle('autoAnalyze', 'Auto Analyze', 'Automatically analyze PRs when they arrive (requires AI enabled)', status)
      html += '<div class="token-detail"><span class="token-label">Model</span><select id="ai-model-select" style="background:#0d1117;color:#c9d1d9;border:1px solid #30363d;border-radius:4px;padding:0.3rem 0.5rem;font-size:0.65rem;font-family:var(--font-mono);width:100%;margin-top:0.3rem"><option value="">Auto-detect</option></select></div>'
      html += '<div id="ai-model-status" style="font-size:0.55rem;color:var(--text-dark);margin-top:0.2rem"></div>'
      html += '</div>'

      html += '<div class="settings-group"><div class="settings-group-title">05 // Sentinel Installer</div>'
      html += '<div class="token-detail"><span class="token-label">GitHub Actions Telemetry</span><span class="badge">OPTIONAL</span></div>'
      html += '<p style="font-size:0.6rem;color:var(--text-dark);line-height:1.5;margin:0.4rem 0">Install a workflow that sends workflow run timing data to Sentinel Oracle. This enables worklow intelligence, anomaly detection, and baseline tracking.</p>'
      html += '<button id="install-telemetry-btn" class="secondary-btn" style="width:100%;margin-top:0.4rem">⬇ INSTALL SENTINEL TELEMETRY WORKFLOW</button>'
      html += '<div id="install-telemetry-status" style="margin-top:0.3rem;font-size:0.55rem;color:var(--text-dark)"></div>'
      html += '</div>'

      el.innerHTML = html
      // Wire toggle events
      el.querySelectorAll('.toggle-switch input').forEach(function (inp) {
        inp.addEventListener('change', async function () {
          var key = this.id.replace('toggle-', '')
          var val = this.checked
          var body = {}
          body[key] = val
          try {
            await api('/api/config/settings', { method: 'POST', body: JSON.stringify(body) })
            if (key === 'scanEnabled' || key === 'autoScan' || key === 'aiEnabled' || key === 'autoAnalyze') {
              currentStatus = null  // force refresh
            }
          } catch (err) {
            this.checked = !val
          }
        })
      })
      // Populate model selector
      populateModelSelector()
      // Wire installer button
      var installBtn = document.getElementById('install-telemetry-btn')
      if (installBtn) {
        installBtn.addEventListener('click', async function () {
          var statusEl = document.getElementById('install-telemetry-status')
          statusEl.textContent = 'Downloading workflow template...'
          try {
            var yaml = await api('/api/installer/sentinel-telemetry')
            await navigator.clipboard.writeText(yaml)
            statusEl.innerHTML = '<span style="color:var(--accent-green)">Copied to clipboard!</span> Create <code>.github/workflows/sentinel-telemetry.yml</code> in your repo and paste this content.'
          } catch (err) {
            statusEl.textContent = 'Error: ' + escapeHtml(err.message)
          }
        })
      }
    } catch (err) {
      el.innerHTML = '<p class="empty">Error loading settings: ' + escapeHtml(err.message) + '</p>'
    }
  }

  function buildToggle(key, label, desc, status) {
    var checked = status[key] ? 'checked' : ''
    return '<div class="toggle-row">' +
      '<div class="toggle-info">' +
        '<div class="toggle-label">' + label + '</div>' +
        '<div class="toggle-desc">' + desc + '</div>' +
      '</div>' +
      '<label class="toggle-switch">' +
        '<input type="checkbox" id="toggle-' + key + '" ' + checked + '>' +
        '<span class="toggle-slider"></span>' +
      '</label>' +
    '</div>'
  }

  async function populateModelSelector() {
    var select = document.getElementById('ai-model-select')
    var statusEl = document.getElementById('ai-model-status')
    if (!select) return
    try {
      var data = await api('/api/ai/models')
      var models = data.models || []
      var selected = data.selected || ''
      select.innerHTML = '<option value="">Auto-detect</option>'
      for (var i = 0; i < models.length; i++) {
        var opt = document.createElement('option')
        opt.value = models[i].id
        opt.textContent = models[i].name + ' (' + models[i].backend + ')'
        if (models[i].id === selected) opt.selected = true
        select.appendChild(opt)
      }
      if (models.length === 0) {
        statusEl.textContent = 'No AI models detected'
      } else {
        statusEl.textContent = models.length + ' model(s) available'
      }
      select.addEventListener('change', async function () {
        var val = this.value
        this.style.borderColor = 'var(--accent-orange)'
        try {
          await api('/api/config/settings', { method: 'POST', body: JSON.stringify({ aiModel: val }) })
          statusEl.textContent = '✓ Model saved: ' + (val || 'auto-detect')
          statusEl.style.color = 'var(--accent-green)'
          this.style.borderColor = 'var(--accent-green)'
          setTimeout(function () {
            select.style.borderColor = '#30363d'
            statusEl.style.color = 'var(--text-dark)'
            statusEl.textContent = (select.options.length - 1) + ' model(s) available'
          }, 3000)
        } catch (err) {
          statusEl.textContent = 'Error saving model: ' + err.message
          statusEl.style.color = 'var(--accent-red)'
          this.style.borderColor = 'var(--accent-red)'
        }
      })
    } catch (err) {
      statusEl.textContent = 'Error: ' + err.message
    }
  }

  // Webhook Info
  async function loadWebhookInfo() {
    if (!authenticated) return;
    const el = document.getElementById('webhook-info');
    try {
      let secretHint = 'configured';
      if (currentStatus && currentStatus.webhookSecretHint) {
        secretHint = currentStatus.webhookSecretHint;
      } else {
        const status = await api('/api/status');
        currentStatus = status;
        if (status.webhookSecretHint) secretHint = status.webhookSecretHint;
      }
      el.innerHTML = '<div class="token-detail"><span class="token-label">Receiver</span><code>POST /api/webhook/github</code></div>' +
        '<div class="token-detail"><span class="token-label">Secret</span><span>' + escapeHtml(secretHint) + '</span></div>';
    } catch (err) {
      el.innerHTML = '<div class="token-detail"><span class="token-label">Receiver</span><code>POST /api/webhook/github</code></div>';
    }
  }

  // Auth Section
  function renderAuthConnected(el, credId) {
    el.innerHTML =
      '<div class="auth-section-card authenticated">' +
        '<div class="auth-section-icon authenticated">' +
          '<span class="lock-icon">&#x2713;</span>' +
          '<span class="ring-ripple"></span>' +
          '<span class="ring-ripple"></span>' +
          '<span class="ring-ripple"></span>' +
        '</div>' +
        '<div class="auth-section-connected">' +
          '<span class="auth-section-badge">Session Active</span>' +
          '<div class="auth-section-title">Authenticated</div>' +
          '<div class="auth-section-sub">All operations available — session is live</div>' +
          '<div class="auth-section-detail">Credential ID: <strong>' + (credId || '—') + '</strong></div>' +
        '</div>' +
      '</div>'
  }

  async function loadAuthSection() {
    const el = document.getElementById('auth-section-content')
    if (!el) return
    if (authenticated) {
      renderAuthConnected(el, currentCredentialId)
      return
    }
    try {
      var session = await api('/api/session/check')
      if (session.authenticated) {
        authenticated = true
        currentCredentialId = session.credentialId || currentCredentialId
        renderAuthConnected(el, currentCredentialId)
        return
      }
    } catch (e) {}
    // Not authenticated — render disconnected state
    el.innerHTML =
        '<div class="auth-section-card">' +
          '<div class="auth-section-icon">' +
            '<span class="lock-icon">&#x1F512;</span>' +
            '<span class="ring-ripple"></span>' +
            '<span class="ring-ripple"></span>' +
            '<span class="ring-ripple"></span>' +
          '</div>' +
          '<div class="auth-section-cta">' +
            '<span class="cta-line"></span>' +
            '<span class="cta-text">Passkey Required</span>' +
            '<span class="cta-line"></span>' +
          '</div>' +
          '<div class="auth-section-title">Authentication Required</div>' +
          '<div class="auth-section-sub">Authenticate with your security key to access the Sentinel dashboard</div>' +
          '<button id="auth-section-btn" class="auth-section-btn">' +
            '<span class="ripple-ring"></span>' +
            '<span class="ripple-ring"></span>' +
            '<span class="ripple-ring"></span>' +
            'Authenticate' +
          '</button>' +
          '<div id="auth-section-status" class="auth-section-status"></div>' +
        '</div>'
    document.getElementById('auth-section-btn').addEventListener('click', async function () {
        var btn = this
        var statusEl = document.getElementById('auth-section-status')
        btn.disabled = true
        statusEl.textContent = 'Authenticating...'
        statusEl.className = 'auth-section-status info'
        try {
          var data = await api('/api/webauthn/assert/begin', { method: 'POST' })
          var credential = await navigator.credentials.get({ publicKey: prepareWebAuthnOptions(data.options) })
          var result = await api('/api/webauthn/assert/complete', {
            method: 'POST',
            body: JSON.stringify({ credential: credential.toJSON(), challenge: data.challenge })
          })
          if (result.verified) {
            authenticated = true
            currentCredentialId = result.credentialId
            el.innerHTML =
              '<div class="auth-section-card authenticated">' +
                '<div class="auth-section-icon authenticated">' +
                  '<span class="lock-icon">&#x2713;</span>' +
                  '<span class="ring-ripple"></span>' +
                  '<span class="ring-ripple"></span>' +
                  '<span class="ring-ripple"></span>' +
                '</div>' +
                '<div class="auth-section-connected">' +
                  '<span class="auth-section-badge">Session Active</span>' +
                  '<div class="auth-section-title">Authenticated</div>' +
                  '<div class="auth-section-sub">Authentication successful — access granted</div>' +
                  '<div class="auth-section-detail">Credential ID: <strong>' + (result.credentialId || '—') + '</strong></div>' +
                '</div>' +
              '</div>'
          } else {
            statusEl.textContent = 'Authentication failed'
            statusEl.className = 'auth-section-status error'
          }
        } catch (err) {
          statusEl.textContent = err.name === 'NotAllowedError' ? 'Cancelled' : err.message
          statusEl.className = 'auth-section-status error'
        } finally {
          btn.disabled = false
        }
      })
  }

  // About Sentinel
  function loadAboutSentinel() {
    const el = document.getElementById('about-content')
    if (!el) return
    el.innerHTML =
      '<div class="about-container">' +
        '<div class="about-card primary">' +
          '<div class="about-card-header">' +
            '<span class="about-card-badge">01</span>' +
            '<span class="about-card-title">Qu&eacute; es</span>' +
          '</div>' +
          '<p>Sentinel Oracle es un servidor de autorizaci&oacute;n de merges f&iacute;sicamente aislado para GitHub. Opera como una capa de autorizaci&oacute;n adicional sobre branch protection. Las credenciales de merge residen en un dispositivo dedicado (Raspberry Pi, NUC, mini PC, o un tel&eacute;fono Android viejo) en la red local. La workstation que desarrolla c&oacute;digo nunca tiene las credenciales para mergear.</p>' +
        '</div>' +
        '<div class="about-card warning">' +
          '<div class="about-card-header">' +
            '<span class="about-card-badge">02</span>' +
            '<span class="about-card-title">Qu&eacute; NO es</span>' +
          '</div>' +
          '<p>No es un linter, ni un reemplazo de branch protection, ni un code review tool, ni un CI/CD pipeline. Es una capa de autorizaci&oacute;n que cierra el &uacute;ltimo vector de ataque antes de producci&oacute;n: la workstation comprometida con credenciales de merge.</p>' +
        '</div>' +
        '<div class="about-card arch">' +
          '<div class="about-card-header">' +
            '<span class="about-card-badge">03</span>' +
            '<span class="about-card-title">Arquitectura</span>' +
          '</div>' +
          '<div class="arch-device"><span class="arch-device-tag untrusted">D1</span> Workstation (no confiable) — Dashboard de solo lectura, nunca tiene credenciales de merge</div>' +
          '<div class="arch-device"><span class="arch-device-tag trusted">D2</span> Oracle Server (confiable) — Ejecuta merges v&iacute;a API de GitHub, expone dashboard HTTPS solo en Tailscale</div>' +
          '<div class="arch-device"><span class="arch-device-tag identity">D3</span> Tel&eacute;fono (identidad) — Passkey WebAuthn con biometr&iacute;a, firma cada autorizaci&oacute;n individual</div>' +
        '</div>' +
        '<div class="about-card">' +
          '<div class="about-card-header">' +
            '<span class="about-card-badge">04</span>' +
            '<span class="about-card-title">Misi&oacute;n</span>' +
          '</div>' +
          '<p>Separar f&iacute;sicamente la autoridad de merge del entorno de desarrollo. Sentinel Oracle garantiza que ninguna estaci&oacute;n de trabajo comprometida —por malware, extensiones maliciosas, npm supply chain attacks o phishing— pueda fusionar c&oacute;digo a producci&oacute;n sin autorizaci&oacute;n biom&eacute;trica desde un dispositivo independiente.</p>' +
          '<p>El merge no es una operaci&oacute;n de CI. Es un acto de autoridad que debe requerir presencia f&iacute;sica y consentimiento expl&iacute;cito.</p>' +
        '</div>' +
        '<div class="about-card">' +
          '<div class="about-card-header">' +
            '<span class="about-card-badge">05</span>' +
            '<span class="about-card-title">Visi&oacute;n</span>' +
          '</div>' +
          '<p>Un ecosistema donde el ciclo de vida del c&oacute;digo tenga tres roles irreducibles: el desarrollador escribe y prueba, la CI verifica calidad, y un dispositivo f&iacute;sico aislado —el Oracle— concede el merge. Ning&uacute;n ataque que comprometa solo un eslab&oacute;n puede completar un merge malicioso.</p>' +
        '</div>' +
        '<div class="about-card">' +
          '<div class="about-card-header">' +
            '<span class="about-card-badge">06</span>' +
            '<span class="about-card-title">Planteamiento del Problema</span>' +
          '</div>' +
          '<p>En la cadena de suministro de software moderna, el eslab&oacute;n m&aacute;s d&eacute;bil no es el c&oacute;digo, sino la workstation del desarrollador. Malware, extensiones maliciosas de IDE, ataques de phishing dirigidos y dependencias comprometidas pueden tomar control de las credenciales de Git y mergear c&oacute;digo malicioso a producci&oacute;n sin que nadie lo note.</p>' +
          '<p>Las soluciones existentes —branch protection, code review, CI pipelines— asumen que la workstation es confiable. Cuando ese supuesto se rompe, todas las dem&aacute;s defensas fallan en cascada. Sentinel Oracle elimina ese supuesto: las credenciales de merge nunca residen en la workstation, y cada merge requiere autorizaci&oacute;n biom&eacute;trica desde un dispositivo independiente.</p>' +
        '</div>' +
      '</div>'
  }
  // Help Guide
  async function loadHelp() {
    const el = document.getElementById('help-content')
    if (!el) return
    el.innerHTML = HELP_HTML
  }
  const HELP_HTML = `
<div class="help-section"><div class="help-section-title">01 // Pull Requests</div>
<p>The main operational view. Each open PR displays:</p>
<ul><li>PR number, title, author, creation time</li>
<li>Three status badges: CI status, Sentinel scan status, Gateway (auth) status</li>
<li>Action buttons: AUTHORIZE MERGE (QR), DIRECT AUTH (WebAuthn), REJECT</li>
<li>Scan Analysis button (when scanner is enabled) — runs code analysis on the PR diff</li>
<li>Expand Telemetry & Checks — shows check runs and CI details</li></ul>
<p>Click the PR title to expand a detail panel with scan evidence, check runs, and branch telemetry.</p>
<p>The PR list auto-refreshes every 15 seconds. A countdown timer in the section header shows time until next refresh.</p></div>

<div class="help-section"><div class="help-section-title">02 // Authorization Flows</div>
<p><b>QR Authorization (AUTHORIZE MERGE):</b></p>
<ol><li>Click AUTHORIZE MERGE on a PR</li>
<li>A QR code is displayed. The authenticator device scans it.</li>
<li>The device signs the challenge and sends confirmation to the server.</li>
<li>The PR is authorized and merged.</li></ol>
<p><b>Direct Authorization (DIRECT AUTH):</b></p>
<ol><li>Click DIRECT AUTH on a PR</li>
<li>Your browser's WebAuthn prompt appears — touch your passkey.</li>
<li>The assertion is sent to the server for verification.</li>
<li>The PR is authorized and merged.</li></ol>
<p><b>Rejection:</b> Click REJECT. You must re-authenticate with your passkey (re-assertion modal). Then the PR is marked as rejected.</p></div>

<div class="help-section"><div class="help-section-title">03 // Scan History</div>
<p>Shows all scan results over time. Features:</p>
<ul><li>Filters by date range and minimum risk level</li>
<li>Metric pills: total scans, average risk, critical/high/clean counts</li>
<li>Risk score timeline bar chart (svg)</li>
<li>Sortable table with PR number, title, risk score, finding counts, auth status, and date</li></ul>
<p>Click a PR number to jump back to the PR section.</p></div>

<div class="help-section"><div class="help-section-title">04 // History</div>
<p>Shows all PRs that have been authorized or rejected, with timestamps and the device name that performed the action.</p></div>

<div class="help-section"><div class="help-section-title">05 // Registered Devices</div>
<p>Lists all passkeys (WebAuthn credentials) registered on the server. Each device has a name, credential ID, and creation date. Devices can be revoked individually.</p>
<p><b>Registering a new device:</b> Authenticate first, then go to Devices section and use the Register form. The new device must be physically present (WebAuthn create ceremony).</p>
<p><b>First device (enrollment):</b> When no devices exist, the server shows an enrollment form. You need the enrollment token from the server console. This is a one-time setup step.</p></div>

<div class="help-section"><div class="help-section-title">06 // Lockdown</div>
<p>Emergency stop. Activating lockdown:</p>
<ul><li>All pending authorizations are rejected</li>
<li>No new merges can be authorized</li>
<li>The lockdown banner appears at the top of the dashboard</li></ul>
<p>Deactivate lockdown with the same button (requires re-authentication).</p></div>

<div class="help-section"><div class="help-section-title">07 // Auth Mode</div>

<p>Two authentication modes for GitHub. GitHub App is recommended for production; PAT is simpler for testing.</p>

<p><b>GITHUB APP (recommended for production)</b></p>
<p>Create the App at <code>https://github.com/settings/apps/new</code>. During creation, under <b>Repository Permissions</b>, set each permission to exactly one of these levels:</p>
<table class="help-table">
<tr><th>Permission</th><th>Level</th><th>Why</th><th>API endpoints used</th></tr>
<tr><td>Pull requests</td><td><b>Read &amp; Write</b></td><td>List open PRs, read PR diff files for scanning, and merge PRs after authorization</td><td><code>GET /pulls</code>, <code>GET /pulls/{n}/files</code>, <code>PUT /pulls/{n}/merge</code></td></tr>
<tr><td>Checks</td><td><b>Read &amp; Write</b></td><td>Read existing check runs to detect CI status, and create/update the "Sentinel Authorization" check run on each PR</td><td><code>GET /commits/{sha}/check-runs</code>, <code>POST /check-runs</code>, <code>PATCH /check-runs/{id}</code></td></tr>
<tr><td>Contents</td><td><b>Read</b> (not Write)</td><td>Compare commits between base and head for PR scanning, and get file commit history</td><td><code>GET /compare/{base}...{head}</code>, <code>GET /commits</code></td></tr>
<tr><td>Commit statuses</td><td><b>Read</b> (not Write)</td><td>Read combined commit status (e.g. CI build pass/fail) for each PR commit</td><td><code>GET /commits/{sha}/status</code></td></tr>
<tr><td>Metadata</td><td><b>Read</b> (auto)</td><td>Get repository default branch name and basic repo info. Auto-granted by GitHub, cannot be changed.</td><td><code>GET /repos/{owner}/{repo}</code></td></tr>
</table>
<p>Under <b>Subscribe to events</b>, you can optionally subscribe to <code>Pull request</code> and <code>Check suite</code> events for real-time updates (not required — Sentinel Oracle polls every 30s).</p>
<p>Under <b>Where can this App be installed?</b>, select <code>Only on this account</code> or <code>Any account</code>. After creation, go to <b>Install App</b> in the left sidebar, click <b>Install</b>, and select <b>Only select repositories</b> — pick the target repo. Note the <b>Installation ID</b> from the URL: <code>https://github.com/settings/installations/&lt;ID&gt;</code>.</p>
<p>Then generate a <b>Private Key</b> (PEM file) from the app settings page. You need: App ID, Installation ID, and the PEM file content.</p>

<p><b>PAT (Personal Access Token)</b></p>
<p>Create at <code>https://github.com/settings/tokens</code>:</p>
<ul>
<li><b>Classic PAT:</b> Scopes required: <code>repo</code> (full control of private repos) OR <code>public_repo</code> + <code>read:repo_hook</code> (public repos only). Note: classic PATs have user-level scope, not repo-level.</li>
<li><b>Fine-grained PAT:</b> Repository permissions: Pull requests (Read &amp; Write), Checks (Read &amp; Write), Contents (Read), Commit statuses (Read). Same as GitHub App permissions above.</li>
</ul>

<p><b>Single-repo limit:</b> Sentinel Oracle monitors exactly one repository — the one configured in <code>githubOwner</code> / <code>githubRepo</code>. Even if the GitHub App is installed on multiple repos, only the configured repo is polled. To protect multiple repos, run multiple instances on different ports.</p></div>

<div class="help-section"><div class="help-section-title">08 // Branch Protection</div>
<p>Verifies GitHub branch protection rules for the target branch. Shows required status checks, required reviews, and whether the branch is protected. Fetches data live from the GitHub API.</p></div>

<div class="help-section"><div class="help-section-title">09 // Metrics</div>
<p>Operational telemetry:</p>
<ul><li>Recent merge times per PR</li>
<li>Author statistics (number of PRs, average wait)</li>
<li>Total counts and averages</li></ul>
<p>Metrics are accumulated from authorization events. Auto-refreshes every 60 seconds.</p></div>

<div class="help-section"><div class="help-section-title">10 // Audit Log</div>
<p>Time-ordered event log of all system activity: authorizations, rejections, lockdown events, device registrations and revocations, config changes, errors. Each entry has a timestamp, action type, and detail. Auto-refreshes every 30 seconds.</p></div>

<div class="help-section"><div class="help-section-title">11 // Settings</div>
<p><b>GitHub Integration:</b> Configure repository owner, name, authentication mode (PAT or GitHub App), webhook secret, and scanner toggle. Use the Setup Wizard for guided configuration at /setup.html.</p>
<p><b>Required GitHub permissions by mode:</b></p>
<ul>
<li><b>PAT:</b> <code>repo</code> scope (private repos) or <code>public_repo</code> + <code>read:repo_hook</code> (public repos).</li>
<li><b>GitHub App:</b> Pull requests (Read &amp; Write), Checks (Read &amp; Write), Contents (Read).</li>
</ul>
<p><b>Repository scope:</b> Sentinel Oracle monitors exactly one repository at a time. Multiple repos require separate instances.</p>
<p><b>Authorization Password:</b> Optional second factor. If set, the operator must enter this password in addition to the WebAuthn passkey to authorize merges.</p>
<p><b>Webhook:</b> GitHub webhook receiver endpoint POST /api/webhook/github. Configure the webhook secret to verify payload authenticity.</p>
<p><b>Configuration file:</b> All settings persist in ~/.sentinel-oracle/config.json (JSON format, file mode 0600). Edit directly or use the API endpoints.</p></div>

<div class="help-section"><div class="help-section-title">12 // Token Inspector</div>
<p>Shows the current GitHub token used for API calls: type (PAT vs installation token), scopes/permissions, expiration, and risk assessment. The full inventory view at /inventory.html provides deeper analysis including drift detection and token scanning.</p></div>

<div class="help-section"><div class="help-section-title">13 // System Setup</div>
<p><b>Fresh install:</b></p>
<ol><li>Start the server: npm start (or node dist/index.js)</li>
<li>If GitHub is not configured, the server starts in setup mode.</li>
<li>Open /setup.html in a browser or navigate to the server URL.</li>
<li>Follow the 5-step wizard: Repository, GitHub App, Settings, Test, Done.</li>
<li>Stop the server with Ctrl+C and restart for changes to take effect.</li>
<li>On first access, complete device enrollment with the token from the console.</li>
<li>Authenticate with your passkey to access the dashboard.</li></ol>
<p><b>Environment variables:</b> (overrides config.json values)</p>
<ul><li>SENTINEL_GITHUB_PRIVATE_KEY — base64-encoded private key (overrides file path). Optional. Set only if not using the file-based key.</li>
<li>SENTINEL_GITHUB_PRIVATE_KEY_PATH — path to PEM file on disk. Optional. Alternative to pasting the key in the setup wizard.</li>
<li>SENTINEL_COOKIE_SECRET — override auto-generated cookie signing secret. Optional. Auto-generated if not set.</li>
<li>SENTINEL_HMAC_SEED — override HMAC seed (32 bytes hex). Optional. Auto-generated if not set.</li>
<li>SENTINEL_TEST_MODE=1 — enable test mode. Only needed for development with test tokens.</li>
<li>SENTINEL_SKIP_TOKEN_VERIFY=1 — skip GitHub token verification on startup. Only needed for development.</li></ul>
<p><b>What the system generates automatically (no user action needed):</b></p>
<ul><li>Encryption key → ~/.sentinel-oracle/.encryption_key</li>
<li>Cookie secret → ~/.sentinel-oracle/.cookie_secret</li>
<li>HMAC seed → ~/.sentinel-oracle/.hmac_seed</li>
<li>SQLite database → ~/.sentinel-oracle/data.db (session store, audit log, keys)</li>
<li>Self-signed HTTPS certs → ~/.sentinel-oracle/cert.pem, key.pem</li></ul>
<p><b>What the user must configure:</b></p>
<ul><li>GitHub owner + repository name (monitors exactly one repo)</li>
<li>Authentication: GitHub App (App ID, Installation ID, Private Key) OR Personal Access Token</li>
<li>Required GitHub App permissions: Pull requests (Read &amp; Write), Checks (Read &amp; Write), Contents (Read). For PAT: <code>repo</code> scope (private) or <code>public_repo</code> (public).</li>
<li>Install the GitHub App on the target repository (if using GitHub App mode).</li>
<li>Webhook secret (optional but recommended)</li></ul>
<p><b>Configuration file location:</b> ~/.sentinel-oracle/config.json — all user settings persist here.</p>
<p><b>Data directory:</b> ~/.sentinel-oracle/</p></div>

<div class="help-section"><div class="help-section-title">14 // API Endpoints</div>
<table class="help-table"><tr><th>Method</th><th>Path</th><th>Auth</th><th>Description</th></tr>
<tr><td>GET</td><td>/api/status</td><td>None</td><td>System status, device count, lockdown state, auth mode</td></tr>
<tr><td>GET</td><td>/api/config/github-status</td><td>None*</td><td>GitHub configuration state</td></tr>
<tr><td>POST</td><td>/api/config/github</td><td>Config*</td><td>Save GitHub App credentials</td></tr>
<tr><td>POST</td><td>/api/config/webhook</td><td>Config*</td><td>Set webhook secret</td></tr>
<tr><td>POST</td><td>/api/config/settings</td><td>Config*</td><td>Update scanner, challenge TTL, etc.</td></tr>
<tr><td>GET</td><td>/api/prs</td><td>Session</td><td>List pending PRs</td></tr>
<tr><td>POST</td><td>/api/prs/:n/authorize</td><td>Session</td><td>Create authorization challenge (QR)</td></tr>
<tr><td>POST</td><td>/api/prs/:n/confirm</td><td>None</td><td>Confirm authorization with credential</td></tr>
<tr><td>POST</td><td>/api/prs/:n/reject</td><td>Session</td><td>Reject a PR (requires re-assertion)</td></tr>
<tr><td>GET</td><td>/api/prs/:n/checks</td><td>Session</td><td>Check runs for a PR</td></tr>
<tr><td>GET</td><td>/api/devices</td><td>Session</td><td>List registered devices</td></tr>
<tr><td>GET</td><td>/api/audit</td><td>Session</td><td>Audit log entries</td></tr>
<tr><td>GET</td><td>/api/metrics</td><td>Session</td><td>Operational metrics</td></tr>
<tr><td>GET</td><td>/api/session/check</td><td>None</td><td>Check if session cookie is valid</td></tr>
<tr><td>POST</td><td>/api/webauthn/assert/begin</td><td>None</td><td>Start WebAuthn assertion</td></tr>
<tr><td>POST</td><td>/api/webauthn/assert/complete</td><td>None</td><td>Complete WebAuthn assertion (creates session)</td></tr>
<tr><td>POST</td><td>/api/webhook/github</td><td>HMAC</td><td>GitHub webhook receiver</td></tr></table>
<p><i>* Config endpoints are unauthenticated when GitHub is not configured (setup mode), session-authenticated otherwise.</i></p></div>

<div class="help-section"><div class="help-section-title">15 // Policies and Privacy</div>

<div class="help-section-title" style="font-size:13px;margin-top:12px">15.1 // Data Collection and Storage</div>
<p>Sentinel Oracle stores the following data on the server filesystem under <code>~/.sentinel-oracle/</code>:</p>
<ul>
<li><b>SQLite database (data.db):</b> PR metadata, audit log entries, registered WebAuthn credential IDs and device names, session records, configuration key-value store, and token scan results.</li>
<li><b>Encryption key (.encryption_key):</b> Auto-generated AES-256 key used to encrypt sensitive values at rest (GitHub tokens, HMAC seeds). Stored with file mode 0600.</li>
<li><b>Cookie secret (.cookie_secret):</b> Auto-generated secret used to sign session cookies.</li>
<li><b>HMAC seed (.hmac_seed):</b> Auto-generated seed for webhook payload verification.</li>
<li><b>Self-signed TLS certificates (cert.pem, key.pem):</b> Generated on first launch if no existing certificates are found.</li>
<li><b>Configuration file (config.json):</b> User-configured GitHub credentials, repository settings, and operational parameters. File mode 0600.</li>
</ul>
<p>No data is transmitted to third parties. All API communication occurs between the browser and the server over the configured network interface. GitHub API calls are made exclusively to api.github.com using the configured credentials.</p>

<div class="help-section-title" style="font-size:13px;margin-top:12px">15.2 // Credential Handling</div>
<p>WebAuthn credential IDs are stored in the database for credential verification. Private keys never leave the authenticator device (passkey, security key, or platform authenticator). The server stores only the credential public key and credential ID. Biometric data (fingerprint, face scan) never reaches the server — it is processed entirely by the authenticator.</p>
<p>GitHub tokens (PAT or installation tokens) are encrypted at rest using AES-256. The encryption key is auto-generated on first launch and stored separately from the database. Decrypted tokens are held in memory only during active API calls and are never written to disk unencrypted.</p>

<div class="help-section-title" style="font-size:13px;margin-top:12px">15.3 // Session Management</div>
<p>Session cookies are signed with the server's cookie secret to prevent tampering. Sessions expire after a configurable idle timeout (default 24 hours). Session data is stored in the local SQLite database and is never shared across server instances. Clearing browser cookies or logging out destroys the session reference on both client and server.</p>

<div class="help-section-title" style="font-size:13px;margin-top:12px">15.4 // Audit Logging</div>
<p>All authorization events, device registrations, revocations, lockdown toggles, configuration changes, and system errors are recorded in the audit log with an ISO 8601 timestamp. Audit log entries are immutable — no mechanism exists to delete or alter entries once written. The audit log is stored in the local SQLite database and is viewable through the dashboard Audit section.</p>

<div class="help-section-title" style="font-size:13px;margin-top:12px">15.5 // Security Responsibilities</div>
<p>The operator bears full responsibility for:</p>
<ul>
<li>Securing the server's filesystem and restricting access to the <code>~/.sentinel-oracle/</code> directory.</li>
<li>Configuring appropriate network controls (firewall, VPN, Tailscale ACLs) to limit access to the Sentinel Oracle web interface and API.</li>
<li>Protecting the GitHub credentials (PAT or GitHub App private key) from unauthorized disclosure.</li>
<li>Enabling GitHub branch protection to require the Sentinel Authorization check on the target branch.</li>
<li>Keeping the server and its dependencies updated.</li>
<li>Auditing the audit log regularly for unauthorized activity.</li>
<li>Using HTTPS in production (server auto-generates self-signed certs; for production, replace with a CA-signed certificate or place behind a TLS-terminating reverse proxy).</li>
</ul>

<div class="help-section-title" style="font-size:13px;margin-top:12px">15.6 // Disclaimer</div>
<p>Sentinel Oracle is provided as-is without warranty of any kind, express or implied. The software is a security tool that assists in merge authorization workflows but does not guarantee that every unauthorized merge will be prevented. The operator should implement defense in depth, including but not limited to branch protection rules, required status checks, code review policies, and regular security audits. The authors and contributors assume no liability for damages arising from the use or misuse of this software.</p></div>

<div class="help-section"><div class="help-section-title">16 // Project Structure</div>
<pre style="font-size:0.62rem;line-height:1.3;color:var(--text-dark);overflow-x:auto;white-space:pre;padding:0.5rem;background:var(--bg-primary);border:1px solid var(--border-color);">
sentinel-oracle/
├── public/                  # Frontend static files (served by Express)
│   ├── index.html           # Main dashboard SPA
│   ├── app.js               # All dashboard logic, help guide, API client
│   ├── setup.html           # Initial configuration wizard
│   ├── authorize.html       # QR authorization page for authenticator devices
│   ├── inventory.html       # Token inventory and drift detection UI
│   └── style.css            # Global styles (dark theme, terminal aesthetic)
├── src/                     # TypeScript backend source
│   ├── index.ts             # Entry point: parses config, initializes services
│   ├── server.ts            # Express app: all API routes, middleware, polling
│   ├── config.ts            # Config load/save/validation (~/.sentinel-oracle/config.json)
│   ├── startup.ts           # TLS cert generation, first-run setup
│   ├── logger.ts            # Console logger with ISO timestamps
│   ├── auth/                # WebAuthn (passkey) authentication
│   │   ├── webauthn.ts      # WebAuthn registration and assertion logic
│   │   └── challenge.ts     # Challenge generation and verification
│   ├── crypto/              # Cryptographic utilities
│   │   ├── signing.ts       # HMAC signing for webhook verification
│   │   └── password.ts      # Authorization password hashing (bcrypt)
│   ├── github/              # GitHub API integration
│   │   ├── client.ts        # GitHubClient class: all REST API calls
│   │   ├── auth.ts          # GitHubAppAuth: JWT generation, installation tokens
│   │   └── monitor.ts       # pollPRs: PR polling, CI status, branch protection
│   ├── storage/             # Persistent storage
│   │   ├── database.ts      # SQLite wrapper: PRs, sessions, devices, audit log
│   │   └── encryption.ts    # AES-256-GCM encrypt/decrypt for sensitive values
│   ├── scanner/             # PR diff security scanner
│   │   ├── index.ts         # scanPRFiles: entry point for scanning
│   │   └── rules.ts         # Detection rules: secrets, tokens, infra changes
│   ├── middleware/           # Express middleware
│   │   ├── session.ts       # Session cookie parsing and validation
│   │   ├── security.ts      # CORS, CSP, rate limit headers
│   │   └── rateLimit.ts     # Per-IP rate limiter
│   ├── queue/               # Authorization queue
│   │   └── authorization.ts # Lockdown state, challenge queue, PR auth flow
│   └── inventory/           # Token inventory and supply-chain scanning
│       └── tokens.ts        # GitHub token scanner, drift detection
├── scripts/                 # Standalone scripts (run with node)
│   ├── setup.cjs            # Interactive setup script for config.json
│   ├── gencert.cjs          # Generate self-signed TLS certificate
│   ├── check-db.cjs         # Inspect SQLite database contents
│   ├── setup-test-db.cjs    # Create test database with sample data
│   ├── reset-test-db.cjs    # Reset test database
│   ├── refresh-session.cjs  # Utility to inspect/clear sessions

├── test/                    # Unit tests (Vitest)
│   ├── authorization.test.ts
│   ├── e2e.test.ts
│   ├── encryption.test.ts
│   ├── github-auth.test.ts
│   ├── scanner.test.ts
│   └── signing.test.ts
├── README.md                # Project overview
├── docs/
│   ├── github-app-setup.md  # Step-by-step GitHub App creation guide
│   ├── security-audit.md    # Security audit report
│   └── attack-vectors.md    # Documented attack vectors and mitigations
├── tsconfig.json            # TypeScript compiler configuration
├── package.json             # Dependencies and scripts
└── start.cmd                # Windows start script</pre>
<p>Key entry points:</p>
<ul>
<li><code>npm start</code> — compiles TypeScript and runs <code>dist/index.js</code></li>
<li><code>npm run dev</code> — runs directly with <code>tsx src/index.ts</code> (hot reload)</li>
<li><code>npm test</code> — runs Vitest unit tests from <code>test/</code></li>
<li><code>node scripts/setup.cjs</code> — interactive config.json generator</li>
</ul></div>

<div class="help-section"><div class="help-section-title">17 // Security Scanner</div>
<p>The PR diff scanner analyzes code changes across 13 intel modules. Scans are deduplicated by SHA-256 of PR sha + file metadata; identical code is never scanned twice.</p>
<p><b>Intel Modules:</b></p>
<ul>
<li><b>Capabilities:</b> Filesystem, network, shell, dynamic code, database, crypto operations</li>
<li><b>Endpoints:</b> URLs, IP addresses, external domains</li>
<li><b>Services:</b> SDK integrations (Stripe, AWS, OpenAI)</li>
<li><b>Permissions:</b> Workflow permission changes</li>
<li><b>Dependencies:</b> npm, Python, Go, Rust dependency changes (EXPERIMENTAL: tarball diff)</li>
<li><b>Secrets:</b> Environment variable exposure, hardcoded credentials</li>
<li><b>Trust:</b> Data flow across trust boundaries</li>
<li><b>Crypto:</b> Algorithm changes, key length changes</li>
<li><b>Auth:</b> New routes, authentication middleware removal</li>
<li><b>Infrastructure:</b> Docker, Kubernetes, Terraform changes</li>
<li><b>CI Integrity:</b> Step redistribution, cache camouflage, fingerprint churn, campaign detection</li>
<li><b>Trust Drift:</b> New collaborators, GitHub Apps, secrets, runners, environments, branch protection removals, permission escalations</li>
<li><b>Security DNA:</b> 14-dimension capability fingerprint aggregator</li>
</ul>
<p><b>Auto Scan:</b> Toggle in Settings. When ON, all PRs auto-scan on queue refresh. Manual SCAN button when OFF.</p>
<p><b>Severity levels:</b> Critical (&gt;=10), High (&gt;=7), Medium (&gt;=4), Low (&gt;=1), None (0).</p></div>

<div class="help-section"><div class="help-section-title">18 // CI Integrity Engine</div>
<p>Monitors GitHub Actions workflows for anomalous behavior using MAD-based z-scores across three time windows (7d, 30d, full history).</p>
<p><b>Detection signals:</b> Step redistribution, cache camouflage, fingerprint churn, synthetic telemetry, evasion signals (YAML anchors, merge tags, template variables), cross-PR campaign detection with weighted scoring.</p>
<p><b>Multi-window baselines:</b> Each check computed independently for 7d/30d/full; worst z-score across all windows determines anomaly. Trusted baselines only train on PRs with <code>trusted: true</code>.</p>
<p><b>Integrity Score:</b> Starts at 100. Critical=-25, High=-15, Medium=-5, Low=-1, z&gt;10=-40, z&gt;5=-20, missing sensor=-10.</p></div>

<div class="help-section"><div class="help-section-title">19 // Trust Drift Detection</div>
<p>Monitors GitHub organization changes that weaken security posture. 7 weighted signals:</p>
<ul>
<li><b>Collaborator (+2):</b> New users with write/admin access</li>
<li><b>GitHub App (+3):</b> New GitHub Apps installed on the repo</li>
<li><b>Secret (+3):</b> New secrets added to environments</li>
<li><b>Runner (+3):</b> New self-hosted runners</li>
<li><b>Environment (+2):</b> New environments created</li>
<li><b>Branch Protection (+4):</b> Removal of branch protection rules</li>
<li><b>Permission Escalation (+4):</b> Escalated permissions in YAML workflow files</li>
</ul>
<p><b>Thresholds:</b> &gt;=10 critical, &gt;=6 high, &gt;=3 medium.</p></div>

<div class="help-section"><div class="help-section-title">20 // Security DNA</div>
<p>A capability aggregator that reads from existing IntelReport modules to produce a 14-dimension repository fingerprint. It is NOT a new detector — it observes, analyzes, and summarizes.</p>
<p><b>Dimensions:</b> filesystem, network, shell, dynamicCode, database, crypto, secrets, runners, environments, collaborators, permissionEscalations, newDomains, newIntegrations, workflowCount.</p>
<p>View at the Security DNA panel under SECURITY OPERATIONS. Snapshots persisted in SQLite and auto-generated after every scan.</p>
<p><b>API:</b> <code>GET /api/dna</code> returns current snapshot, history, per-field changes, summary statement, and count.</p></div>

<div class="help-section"><div class="help-section-title">21 // Documentation</div>
<p>Full documentation is available in the <code>docs/</code> directory:</p>
<ul>
<li><b>docs/architecture.md</b> — System architecture, module dependency graph, data flow, database schema</li>
<li><b>docs/api.md</b> — Complete API reference with request and response examples</li>
<li><b>docs/guide.md</b> — Operational guide: installation, configuration, CLI reference, troubleshooting</li>
<li><b>docs/security-dna.md</b> — Security DNA design, data flow, validation methodology and results</li>
</ul>
<p>GitHub repository: <a href="https://github.com/javier20dev25/sentinel-oracle" target="_blank">https://github.com/javier20dev25/sentinel-oracle</a></p></div>
`

  // Panel navigation
  let currentPanel = null
  let panelsLoaded = {}
  function showPanel(id) {
    document.querySelectorAll('.panel').forEach(function (p) { p.style.display = 'none' })
    if (!id) return
    const target = document.getElementById(id)
    if (target) {
      target.style.display = 'block'
      currentPanel = id
      // Lazy-load panel data if not loaded yet
      const allowUnauthenticated = ['github-config-section', 'setup-section', 'password-section', 'auth-section']
      if (!panelsLoaded[id] && (authenticated || allowUnauthenticated.includes(id))) {
        panelsLoaded[id] = true
        switch (id) {
          case 'soc-section': loadSOC(); break
          case 'dna-section': loadDNA(); break
          case 'inbox-section': loadInbox(); break
          case 'queue-section': loadQueue(); break
          case 'devices-section': loadDevices(); break
          case 'token-section': loadTokenInfo(); break
          case 'auth-mode-section': loadAuthMode(); break
          case 'branch-protection-section': loadBranchProtection(); break
          case 'metrics-section': loadMetrics(); break
          case 'webhook-section': loadWebhookInfo(); break
          case 'github-config-section': loadGithubConfig(); break
          case 'settings-section': loadSettingsPanel(); break
          case 'history-section': loadHistory(); break
          case 'audit-section': loadAudit(); break
          case 'password-section': loadPasswordSection(); break
          case 'analytics-section': loadAnalytics(); break
          case 'about-section': loadAboutSentinel(); break
          case 'auth-section': loadAuthSection(); break
          case 'help-section': loadHelp(); break
          case 'scans-section': loadScans(); break
          case 'blacklist-section': loadBlacklist(); break
        }
      }
    }
    document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.toggle('active', n.dataset.target === id) })
    const sidebar = document.getElementById('sidebar')
    if (sidebar && window.innerWidth <= 768) {
      sidebar.classList.remove('open')
    }
  }

  // Sidebar navigation — check auth first
  document.querySelectorAll('.nav-item').forEach(function (item) {
    item.addEventListener('click', function () {
      const targetId = this.dataset.target
      if (!targetId) return
      // Allow about, help, github-config without auth
      const publicPanels = ['about-section', 'auth-section', 'help-section', 'github-config-section', 'settings-section', 'password-section', 'enrollment-section', 'setup-section']
      if (!authenticated && !publicPanels.includes(targetId)) {
        const modal = document.getElementById('auth-modal')
        if (modal) {
          document.getElementById('auth-modal-message').textContent = 'Authenticate with your passkey to access this section.'
          modal.style.display = 'flex'
        }
        return
      }
      showPanel(targetId)
    })
  })

  document.getElementById('sidebar-toggle').addEventListener('click', function () {
    const sidebar = document.getElementById('sidebar')
    sidebar.classList.toggle('collapsed')
    this.textContent = sidebar.classList.contains('collapsed') ? '\u00bb' : '\u00ab'
  })

  const floatBtn = document.getElementById('sidebar-toggle-float')
  if (floatBtn) {
    floatBtn.addEventListener('click', function () {
      const sidebar = document.getElementById('sidebar')
      if (window.innerWidth <= 768) {
        sidebar.classList.add('open')
        this.style.display = 'none'
      } else {
        sidebar.classList.remove('collapsed')
      }
    })
  }

  // Init
  checkSetup()

  document.getElementById('backfill-btn').addEventListener('click', function () {
    var statusEl = document.getElementById('backfill-status')
    var btn = this
      statusEl.textContent = 'Starting...'
      statusEl.className = 'status info'
      btn.disabled = true
    api('/api/admin/backfill-history', { method: 'POST' }).then(function (data) {
      statusEl.textContent = 'Backfill running... 0 / ?'
      // poll progress
      var iv = setInterval(function () {
        api('/api/admin/backfill-status').then(function (s) {
          if (s.done) {
            clearInterval(iv)
            btn.disabled = false
            var msg = s.total + ' PRs processed' + (s.errors ? ', ' + s.errors + ' errors' : '')
            statusEl.textContent = msg
            statusEl.className = 'status ' + (s.errors ? 'error' : 'success')
            if (s.lastError) statusEl.title = s.lastError
            return
          }
          statusEl.textContent = 'Backfill: ' + s.current + ' / ' + s.total + (s.errors ? ' (' + s.errors + ' errs)' : '')
        }).catch(function () {
          // server might be busy
        })
      }, 3000)
    }).catch(function (err) {
      statusEl.textContent = 'Error: ' + escapeHtml(err.message)
      statusEl.className = 'status error'
      btn.disabled = false
    })
  })

  // Scan report modal events
  var scanReportModal = document.getElementById('scan-report-modal')
  if (scanReportModal) {
    document.getElementById('scan-report-close').addEventListener('click', function () {
      scanReportModal.style.display = 'none'
    })
    document.getElementById('scan-report-overlay').addEventListener('click', function () {
      scanReportModal.style.display = 'none'
    })
    document.getElementById('scan-report-export-json').addEventListener('click', function () {
      if (!lastScanResult) return
      var blob = new Blob([JSON.stringify(lastScanResult, null, 2)], { type: 'application/json' })
      var url = URL.createObjectURL(blob)
      var a = document.createElement('a')
      a.href = url; a.download = 'sentinel-scan-' + (lastScanResult.prNumber || 'pr') + '.json'
      document.body.appendChild(a); a.click()
      document.body.removeChild(a); URL.revokeObjectURL(url)
    })
    document.getElementById('scan-report-export-sarif').addEventListener('click', function () {
      if (!lastScanResult) return
      var sarif = buildSARIF(lastScanResult)
      var blob = new Blob([JSON.stringify(sarif, null, 2)], { type: 'application/json' })
      var url = URL.createObjectURL(blob)
      var a = document.createElement('a')
      a.href = url; a.download = 'sentinel-scan-' + (lastScanResult.prNumber || 'pr') + '.sarif'
      document.body.appendChild(a); a.click()
      document.body.removeChild(a); URL.revokeObjectURL(url)
    })
    document.getElementById('scan-report-print').addEventListener('click', function () {
      window.print()
    })
  }

  // AI report modal events
  var aiReportModal = document.getElementById('ai-report-modal')
  if (aiReportModal) {
    document.getElementById('ai-report-close').addEventListener('click', function () {
      aiReportModal.style.display = 'none'
    })
    document.getElementById('ai-report-overlay').addEventListener('click', function () {
      aiReportModal.style.display = 'none'
    })
    // Blacklist button in AI report modal
    var aiBlacklistBtn = document.getElementById('ai-report-blacklist-btn')
    if (aiBlacklistBtn) {
      aiBlacklistBtn.addEventListener('click', async function () {
        if (!_currentAiPrNumber) return
        var reason = prompt('Razón para añadir a lista negra:')
        if (!reason) return
        try {
          await api('/api/prs/' + _currentAiPrNumber + '/blacklist', {
            method: 'POST',
            body: JSON.stringify({ reason: reason })
          })
          alert('PR #' + _currentAiPrNumber + ' añadido a lista negra')
          aiReportModal.style.display = 'none'
          if (panelsLoaded['blacklist-section']) loadBlacklist()
        } catch (err) {
          alert('Error: ' + err.message)
        }
      })
    }
    // Save AI report as JSON download
    var aiSaveBtn = document.getElementById('ai-report-save-btn')
    if (aiSaveBtn) {
      aiSaveBtn.addEventListener('click', function () {
        if (!_currentAiPrNumber) return
        var result = _aiResults[_currentAiPrNumber]
        var explanation = _aiExplanations[_currentAiPrNumber]
        var data = { analysis: result, explanation: explanation, prNumber: _currentAiPrNumber, savedAt: new Date().toISOString() }
        var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
        var url = URL.createObjectURL(blob)
        var a = document.createElement('a')
        a.href = url
        a.download = 'sentinel-ai-report-pr-' + _currentAiPrNumber + '.json'
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
      })
    }
  }

  // Scan filter button
  document.getElementById('scan-filter-apply')?.addEventListener('click', loadScans)
  // Also re-apply on enter key in date inputs
  document.querySelectorAll('#scan-filter-from, #scan-filter-to').forEach(function(el) {
    el.addEventListener('change', loadScans)
  })

  loadAudit();
  panelsLoaded['audit-section'] = true
  setInterval(loadPRs, 15000);
  setInterval(loadAudit, 30000);
  setInterval(loadMetrics, 60000);
  setInterval(function () {
    if (currentPanel === 'soc-section') loadSOC()
  }, 30000);
  setInterval(function () {
    if (currentPanel === 'inbox-section') loadInbox()
  }, 30000);
  setInterval(function () {
    if (currentPanel === 'queue-section') loadQueue()
  }, 30000);

  // Refresh countdown
  var _refreshCountdown = 15
  setInterval(function () {
    var el = document.getElementById('refresh-countdown')
    if (el) {
      _refreshCountdown--
      if (_refreshCountdown <= 0) _refreshCountdown = 15
      el.textContent = 'REFRESH IN ' + _refreshCountdown + 'S'
    }
  }, 1000)
})();
