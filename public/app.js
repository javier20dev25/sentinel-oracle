(function () {
  'use strict';

  let authenticated = false;
  let currentCredentialId = null;
  let devicesRegistered = false;
  let currentStatus = null;
  let _connected = true

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
    const prevPanel = currentPanel
    showPanel('auth-section')
    const p = document.querySelector('#auth-section p')
    if (p) p.textContent = 'Session expired — please re-authenticate with your passkey'
    // Schedule a session re-check to recover from transient failures
    setTimeout(function () {
      if (!authenticated) {
        api('/api/session/check').then(function (s) {
          if (s.authenticated) {
            authenticated = true
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
      showPanel('auth-section');
    } else {
      showPanel('pr-section');
        await loadPRs();
        panelsLoaded['devices-section'] = true
        panelsLoaded['token-section'] = true
        panelsLoaded['auth-mode-section'] = true
        panelsLoaded['branch-protection-section'] = true
        panelsLoaded['metrics-section'] = true
        panelsLoaded['webhook-section'] = true
        panelsLoaded['history-section'] = true
        await loadDevices();
        await loadTokenInfo();
        await loadAuthMode();
        await loadBranchProtection();
        await loadMetrics();
        await loadWebhookInfo();
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
        showPanel('pr-section');
        await loadPRs();
        panelsLoaded['devices-section'] = true
        panelsLoaded['token-section'] = true
        panelsLoaded['auth-mode-section'] = true
        panelsLoaded['branch-protection-section'] = true
        panelsLoaded['metrics-section'] = true
        panelsLoaded['webhook-section'] = true
        panelsLoaded['history-section'] = true
        await loadDevices();
        await loadTokenInfo();
        await loadAuthMode();
        await loadBranchProtection();
        await loadMetrics();
        await loadWebhookInfo();
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
      } else {
        prList.innerHTML = '';
        for (const pr of prs) {
          const existing = document.getElementById('pr-card-' + pr.prNumber)
          if (existing) {
            // Update status badges in-place
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
                  <div class="pr-title-row">
                    <span class="pr-number">#${pr.prNumber}</span>
                    <h3 class="pr-title">${escapeHtml(pr.title)}</h3>
                  </div>
                  <div class="meta-row">
                    <span class="pr-author"><span class="meta-icon">👤</span>${escapeHtml(pr.author)}</span>
                    <span class="meta-divider">&middot;</span>
                    <span class="pr-date"><span class="meta-icon">📅</span>${new Date(pr.createdAt).toLocaleString()}</span>
                  </div>
                </div>
                <div class="status-row">
                  <span class="badge ${pr.ciStatus}">CI: ${pr.ciStatus}</span>
                  <span class="badge ${pr.sentinelStatus}">Sentinel: ${pr.sentinelStatus}</span>
                  <span class="badge ${pr.authStatus}">Auth: ${pr.authStatus}</span>
                </div>
                <div class="actions-wrapper">
                  <div class="actions">
                    <button class="auth-btn" data-pr="${pr.prNumber}"><span class="btn-icon">⚡</span>Authorize</button>
                    <button class="direct-auth-btn" data-pr="${pr.prNumber}"><span class="btn-icon">📱</span>Authorize (Same Device)</button>
                    <button class="reject-btn" data-pr="${pr.prNumber}"><span class="btn-icon">🚫</span>Reject</button>
                    ${currentStatus?.scanEnabled ? `<button class="scan-btn" data-pr="${pr.prNumber}"><span class="btn-icon">🔍</span>Scan</button>` : ''}
                  </div>
                </div>
                <div class="qr-section" id="qr-section-${pr.prNumber}" style="display:none"></div>
                <div class="checks-toggle-wrapper">
                  <button class="checks-toggle-btn" data-pr="${pr.prNumber}">Show Checks</button>
                </div>
                <div class="checks-section" id="checks-section-${pr.prNumber}" style="display:none"></div>
              </div>
              <div class="pr-card-scan-panel" id="scan-panel-${pr.prNumber}"></div>
            </div>
          `;
          prList.appendChild(card);
        }

        document.querySelectorAll('.auth-btn').forEach(btn => {
          btn.addEventListener('click', authorizePR);
        });
        document.querySelectorAll('.direct-auth-btn').forEach(btn => {
          btn.addEventListener('click', authorizeDirectPR);
        });
        document.querySelectorAll('.reject-btn').forEach(btn => {
          btn.addEventListener('click', rejectPR);
        });
        if (currentStatus?.scanEnabled) {
          document.querySelectorAll('.scan-btn').forEach(btn => {
            const pr = parseInt(btn.dataset.pr, 10)
            if (!isNaN(pr)) btn.addEventListener('click', () => scanPR(pr, btn));
          });
        }
        document.querySelectorAll('.checks-toggle-btn').forEach(btn => {
          btn.addEventListener('click', function () {
            togglePRChecks(this.dataset.pr, this);
          });
        });
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
      const severityClass = result.critical > 0 || result.high > 0 ? 'scan-critical' : result.medium > 0 ? 'scan-warning' : 'scan-clean';
      const severityLabel = result.critical > 0 ? 'CRITICAL' : result.high > 0 ? 'HIGH' : result.medium > 0 ? 'MEDIUM' : 'LOW';
      scanPanel.innerHTML = `
        <div class="scan-panel-header">
          <div class="risk-gauge-container ${severityClass}">
            <div class="risk-gauge-circle">
              <span class="risk-score-num">${result.riskScore}</span>
              <span class="risk-score-lbl">RISK</span>
            </div>
          </div>
          <div class="risk-summary-details">
            <h3 class="risk-label-title ${severityClass}">${severityLabel} RISK LEVEL</h3>
            <div class="severity-pill-row">
              <span class="sev-pill crit" title="Critical">${result.critical}C</span>
              <span class="sev-pill high" title="High">${result.high}H</span>
              <span class="sev-pill med" title="Medium">${result.medium}M</span>
              <span class="sev-pill low" title="Low">${result.low}L</span>
            </div>
          </div>
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
                        <span class="location-icon">📁</span>
                        <span class="location-path">${escapeHtml(f.file)}${f.line != null ? ':' + f.line : ''}</span>
                      </div>
                    ` : ''}
                    ${f.code ? `
                      <div class="code-terminal-mockup">
                        <div class="terminal-header">
                          <span class="terminal-dots">
                            <span class="terminal-dot close"></span>
                            <span class="terminal-dot minimize"></span>
                            <span class="terminal-dot maximize"></span>
                          </span>
                          <span class="terminal-file">${escapeHtml(filename)}</span>
                        </div>
                        <pre class="terminal-body"><code>${escapeHtml(f.code)}</code></pre>
                      </div>
                    ` : ''}
                  </div>
                  ${f.prUrl ? `
                    <div class="finding-card-footer">
                      <a href="${escapeHtml(f.prUrl)}" target="_blank" class="view-pr-link">
                        <span>View Line in GitHub</span>
                        <span class="link-arrow">&rarr;</span>
                      </a>
                    </div>
                  ` : ''}
                </div>
              `;
            }).join('')}
          </div>
        ` : `
          <div class="scan-clean-card">
            <span class="clean-icon">🛡️</span>
            <h4>No issues detected</h4>
            <p>This Pull Request complies with all security guidelines and policies analyzed by Sentinel.</p>
          </div>
        `}
      `;
      scanPanel.classList.add('active');
      btn.textContent = 'Re-scan';
    } catch (err) {
      console.error('Scan failed for PR #' + prNumber + ':', err)
      scanPanel.innerHTML = `<div class="scan-header scan-critical">Scan failed: ${escapeHtml(err.message)}</div>`;
      scanPanel.classList.add('active');
      btn.textContent = 'Scan';
    } finally {
      btn.disabled = false;
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

  // Password management
  const passwordForm = document.getElementById('password-form');
  if (passwordForm) {
    passwordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('password-btn');
      const cur = document.getElementById('current-password').value;
      const pwd = document.getElementById('new-password').value;
      btn.disabled = true;
      setStatus('password-status', 'Saving password...', 'info');

      try {
        await api('/api/config/password', {
          method: 'POST',
          body: JSON.stringify({ currentPassword: cur, newPassword: pwd }),
        });
        setStatus('password-status', 'Authorization password updated', 'success');
        document.getElementById('current-password').value = '';
        document.getElementById('new-password').value = '';
      } catch (err) {
        setStatus('password-status', err.message, 'error');
      } finally {
        btn.disabled = false;
      }
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

      const data = await api('/api/prs/' + prNumber + '/checks');

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
    } catch (err) {
      section.innerHTML = '<p class="empty">Error: ' + escapeHtml(err.message) + '</p>';
      btn.textContent = 'Show Checks';
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
      if (!panelsLoaded[id] && authenticated) {
        panelsLoaded[id] = true
        switch (id) {
          case 'devices-section': loadDevices(); break
          case 'token-section': loadTokenInfo(); break
          case 'auth-mode-section': loadAuthMode(); break
          case 'branch-protection-section': loadBranchProtection(); break
          case 'metrics-section': loadMetrics(); break
          case 'webhook-section': loadWebhookInfo(); break
          case 'history-section': loadHistory(); break
          case 'audit-section': loadAudit(); break
        }
      }
    }
    document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.toggle('active', n.dataset.target === id) })
    const sidebar = document.getElementById('sidebar')
    if (sidebar && window.innerWidth <= 768) {
      sidebar.classList.remove('open')
    }
  }

  // Sidebar navigation
  document.querySelectorAll('.nav-item').forEach(function (item) {
    item.addEventListener('click', function () {
      const targetId = this.dataset.target
      if (targetId) showPanel(targetId)
    })
  })

  document.getElementById('sidebar-toggle').addEventListener('click', function () {
    const sidebar = document.getElementById('sidebar')
    sidebar.classList.toggle('collapsed')
    this.textContent = sidebar.classList.contains('collapsed') ? '\u00bb' : '\u00ab'
  })

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

  loadAudit();
  panelsLoaded['audit-section'] = true
  setInterval(loadPRs, 15000);
  setInterval(loadAudit, 30000);
  setInterval(loadMetrics, 60000);
})();
