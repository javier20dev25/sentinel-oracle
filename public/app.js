(function () {
  'use strict';

  let authenticated = false;
  let currentCredentialId = null;
  let devicesRegistered = false;

  function base64urlToBuffer(str) {
    const padding = '='.repeat((4 - str.length % 4) % 4);
    const base64 = (str + padding).replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    const buf = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) buf[i] = raw.charCodeAt(i);
    return buf;
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
    const res = await fetch(path, {
      headers: { 'Content-Type': 'application/json' },
      ...options,
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error || `Request failed (${res.status})`);
    }
    return res.json();
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
    updateLockdownBanner(status.locked);

    // Validate session server-side
    const session = await api('/api/session/check');
    authenticated = session.authenticated;

    if (status.setupRequired) {
      show('enrollment-section');
      hide('setup-section');
      hide('auth-section');
      hide('pr-section');
      hide('devices-section');
      hide('lockdown-section');
    } else if (!devicesRegistered) {
      show('setup-section');
      hide('enrollment-section');
      hide('auth-section');
      hide('pr-section');
      hide('devices-section');
      hide('lockdown-section');
    } else if (!authenticated) {
      show('auth-section');
      hide('setup-section');
      hide('pr-section');
      hide('devices-section');
      hide('lockdown-section');
    } else {
        show('pr-section');
        show('devices-section');
        show('lockdown-section');
        show('token-section');
        hide('enrollment-section');
        hide('setup-section');
        hide('auth-section');
        await loadPRs();
        await loadDevices();
        await loadTokenInfo();
      }
    }
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
        setStatus('auth-status', 'Authenticated successfully!', 'success');
        hide('auth-section');
        hide('enrollment-section');
        show('pr-section');
        show('devices-section');
        show('lockdown-section');
        show('token-section');
        await loadPRs();
        await loadDevices();
        await loadTokenInfo();
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
  async function loadPRs() {
    if (!authenticated) return;
    const prList = document.getElementById('pr-list');

    try {
      const prs = await api('/api/prs');
      if (prs.length === 0) {
        prList.innerHTML = '<p class="empty">No pending PRs awaiting authorization.</p>';
      } else {
        prList.innerHTML = '';
        for (const pr of prs) {
          const card = document.createElement('div');
          card.className = 'pr-card';
          card.innerHTML = `
            <h3>#${pr.prNumber}: ${escapeHtml(pr.title)}</h3>
            <div class="meta">${escapeHtml(pr.author)} &middot; ${new Date(pr.createdAt).toLocaleString()}</div>
            <div class="status-row">
              <span class="badge ${pr.ciStatus}">CI: ${pr.ciStatus}</span>
              <span class="badge ${pr.sentinelStatus}">Sentinel: ${pr.sentinelStatus}</span>
              <span class="badge ${pr.authStatus}">Auth: ${pr.authStatus}</span>
            </div>
            <div class="actions">
              <button class="auth-btn" data-pr="${pr.prNumber}">Authorize</button>
              <button class="reject-btn" data-pr="${pr.prNumber}" style="background:#da3633">Reject</button>
            </div>
            <div class="qr-section" id="qr-section-${pr.prNumber}" style="display:none"></div>
          `;
          prList.appendChild(card);
        }

        document.querySelectorAll('.auth-btn').forEach(btn => {
          btn.addEventListener('click', authorizePR);
        });
        document.querySelectorAll('.reject-btn').forEach(btn => {
          btn.addEventListener('click', rejectPR);
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
      const section = document.getElementById('history-section');
      if (prs.length === 0) {
        section.style.display = 'none';
        return;
      }
      section.style.display = 'block';
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
      const { challengeId, qrUrl, expiresAt } = await api(`/api/prs/${prNumber}/authorize`, {
        method: 'POST',
      });

      qrSection.style.display = 'block';
      qrSection.innerHTML = '<div class="qr-status">Scan with your authenticator device</div>';

      const QRCode = window.QRCode;
      if (typeof QRCode !== 'undefined') {
        QRCode.toCanvas(qrUrl, { width: 256 }, function (err, canvas) {
          if (err) {
            qrSection.innerHTML += `<p>${escapeHtml(qrUrl)}</p>`;
            return;
          }
          qrSection.insertBefore(canvas, qrSection.firstChild);
        });
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
      setStatus('pr-list', `Authorization failed: ${err.message}`, 'error');
    } finally {
      e.target.disabled = false;
    }
  }

  async function rejectPR(e) {
    const prNumber = e.target.dataset.pr;
    e.target.disabled = true;

    try {
      await api(`/api/prs/${prNumber}/reject`, { method: 'POST' });
      await loadPRs();
    } catch (err) {
      setStatus('pr-list', `Rejection failed: ${err.message}`, 'error');
    } finally {
      e.target.disabled = false;
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
          <button class="revoke-btn" data-credential="${device.credentialId}" style="background:#da3633;margin-left:auto;">Revoke</button>
        `;
        deviceList.appendChild(div);
      }

      document.querySelectorAll('.revoke-btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
          const credentialId = e.target.dataset.credential;
          const row = e.target.closest('.device-row');
          e.target.disabled = true;
          try {
            await api(`/api/devices/${encodeURIComponent(credentialId)}/revoke`, { method: 'POST' });
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
    const btn = document.getElementById('lockdown-btn');
    const unlockBtn = document.getElementById('unlock-btn');
    btn.disabled = true;
    setStatus('lockdown-status', 'Activating lockdown...', 'info');

    try {
      await api('/api/lockdown', { method: 'POST' });
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
    const btn = document.getElementById('unlock-btn');
    const lockdownBtn = document.getElementById('lockdown-btn');
    btn.disabled = true;
    setStatus('lockdown-status', 'Deactivating lockdown...', 'info');

    try {
      await api('/api/unlock', { method: 'POST' });
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
          headers: { 'Content-Type': 'application/json' },
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

  // Init
  checkSetup();
  loadAudit();
  setInterval(loadPRs, 15000);
  setInterval(loadAudit, 30000);
})();
