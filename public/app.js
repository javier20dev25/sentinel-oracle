(function () {
  'use strict';

  let authenticated = false;
  let currentCredentialId = null;
  let devicesRegistered = false;
  let currentStatus = null;

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
    currentStatus = status;
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
      hide('auth-mode-section');
      hide('branch-protection-section');
      hide('metrics-section');
      hide('webhook-section');
    } else if (!devicesRegistered) {
      show('setup-section');
      hide('enrollment-section');
      hide('auth-section');
      hide('pr-section');
      hide('devices-section');
      hide('lockdown-section');
      hide('auth-mode-section');
      hide('branch-protection-section');
      hide('metrics-section');
      hide('webhook-section');
    } else if (!authenticated) {
      show('auth-section');
      hide('setup-section');
      hide('pr-section');
      hide('devices-section');
      hide('lockdown-section');
      hide('auth-mode-section');
      hide('branch-protection-section');
      hide('metrics-section');
      hide('webhook-section');
    } else {
        show('pr-section');
        show('devices-section');
        show('lockdown-section');
        show('token-section');
        show('auth-mode-section');
        show('branch-protection-section');
        show('metrics-section');
        show('webhook-section');
        hide('enrollment-section');
        hide('setup-section');
        hide('auth-section');
        await loadPRs();
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
        show('auth-mode-section');
        show('branch-protection-section');
        show('metrics-section');
        show('webhook-section');
        await loadPRs();
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
            <button class="checks-toggle-btn" data-pr="${pr.prNumber}" style="margin-top:0.5rem;font-size:0.8rem;background:transparent;border:1px solid #30363d;">Show Checks</button>
            <div class="checks-section" id="checks-section-${pr.prNumber}" style="display:none"></div>
          `;
          prList.appendChild(card);
        }

        document.querySelectorAll('.auth-btn').forEach(btn => {
          btn.addEventListener('click', authorizePR);
        });
        document.querySelectorAll('.reject-btn').forEach(btn => {
          btn.addEventListener('click', rejectPR);
        });
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

      let html = '<div class="token-header"><span class="badge risk-badge ' + overallClass + '" style="font-size:0.9rem;padding:0.3rem 0.8rem;">' + overallText + '</span></div>';

      if (data.issues && data.issues.length > 0) {
        html += '<ul class="risk-reasons" style="margin-bottom:0.75rem;">';
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
      section.innerHTML = '<p style="padding:0.5rem;color:#8b949e;">Loading checks...</p>';
      section.style.display = 'block';
      btn.textContent = 'Hide Checks';

      const data = await api('/api/prs/' + prNumber + '/checks');

      let html = '<div style="padding:0.75rem 0;font-size:0.85rem;">';
      html += '<table style="width:100%;border-collapse:collapse;"><thead><tr style="border-bottom:1px solid #30363d;">';
      html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">Check</th>';
      html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">Conclusion</th>';
      html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">Duration</th></tr></thead><tbody>';

      if (data.checks && data.checks.length > 0) {
        data.checks.forEach(function (check) {
          var conclusionClass = check.conclusion === 'success' ? 'success' : check.conclusion === 'failure' ? 'error' : 'warning';
          html += '<tr style="border-bottom:1px solid #21262d;">';
          html += '<td style="padding:0.3rem 0.5rem;">' + escapeHtml(check.name) + '</td>';
          html += '<td style="padding:0.3rem 0.5rem;"><span class="badge ' + conclusionClass + '">' + escapeHtml(check.conclusion || 'pending') + '</span></td>';
          html += '<td style="padding:0.3rem 0.5rem;color:#8b949e;">' + (check.duration ? check.duration + 's' : '-') + '</td>';
          html += '</tr>';
        });
      } else {
        html += '<tr><td colspan="3" style="padding:0.5rem;color:#8b949e;">No checks found</td></tr>';
      }
      html += '</tbody></table>';

      if (data.diffStats) {
        html += '<div class="token-detail" style="margin-top:0.5rem;"><span class="token-label">Diff</span>';
        html += '<span>' + data.diffStats.files + ' files changed, <span style="color:#3fb950;">+' + data.diffStats.additions + '</span> <span style="color:#f85149;">-' + data.diffStats.deletions + '</span></span>';
        html += '</div>';
      }

      html += '</div>';
      section.innerHTML = html;
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

      let html = '<div class="token-header" style="flex-wrap:wrap;gap:0.75rem;">';
      html += '<span class="badge scope-badge low"><strong>Total PRs:</strong> ' + (data.totalPrs || 0) + '</span>';
      html += '<span class="badge scope-badge low"><strong>Pending:</strong> ' + (data.pending || 0) + '</span>';
      html += '<span class="badge scope-badge low"><strong>Authorized:</strong> ' + (data.authorized || 0) + '</span>';
      html += '<span class="badge scope-badge low"><strong>Rejected:</strong> ' + (data.rejected || 0) + '</span>';
      html += '<span class="badge scope-badge low"><strong>Expired:</strong> ' + (data.expired || 0) + '</span>';
      html += '</div>';

      if (data.recentMergeTimes && data.recentMergeTimes.length > 0) {
        html += '<h3 style="font-size:0.9rem;margin:0.75rem 0 0.5rem;color:#f0f6fc;">Recent Merge Times</h3>';
        html += '<table style="width:100%;border-collapse:collapse;font-size:0.85rem;"><thead><tr style="border-bottom:1px solid #30363d;">';
        html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">PR #</th>';
        html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">Title</th>';
        html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">Wait Time</th></tr></thead><tbody>';
        data.recentMergeTimes.forEach(function (m) {
          html += '<tr style="border-bottom:1px solid #21262d;">';
          html += '<td style="padding:0.3rem 0.5rem;">#' + m.prNumber + '</td>';
          html += '<td style="padding:0.3rem 0.5rem;">' + escapeHtml(m.title) + '</td>';
          html += '<td style="padding:0.3rem 0.5rem;color:#8b949e;">' + (m.waitTime || '-') + '</td></tr>';
        });
        html += '</tbody></table>';
      }

      if (data.authorStats && data.authorStats.length > 0) {
        html += '<h3 style="font-size:0.9rem;margin:0.75rem 0 0.5rem;color:#f0f6fc;">Author Stats</h3>';
        html += '<table style="width:100%;border-collapse:collapse;font-size:0.85rem;"><thead><tr style="border-bottom:1px solid #30363d;">';
        html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">Author</th>';
        html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">Merged</th>';
        html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">Rejected</th>';
        html += '<th style="text-align:left;padding:0.3rem 0.5rem;color:#8b949e;">Avg Wait</th></tr></thead><tbody>';
        data.authorStats.forEach(function (a) {
          html += '<tr style="border-bottom:1px solid #21262d;">';
          html += '<td style="padding:0.3rem 0.5rem;">' + escapeHtml(a.author) + '</td>';
          html += '<td style="padding:0.3rem 0.5rem;">' + (a.merged || 0) + '</td>';
          html += '<td style="padding:0.3rem 0.5rem;">' + (a.rejected || 0) + '</td>';
          html += '<td style="padding:0.3rem 0.5rem;color:#8b949e;">' + (a.avgWait || '-') + '</td></tr>';
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

  // Init
  checkSetup();
  loadAudit();
  setInterval(loadPRs, 15000);
  setInterval(loadAudit, 30000);
  setInterval(loadMetrics, 60000);
})();
