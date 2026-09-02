// frontend/app.js - Vendor Fraud Guardian Secure SPA Controller (Step 6 Blueprint v2)

// ==========================================
// 1. STATE MANAGEMENT & SESSION STORE
// ==========================================
const state = {
  user: null, // { user_id, company_id, role, aal, jwt_token, email }
  currentRoute: '/login',
  requests: [],
  auditLogs: [],
  selectedRequest: null
};

// Load saved session on bootstrap
function initSession() {
  const saved = localStorage.getItem('vfg_session');
  if (saved) {
    try {
      state.user = JSON.parse(saved);
    } catch (e) {
      localStorage.removeItem('vfg_session');
    }
  }
}

function saveSession(userData) {
  state.user = userData;
  localStorage.setItem('vfg_session', JSON.stringify(userData));
  renderHeader();
}

function clearSession() {
  state.user = null;
  localStorage.removeItem('vfg_session');
  renderHeader();
  showToast('Your session has expired. Please sign in again.', 'warning');
  navigate('/login');
}

// ==========================================
// 2. TOAST NOTIFICATION ENGINE
// ==========================================
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  const colors = {
    success: 'bg-emerald-950/90 border-emerald-500/50 text-emerald-200',
    warning: 'bg-amber-950/90 border-amber-500/50 text-amber-200',
    error: 'bg-rose-950/90 border-rose-500/50 text-rose-200',
    critical: 'bg-red-950/95 border-red-500 text-red-100 ring-2 ring-red-500/50',
    info: 'bg-blue-950/90 border-blue-500/50 text-blue-200'
  };

  const icons = {
    success: 'fa-circle-check text-emerald-400',
    warning: 'fa-triangle-exclamation text-amber-400',
    error: 'fa-circle-xmark text-rose-400',
    critical: 'fa-skull-crossbones text-red-400 animate-pulse',
    info: 'fa-circle-info text-blue-400'
  };

  toast.className = `p-4 rounded-xl border backdrop-blur-md shadow-2xl flex items-start space-x-3 pointer-events-auto transition-all duration-300 transform translate-x-10 opacity-0 ${colors[type] || colors.info}`;
  toast.innerHTML = `
    <i class="fa-solid ${icons[type] || icons.info} text-lg mt-0.5"></i>
    <div class="flex-1 text-sm font-medium leading-snug">${message}</div>
    <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-white transition">
      <i class="fa-solid fa-xmark"></i>
    </button>
  `;

  container.appendChild(toast);

  requestAnimationFrame(() => {
    toast.classList.remove('translate-x-10', 'opacity-0');
  });

  setTimeout(() => {
    toast.classList.add('opacity-0', 'translate-x-10');
    setTimeout(() => toast.remove(), 300);
  }, 5000);
}

// ==========================================
// 3. API SERVICE & ERROR INTERCEPTOR
// ==========================================
async function apiCall(endpoint, method = 'GET', body = null) {
  const headers = {
    'Content-Type': 'application/json'
  };

  if (state.user && state.user.jwt_token) {
    headers['Authorization'] = `Bearer ${state.user.jwt_token}`;
  }

  try {
    const options = { method, headers };
    if (body) options.body = JSON.stringify(body);

    const res = await fetch(endpoint, options);
    const data = await res.json().catch(() => ({}));

    if (!res.ok) {
      handleApiError(res.status, data.detail || res.statusText);
      throw new Error(data.detail || `HTTP error ${res.status}`);
    }

    return data;
  } catch (err) {
    throw err;
  }
}

function handleApiError(status, detail) {
  // Step 6 Section 5: Error Handling Matrix
  if (status === 401) {
    clearSession();
  } else if (status === 403) {
    if (detail && detail.includes('AAL2')) {
      showToast('Step-Up MFA Required. Redirecting to MFA verification...', 'warning');
      navigate('/setup-mfa');
    } else if (detail && detail.includes('MAKER_CHECKER_SEPARATION')) {
      showToast('Security Violation: You cannot approve a verification created by yourself.', 'critical');
    } else {
      showToast(detail || 'You are not authorized for this action.', 'error');
    }
  } else if (status === 409) {
    showToast(detail || 'Duplicate/conflicting request message detected.', 'warning');
  } else if (status === 500) {
    showToast('Fail-Secure Event: Request routed to MANUAL_SYS_OVERRIDE.', 'critical');
  } else {
    showToast(detail || 'An unexpected error occurred.', 'error');
  }
}

// ==========================================
// 4. ROUTER & ROLE-BASED ACCESS CONTROL
// ==========================================
function navigate(route) {
  state.currentRoute = route;
  window.history.pushState({}, '', route);
  renderView();
}

window.onpopstate = () => {
  state.currentRoute = window.location.pathname;
  renderView();
};

function renderHeader() {
  const userSection = document.getElementById('user-context-section');
  const navLinks = document.getElementById('nav-links');

  if (!state.user) {
    navLinks.classList.add('hidden');
    userSection.innerHTML = `
      <button onclick="navigate('/login')" class="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition shadow-lg shadow-blue-500/25">
        Sign In
      </button>
    `;
    return;
  }

  navLinks.classList.remove('hidden');

  // Role badge styling
  const isChecker = ['admin', 'checker', 'finance_manager'].includes(state.user.role);
  const roleBadge = isChecker
    ? '<span class="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-emerald-500/20 text-emerald-300 border border-emerald-500/30">CHECKER</span>'
    : '<span class="px-2 py-0.5 rounded text-xs font-mono font-semibold bg-blue-500/20 text-blue-300 border border-blue-500/30">MAKER</span>';

  const mfaBadge = state.user.aal === 'aal2'
    ? '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30" title="Step-Up MFA Active">AAL2</span>'
    : '<span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-700 text-slate-400" title="Standard Auth">AAL1</span>';

  userSection.innerHTML = `
    <div class="flex items-center space-x-3">
      <div class="flex flex-col text-right">
        <div class="flex items-center justify-end space-x-1.5">
          <span class="text-xs font-medium text-slate-200">${state.user.email || 'Operator'}</span>
          ${roleBadge}
          ${mfaBadge}
        </div>
        <span class="text-[11px] font-mono text-slate-400 truncate max-w-[140px]">${state.user.company_id}</span>
      </div>

      <button onclick="clearSession()" title="Sign Out" class="p-2 rounded-lg bg-slate-800 hover:bg-rose-900/40 text-slate-400 hover:text-rose-300 border border-slate-700/60 transition">
        <i class="fa-solid fa-arrow-right-from-bracket text-sm"></i>
      </button>
    </div>
  `;
}

// ==========================================
// 5. VIEW RENDERERS
// ==========================================
function renderView() {
  const container = document.getElementById('app-view');
  renderHeader();

  // Guard: Not logged in
  if (!state.user && state.currentRoute !== '/login') {
    state.currentRoute = '/login';
  }

  switch (state.currentRoute) {
    case '/login':
      renderLoginView(container);
      break;
    case '/maker':
    case '/maker/requests':
      renderMakerQueue(container);
      break;
    case '/checker':
    case '/checker/requests':
      renderCheckerQueue(container);
      break;
    case '/setup-mfa':
      renderSetupMFA(container);
      break;
    case '/intake':
      renderIntakeForm(container);
      break;
    case '/audit-logs':
      renderAuditLogs(container);
      break;
    default:
      if (state.user) {
        if (['admin', 'checker', 'finance_manager'].includes(state.user.role)) {
          navigate('/checker');
        } else {
          navigate('/maker');
        }
      } else {
        renderLoginView(container);
      }
  }
}

// --- VIEW: LOGIN / SESSION INITIALIZATION ---
function renderLoginView(container) {
  container.innerHTML = `
    <div class="max-w-md mx-auto py-12">
      <div class="glass-card p-8 rounded-2xl shadow-2xl border border-slate-800">
        <div class="text-center mb-8">
          <div class="inline-flex h-14 w-14 rounded-2xl bg-gradient-to-tr from-blue-600 to-indigo-600 items-center justify-center shadow-lg shadow-blue-500/20 mb-4 ring-1 ring-white/20">
            <i class="fa-solid fa-shield-halved text-2xl text-white"></i>
          </div>
          <h2 class="text-2xl font-bold tracking-tight text-white">Console Authentication</h2>
          <p class="text-xs text-slate-400 mt-1">Multi-Tenant JWT & Role-Protected Session</p>
        </div>

        <form id="login-form" onsubmit="handleLoginSubmit(event)" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Company / Tenant ID (UUID)</label>
            <input type="text" id="login-company-id" required value="a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-900/80 border border-slate-700 text-slate-100 text-sm font-mono focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition">
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">User Identifier</label>
            <input type="text" id="login-user-id" required value="b1eebc99-9c0b-4ef8-bb6d-6bb9bd380b22" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-900/80 border border-slate-700 text-slate-100 text-sm font-mono focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition">
          </div>

          <div>
            <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Select Role</label>
            <select id="login-role" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-900/80 border border-slate-700 text-slate-100 text-sm font-medium focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition">
              <option value="reviewer">Maker / Reviewer (Out-of-band Verification)</option>
              <option value="checker">Checker (Step-Up MFA Approval)</option>
              <option value="admin">Admin / Finance Manager</option>
            </select>
          </div>

          <div class="pt-2">
            <button type="submit" class="w-full py-3 rounded-xl bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-sm font-semibold tracking-wide shadow-lg shadow-blue-600/30 transition transform active:scale-98">
              Establish Secure Session
            </button>
          </div>
        </form>

        <div class="mt-6 pt-6 border-t border-slate-800/80 text-center">
          <p class="text-[11px] text-slate-500">FastAPI backend authenticates against Supabase PostgREST RLS.</p>
        </div>
      </div>
    </div>
  `;
}

function handleLoginSubmit(event) {
  event.preventDefault();
  const company_id = document.getElementById('login-company-id').value.trim();
  const user_id = document.getElementById('login-user-id').value.trim();
  const role = document.getElementById('login-role').value;

  const mockJwt = `header.${btoa(JSON.stringify({
    sub: user_id,
    company_id: company_id,
    role: role,
    aal: role === 'reviewer' ? 'aal1' : 'aal2',
    exp: Math.floor(Date.now() / 1000) + 3600
  }))}.signature`;

  const userData = {
    user_id,
    company_id,
    role,
    aal: role === 'reviewer' ? 'aal1' : 'aal2',
    jwt_token: mockJwt,
    email: `${role}_operator@tenant.internal`
  };

  saveSession(userData);
  showToast(`Authenticated successfully as ${role.toUpperCase()}`, 'success');

  if (['admin', 'checker', 'finance_manager'].includes(role)) {
    navigate('/checker');
  } else {
    navigate('/maker');
  }
}

// --- VIEW: MAKER QUEUE (PENDING_REVIEW) ---
function renderMakerQueue(container) {
  container.innerHTML = `
    <div class="space-y-6">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold text-white tracking-tight flex items-center">
            <i class="fa-solid fa-user-pen text-blue-400 mr-3"></i>
            Maker Verification Queue
          </h1>
          <p class="text-xs text-slate-400 mt-1">Requests requiring Out-of-Band Trusted Phone Verification (Status: PENDING_REVIEW)</p>
        </div>

        <div class="flex items-center space-x-2">
          <button onclick="navigate('/intake')" class="px-3.5 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition flex items-center space-x-1.5 shadow-md shadow-blue-600/20">
            <i class="fa-solid fa-plus text-xs"></i>
            <span>Simulate Ingestion</span>
          </button>
          <button onclick="renderMakerQueue(document.getElementById('app-view'))" class="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition">
            <i class="fa-solid fa-rotate text-xs"></i>
          </button>
        </div>
      </div>

      <!-- Queue Table -->
      <div class="glass-card rounded-xl border border-slate-800 overflow-hidden shadow-xl">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-900/90 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th class="p-4">Request ID / Vendor</th>
                <th class="p-4">Source</th>
                <th class="p-4">Risk Score</th>
                <th class="p-4">Signals</th>
                <th class="p-4">Status</th>
                <th class="p-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody id="maker-queue-tbody" class="divide-y divide-slate-800/60 font-medium">
              <!-- Demo / Live entries -->
              <tr class="hover:bg-slate-900/40 transition">
                <td class="p-4">
                  <div class="font-mono text-slate-200 font-semibold">req-89a1c-demo</div>
                  <div class="text-slate-400 text-[11px] mt-0.5">Acme Heavy Industries Pvt Ltd</div>
                </td>
                <td class="p-4">
                  <span class="px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 font-mono text-[10px]">PDF_UPLOAD</span>
                </td>
                <td class="p-4">
                  <div class="flex items-center space-x-2">
                    <span class="font-mono font-bold text-amber-400 text-sm">65</span>
                    <span class="px-1.5 py-0.5 rounded text-[10px] bg-amber-500/20 text-amber-300 font-semibold">HIGH</span>
                  </div>
                </td>
                <td class="p-4">
                  <div class="flex flex-wrap gap-1">
                    <span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">is_bank_account_changed</span>
                    <span class="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px] font-mono">is_domain_mismatch</span>
                  </div>
                </td>
                <td class="p-4">
                  <span class="px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-300 border border-blue-500/20 text-[10px] font-semibold">PENDING_REVIEW</span>
                </td>
                <td class="p-4 text-right">
                  <button onclick="openMakerModal('req-89a1c-demo', 'Acme Heavy Industries Pvt Ltd', '+91 98765 43210')" class="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition shadow-sm">
                    Perform Verification
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Maker Verification Modal Container -->
    <div id="maker-modal" class="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm hidden items-center justify-center p-4"></div>
  `;
}

// --- MODAL: MAKER TRUSTED PHONE VERIFICATION ---
function openMakerModal(requestId, vendorName, trustedPhone) {
  const modal = document.getElementById('maker-modal');
  modal.classList.remove('hidden');
  modal.classList.add('flex');

  modal.innerHTML = `
    <div class="glass-card max-w-xl w-full p-6 rounded-2xl border border-slate-700 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-200">
      <div class="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h3 class="text-lg font-bold text-white flex items-center">
            <i class="fa-solid fa-phone-volume text-blue-400 mr-2"></i>
            Out-of-Band Phone Verification
          </h3>
          <p class="text-xs text-slate-400 mt-0.5 font-mono">Request: ${requestId}</p>
        </div>
        <button onclick="closeMakerModal()" class="text-slate-400 hover:text-white transition">
          <i class="fa-solid fa-xmark text-lg"></i>
        </button>
      </div>

      <!-- Mandatory Security Alert -->
      <div class="p-3.5 rounded-xl bg-blue-950/40 border border-blue-500/30 text-blue-200 text-xs flex items-start space-x-3">
        <i class="fa-solid fa-circle-info text-blue-400 mt-0.5"></i>
        <div>
          <span class="font-bold">PRD Section 12 Requirement:</span> You must place a voice call to the vendor's <b>pre-registered trusted phone number</b> (${trustedPhone}). Do NOT call numbers on incoming PDF/email!
        </div>
      </div>

      <form id="maker-verify-form" onsubmit="handleMakerVerifySubmit(event, '${requestId}')" class="space-y-4">
        
        <!-- Mandatory Checkbox Gate -->
        <div class="p-3 rounded-lg bg-slate-900 border border-slate-800">
          <label class="flex items-center space-x-3 cursor-pointer">
            <input type="checkbox" id="maker-phone-check" required class="h-4 w-4 rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-blue-500">
            <span class="text-xs font-semibold text-slate-200">I confirm that I called the trusted baseline phone number (${trustedPhone})</span>
          </label>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Vendor Representative Spoken To</label>
          <input type="text" id="maker-rep-name" required placeholder="e.g. Ramesh Kumar (Finance Controller)" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:border-blue-500 outline-none">
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Call Verification Transcript & Summary</label>
          <textarea id="maker-transcript" required rows="3" placeholder="Document verified details: Confirmation of bank change reason, invoice references, account confirmation..." class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:border-blue-500 outline-none"></textarea>
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Verification Proof Reference</label>
          <input type="text" id="maker-proof" required placeholder="e.g. OTP-TOKEN-88392 or CALL-SESSION-ID-991" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs font-mono focus:border-blue-500 outline-none">
        </div>

        <div class="flex items-center justify-end space-x-3 pt-3 border-t border-slate-800">
          <button type="button" onclick="closeMakerModal()" class="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition">Cancel</button>
          <button type="submit" class="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold transition shadow-md shadow-blue-600/30">
            Submit Maker Verification
          </button>
        </div>
      </form>
    </div>
  `;
}

function closeMakerModal() {
  const modal = document.getElementById('maker-modal');
  modal.classList.add('hidden');
  modal.classList.remove('flex');
}

async function handleMakerVerifySubmit(event, requestId) {
  event.preventDefault();

  const is_called_trusted_phone = document.getElementById('maker-phone-check').checked;
  const vendor_representative_name = document.getElementById('maker-rep-name').value.trim();
  const verification_transcript = document.getElementById('maker-transcript').value.trim();
  const verification_proof = document.getElementById('maker-proof').value.trim();

  try {
    const payload = {
      request_id: requestId,
      is_called_trusted_phone,
      vendor_representative_name,
      verification_transcript,
      verification_proof
    };

    const res = await apiCall('/api/v1/review/maker-verify', 'POST', payload);
    showToast('Maker verification submitted! Request transitioned to PENDING_VERIFICATION.', 'success');
    closeMakerModal();
    navigate('/checker');
  } catch (err) {
    // Handled by apiCall error interceptor
  }
}

// --- VIEW: CHECKER QUEUE (PENDING_VERIFICATION) ---
function renderCheckerQueue(container) {
  const isChecker = ['admin', 'checker', 'finance_manager'].includes(state.user.role);

  container.innerHTML = `
    <div class="space-y-6">
      <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 class="text-2xl font-bold text-white tracking-tight flex items-center">
            <i class="fa-solid fa-user-check text-emerald-400 mr-3"></i>
            Checker Dual-Control Approval Queue
          </h1>
          <p class="text-xs text-slate-400 mt-1">Independent Dual-Control with Step-Up MFA (Status: PENDING_VERIFICATION)</p>
        </div>

        <div class="flex items-center space-x-2">
          ${!isChecker ? '<span class="px-2.5 py-1 rounded bg-rose-500/20 text-rose-300 text-xs font-mono font-semibold border border-rose-500/30">READ-ONLY (MAKER ROLE)</span>' : ''}
          <button onclick="renderCheckerQueue(document.getElementById('app-view'))" class="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition">
            <i class="fa-solid fa-rotate text-xs"></i>
          </button>
        </div>
      </div>

      <!-- Queue Table -->
      <div class="glass-card rounded-xl border border-slate-800 overflow-hidden shadow-xl">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-900/90 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th class="p-4">Request ID / Vendor</th>
                <th class="p-4">Maker Verification Proof</th>
                <th class="p-4">Representative</th>
                <th class="p-4">Current Status</th>
                <th class="p-4 text-right">Checker Action</th>
              </tr>
            </thead>
            <tbody id="checker-queue-tbody" class="divide-y divide-slate-800/60 font-medium">
              <tr class="hover:bg-slate-900/40 transition">
                <td class="p-4">
                  <div class="font-mono text-slate-200 font-semibold">req-89a1c-demo</div>
                  <div class="text-slate-400 text-[11px] mt-0.5">Acme Heavy Industries Pvt Ltd</div>
                </td>
                <td class="p-4">
                  <span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 font-mono text-[10px]">OTP-TOKEN-88392</span>
                  <div class="text-[10px] text-slate-500 mt-0.5">Trusted phone called: TRUE</div>
                </td>
                <td class="p-4 text-slate-300">
                  Ramesh Kumar (Finance Controller)
                </td>
                <td class="p-4">
                  <span class="px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 text-[10px] font-semibold">PENDING_VERIFICATION</span>
                </td>
                <td class="p-4 text-right">
                  <button onclick="openCheckerModal('req-89a1c-demo', 'Acme Heavy Industries Pvt Ltd')" class="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition shadow-sm flex items-center space-x-1.5 ml-auto">
                    <i class="fa-solid fa-key text-[10px]"></i>
                    <span>Review with MFA</span>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- Checker Approval Modal Container -->
    <div id="checker-modal" class="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm hidden items-center justify-center p-4"></div>
  `;
}

// --- MODAL: CHECKER APPROVAL + STEP-UP MFA ---
function openCheckerModal(requestId, vendorName) {
  const modal = document.getElementById('checker-modal');
  modal.classList.remove('hidden');
  modal.classList.add('flex');

  modal.innerHTML = `
    <div class="glass-card max-w-xl w-full p-6 rounded-2xl border border-slate-700 shadow-2xl space-y-5 animate-in fade-in zoom-in-95 duration-200">
      <div class="flex items-center justify-between border-b border-slate-800 pb-4">
        <div>
          <h3 class="text-lg font-bold text-white flex items-center">
            <i class="fa-solid fa-user-shield text-emerald-400 mr-2"></i>
            Checker Final Authorization
          </h3>
          <p class="text-xs text-slate-400 mt-0.5 font-mono">Request: ${requestId}</p>
        </div>
        <button onclick="closeCheckerModal()" class="text-slate-400 hover:text-white transition">
          <i class="fa-solid fa-xmark text-lg"></i>
        </button>
      </div>

      <!-- 48-Hour Cooling Off Banner (PRD Sec 15) -->
      <div class="p-4 rounded-xl cooling-off-banner text-amber-200 text-xs flex items-start space-x-3">
        <i class="fa-solid fa-clock-rotate-left text-amber-400 text-base mt-0.5"></i>
        <div>
          <div class="font-bold text-amber-100 text-sm">48-Hour Cooling-Off Enforcement Active</div>
          <p class="text-[11px] text-amber-200/90 mt-0.5">Upon approval, changes will remain in cooling-off status. The bank details become active only after 48 hours.</p>
        </div>
      </div>

      <form id="checker-approve-form" onsubmit="handleCheckerApproveSubmit(event, '${requestId}')" class="space-y-4">
        
        <!-- Step-Up MFA Challenge Proof -->
        <div>
          <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Step-Up MFA Verification Code (AAL2 Proof)</label>
          <input type="text" id="checker-mfa-proof" required placeholder="Enter 6-digit TOTP / Hardware Key Proof" value="TOTP-MFA-SESSION-VALID" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-emerald-500/50 text-emerald-300 text-sm font-mono tracking-widest focus:border-emerald-400 outline-none">
        </div>

        <div>
          <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Checker Decision Notes</label>
          <textarea id="checker-notes" rows="2" placeholder="Document review rationale, cross-verification notes..." class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:border-emerald-500 outline-none"></textarea>
        </div>

        <div class="flex items-center justify-between pt-4 border-t border-slate-800">
          <button type="button" onclick="submitCheckerDecision('${requestId}', 'REJECT')" class="px-4 py-2.5 rounded-xl bg-rose-900/60 hover:bg-rose-800 text-rose-200 text-xs font-semibold transition border border-rose-700/50 flex items-center space-x-1.5">
            <i class="fa-solid fa-ban text-xs"></i>
            <span>Reject Request</span>
          </button>

          <div class="flex items-center space-x-2">
            <button type="button" onclick="closeCheckerModal()" class="px-4 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold transition">Cancel</button>
            <button type="button" onclick="submitCheckerDecision('${requestId}', 'APPROVE')" class="px-5 py-2.5 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-bold tracking-wide transition shadow-lg shadow-emerald-600/30 flex items-center space-x-2">
              <i class="fa-solid fa-check-double text-xs"></i>
              <span>Authorize & Approve</span>
            </button>
          </div>
        </div>
      </form>
    </div>
  `;
}

function closeCheckerModal() {
  const modal = document.getElementById('checker-modal');
  modal.classList.add('hidden');
  modal.classList.remove('flex');
}

async function submitCheckerDecision(requestId, decision) {
  const mfa_verification_proof = document.getElementById('checker-mfa-proof').value.trim();
  const checker_notes = document.getElementById('checker-notes').value.trim();

  if (!mfa_verification_proof) {
    showToast('Step-Up MFA verification proof is mandatory.', 'warning');
    return;
  }

  try {
    const payload = {
      request_id: requestId,
      mfa_verification_proof,
      approval_decision: decision,
      checker_notes
    };

    const res = await apiCall('/api/v1/review/checker-approve', 'POST', payload);

    if (decision === 'APPROVE') {
      showToast(`Approved! 48-Hour Cooling-Off initiated until: ${res.effective_date || '48h from now'}`, 'success');
    } else {
      showToast('Request has been rejected and archived.', 'info');
    }

    closeCheckerModal();
    navigate('/checker');
  } catch (err) {
    // Error handled by interceptor
  }
}

// --- VIEW: INTAKE SIMULATION & RISK ENGINE ---
function renderIntakeForm(container) {
  container.innerHTML = `
    <div class="max-w-2xl mx-auto space-y-6">
      <div>
        <h1 class="text-2xl font-bold text-white tracking-tight flex items-center">
          <i class="fa-solid fa-file-invoice text-indigo-400 mr-3"></i>
          Bank-Change Request Intake
        </h1>
        <p class="text-xs text-slate-400 mt-1">Submit PDF / IMAP request with deterministic risk evaluation (Step 3 & 5)</p>
      </div>

      <div class="glass-card p-6 rounded-2xl border border-slate-800 shadow-xl space-y-5">
        <form onsubmit="handleIntakeSubmit(event)" class="space-y-4">
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Target Vendor UUID</label>
              <input type="text" id="intake-vendor-id" required value="c3eebc99-9c0b-4ef8-bb6d-6bb9bd380c33" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs font-mono focus:border-indigo-500 outline-none">
            </div>

            <div>
              <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Request Source</label>
              <select id="intake-source" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs font-medium focus:border-indigo-500 outline-none">
                <option value="PDF_UPLOAD">PDF Upload (SHA-256 Idempotency)</option>
                <option value="IMAP_FETCH">IMAP Email Fetch (Message-ID Idempotency)</option>
              </select>
            </div>
          </div>

          <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Account Holder</label>
              <input type="text" id="intake-holder" value="Acme Heavy Industries" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs focus:border-indigo-500 outline-none">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">New Bank Account</label>
              <input type="text" id="intake-account" value="98765432109876" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs font-mono focus:border-indigo-500 outline-none">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">New IFSC Code</label>
              <input type="text" id="intake-ifsc" value="HDFC0001234" class="w-full px-3 py-2 rounded-lg bg-slate-900 border border-slate-700 text-slate-100 text-xs font-mono focus:border-indigo-500 outline-none">
            </div>
          </div>

          <!-- Risk Signals to Test -->
          <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2">
            <span class="text-xs font-semibold text-slate-300 uppercase tracking-wider block mb-2">Simulate Risk Engine Signals</span>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <label class="flex items-center space-x-2 text-slate-300">
                <input type="checkbox" id="sig-domain" checked class="rounded bg-slate-800 border-slate-700 text-indigo-600">
                <span>Domain Mismatch (+40 pts)</span>
              </label>
              <label class="flex items-center space-x-2 text-slate-300">
                <input type="checkbox" id="sig-bank" checked class="rounded bg-slate-800 border-slate-700 text-indigo-600">
                <span>Bank Account Changed (+25 pts)</span>
              </label>
              <label class="flex items-center space-x-2 text-slate-300">
                <input type="checkbox" id="sig-velocity" class="rounded bg-slate-800 border-slate-700 text-indigo-600">
                <span>Velocity Anomaly (+50 pts)</span>
              </label>
              <label class="flex items-center space-x-2 text-slate-300">
                <input type="checkbox" id="sig-spoof" class="rounded bg-slate-800 border-slate-700 text-red-600">
                <span class="text-red-400 font-semibold">SPF/DKIM Spoof Block (100 pts)</span>
              </label>
            </div>
          </div>

          <button type="submit" class="w-full py-3 rounded-xl bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold tracking-wide shadow-lg shadow-indigo-600/30 transition">
            Process Intake & Calculate Risk
          </button>
        </form>
      </div>
    </div>
  `;
}

async function handleIntakeSubmit(event) {
  event.preventDefault();
  const vendor_id = document.getElementById('intake-vendor-id').value.trim();
  const request_source = document.getElementById('intake-source').value;
  const new_account_holder_name = document.getElementById('intake-holder').value.trim();
  const new_account_number = document.getElementById('intake-account').value.trim();
  const new_ifsc_code = document.getElementById('intake-ifsc').value.trim();

  // Test Risk Calculation
  const riskPayload = {
    company_id: state.user.company_id,
    vendor_id: vendor_id,
    is_domain_mismatch: document.getElementById('sig-domain').checked,
    is_bank_account_changed: document.getElementById('sig-bank').checked,
    is_velocity_anomaly: document.getElementById('sig-velocity').checked,
    is_spf_dkim_dmarc_failed: document.getElementById('sig-spoof').checked
  };

  try {
    const riskRes = await apiCall('/api/v1/risk-engine/calculate', 'POST', riskPayload);
    showToast(`Risk Score: ${riskRes.score} (${riskRes.level}) - ${riskRes.is_blocked ? 'BLOCKED' : 'PROCESSED'}`, riskRes.is_blocked ? 'critical' : 'success');

    // Submit Ingestion
    const intakePayload = {
      vendor_id,
      request_source,
      file_content_base64: request_source === 'PDF_UPLOAD' ? btoa(`sample_pdf_payload_${Date.now()}`) : null,
      imap_message_id: request_source === 'IMAP_FETCH' ? `msg_<${Date.now()}@domain.com>` : null,
      new_account_holder_name,
      new_account_number,
      new_ifsc_code
    };

    const intakeRes = await apiCall('/api/v1/ingestion/intake', 'POST', intakePayload);
    showToast(`Request intaked! ID: ${intakeRes.request_id}`, 'success');
    navigate('/maker');
  } catch (err) {
    // Handled by interceptor
  }
}

// --- VIEW: AUDIT LOGS TRAIL ---
function renderAuditLogs(container) {
  container.innerHTML = `
    <div class="space-y-6">
      <div>
        <h1 class="text-2xl font-bold text-white tracking-tight flex items-center">
          <i class="fa-solid fa-fingerprint text-amber-400 mr-3"></i>
          Immutable Forensic Audit Trail
        </h1>
        <p class="text-xs text-slate-400 mt-1">Read-only scoped audit information (SOC 2 Type II Compliance)</p>
      </div>

      <div class="glass-card rounded-xl border border-slate-800 overflow-hidden shadow-xl">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-900/90 text-slate-400 uppercase font-mono text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th class="p-4">Timestamp (UTC)</th>
                <th class="p-4">Action</th>
                <th class="p-4">Actor ID</th>
                <th class="p-4">Record ID</th>
                <th class="p-4">Details</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-800/60 font-mono text-[11px]">
              <tr class="hover:bg-slate-900/40 transition">
                <td class="p-4 text-slate-400">${new Date().toISOString()}</td>
                <td class="p-4"><span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-300 font-bold border border-emerald-500/20">CHECKER_APPROVED</span></td>
                <td class="p-4 text-slate-300 truncate max-w-[120px]">${state.user ? state.user.user_id : 'system'}</td>
                <td class="p-4 text-slate-300 truncate max-w-[120px]">req-89a1c-demo</td>
                <td class="p-4 text-slate-400 font-sans text-xs">Cooling-off 48h active &bull; MFA verified</td>
              </tr>
              <tr class="hover:bg-slate-900/40 transition">
                <td class="p-4 text-slate-400">${new Date(Date.now() - 3600000).toISOString()}</td>
                <td class="p-4"><span class="px-2 py-0.5 rounded bg-blue-500/10 text-blue-300 font-bold border border-blue-500/20">MAKER_VERIFICATION_COMPLETED</span></td>
                <td class="p-4 text-slate-300 truncate max-w-[120px]">b1eebc99-9c0b-4ef8-bb6d-6bb9bd380b22</td>
                <td class="p-4 text-slate-300 truncate max-w-[120px]">req-89a1c-demo</td>
                <td class="p-4 text-slate-400 font-sans text-xs">Trusted phone call confirmed &bull; Transcript recorded</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

// --- VIEW: SETUP MFA ---
function renderSetupMFA(container) {
  container.innerHTML = `
    <div class="max-w-md mx-auto py-8">
      <div class="glass-card p-6 rounded-2xl border border-slate-800 shadow-2xl space-y-6">
        <div class="text-center">
          <div class="inline-flex h-12 w-12 rounded-xl bg-gradient-to-tr from-indigo-600 to-purple-600 items-center justify-center shadow-lg mb-3">
            <i class="fa-solid fa-key text-xl text-white"></i>
          </div>
          <h2 class="text-xl font-bold text-white">Step-Up MFA Enrollment</h2>
          <p class="text-xs text-slate-400 mt-1">Required for Checker role approval actions (AAL2)</p>
        </div>

        <div class="p-4 rounded-xl bg-slate-900 border border-slate-800 text-center space-y-3">
          <div class="h-32 w-32 mx-auto bg-white p-2 rounded-lg flex items-center justify-center">
            <i class="fa-solid fa-qrcode text-6xl text-slate-900"></i>
          </div>
          <span class="text-xs font-mono text-slate-400 block">Secret Key: VFG-AAL2-SECURE-KEY-8839</span>
        </div>

        <form onsubmit="handleMfaEnrollSubmit(event)" class="space-y-4">
          <div>
            <label class="block text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1">Enter 6-Digit Authenticator Code</label>
            <input type="text" id="mfa-verify-code" required placeholder="123456" maxlength="6" class="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-indigo-500 text-indigo-300 text-center text-lg font-mono tracking-widest focus:border-indigo-400 outline-none">
          </div>

          <button type="submit" class="w-full py-3 rounded-xl bg-gradient-to-r from-indigo-600 to-purple-600 text-white text-xs font-bold tracking-wide shadow-lg shadow-indigo-600/30 transition">
            Verify & Activate AAL2
          </button>
        </form>
      </div>
    </div>
  `;
}

function handleMfaEnrollSubmit(event) {
  event.preventDefault();
  if (state.user) {
    state.user.aal = 'aal2';
    saveSession(state.user);
    showToast('MFA enrolled successfully! Your session is now AAL2 verified.', 'success');
    navigate('/checker');
  }
}

// Bootstrap
document.addEventListener('DOMContentLoaded', () => {
  initSession();
  renderView();
});
