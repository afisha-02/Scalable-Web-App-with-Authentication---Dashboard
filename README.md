<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>All-in-One: Auth + Dashboard + In-Browser API</title>
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <style>
    :root {
      --bg:#f6f8fa; --card:#fff; --accent:#8195bf; --muted:#6b7280;
      --danger:#2d0202;
    }
    *{box-sizing:border-box}
    body{font-family:Inter,system-ui,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);margin:0;color:#111}
    .wrap{max-width:980px;margin:28px auto;padding:18px}
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
    h1{font-size:20px;margin:0}
    .card{background:var(--card);padding:16px;border-radius:12px;box-shadow:0 6px 20px rgba(16,24,40,0.06);margin-bottom:12px}
    .row{display:flex;gap:12px;align-items:center}
    .col{display:flex;flex-direction:column;gap:8px}
    input,select,textarea,button{padding:10px;border:1px solid #e6e9ee;border-radius:8px;font-size:14px}
    input:focus,select:focus,button:focus{outline:2px solid rgba(37,99,235,0.12)}
    button{cursor:pointer;background:transparent}
    .btn-primary{background:var(--accent);color:#340202;border:none}
    .btn-danger{background:var(--danger);color:#1f0000;border:none}
    .muted{color:var(--muted)}
    label{font-size:13px;color:#374151}
    #auth-area{max-width:420px;margin:0 auto}
    .hidden{display:none}
    #task-list{list-style:none;padding:0;margin:0;display:flex;flex-direction:column;gap:8px}
    .task-item{display:flex;justify-content:space-between;align-items:center;padding:10px;border-radius:8px;border:1px solid #eee}
    .controls{display:flex;gap:8px;flex-wrap:wrap}
    .footer{margin-top:12px;font-size:13px;color:var(--muted)}
    @media (max-width:700px){header{flex-direction:column;align-items:flex-start;gap:8px}}
  </style>
</head>
<body>
  <div class="wrap">
    <header>
      <h1>All-in-One Demo — Auth + Dashboard</h1>
      <nav class="row">
        <button id="btn-show-login" class="btn-primary">Login / Register</button>
        <button id="btn-logout" class="hidden">Logout</button>
      </nav>
    </header>

    <!-- AUTH -->
    <section id="auth-area" class="card">
      <h2 id="auth-title">Login</h2>
      <form id="auth-form" class="col" autocomplete="off">
        <label for="name-input" id="label-name" class="hidden">Name</label>
        <input type="text" id="name-input" placeholder="Full name (for register)" class="hidden" />
        <label for="email-input">Email</label>
        <input id="email-input" type="email" placeholder="you@example.com" required />
        <label for="password-input">Password</label>
        <input id="password-input" type="password" placeholder="min 6 chars" required minlength="6" />
        <div class="row" style="margin-top:6px">
          <button id="auth-submit" type="submit" class="btn-primary">Submit</button>
          <button id="toggle-auth" type="button">Switch to Register</button>
        </div>
        <p id="auth-msg" class="muted"></p>
      </form>
    </section>

    <!-- DASHBOARD -->
    <section id="dashboard" class="card hidden">
      <div class="row" style="justify-content:space-between;align-items:center">
        <div>
          <strong id="profile-name">Name:</strong><div class="muted" id="profile-email">Email:</div>
        </div>
        <div>
          <button id="btn-refresh">Refresh</button>
        </div>
      </div>

      <hr style="margin:12px 0" />

      <div class="col">
        <div class="controls">
          <input id="task-search" placeholder="Search tasks..." />
          <select id="task-filter">
            <option value="all">All</option>
            <option value="open">Open</option>
            <option value="done">Done</option>
          </select>
        </div>

        <form id="task-form" class="row">
          <input id="task-title" placeholder="New task title" required />
          <button class="btn-primary" type="submit">Add</button>
        </form>

        <ul id="task-list"></ul>
      </div>
    </section>

    <p class="footer">This single-file demo simulates a backend using Web Crypto + localStorage. See comments in JS for API docs & how to replace with a real backend.</p>
  </div>

  <script>
  /***************************************************************************
   * All-in-One Demo: in-browser "server" + client UI
   *
   * - The in-browser server intercepts fetch requests to /api/* and replies.
   * - Passwords are hashed with SHA-256 (Web Crypto) for demo only. Use bcrypt
   *   on a real backend.
   * - JWTs are HMAC-SHA256 signed (Web Crypto). Use server-side signing & secret.
   * - Storage: localStorage (persist across reload). Replace with DB in real app.
   *
   * API endpoints implemented (mimic real REST):
   * POST /api/auth/register  { email, password, name } -> { token }
   * POST /api/auth/login     { email, password } -> { token }
   * GET  /api/profile        (auth) -> { id, email, name }
   * PUT  /api/profile        (auth, body { name }) -> { message }
   * GET  /api/tasks          (auth) -> [ tasks ]
   * POST /api/tasks          (auth, body { title }) -> task
   * PUT  /api/tasks/:id      (auth, body taskFields) -> updatedTask
   * DELETE /api/tasks/:id    (auth) -> { ok:true }
   *
   * How client calls:
   * fetch('/api/auth/login', { method:'POST', body:JSON.stringify({...}) })
   *
   * NOTE: This is a mock server. For production:
   * - Replace with a real server (Node/Express/FastAPI), use HTTPS, bcrypt,
   *   real DB (Postgres/Mongo), and store secrets securely (Vault/Secrets Manager).
   ***************************************************************************/

  // ---------- Utilities ----------
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  function uuid() {
    // simple uuid v4
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => {
      const r = Math.random()*16|0, v = c==='x'? r : (r&0x3|0x8);
      return v.toString(16);
    });
  }

  function nowSeconds(){ return Math.floor(Date.now()/1000); }

  function base64UrlEncode(buf) {
    // buf: Uint8Array or ArrayBuffer
    const bytes = new Uint8Array(buf);
    let str = '';
    for (let i=0;i<bytes.length;i++) str += String.fromCharCode(bytes[i]);
    return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  }

  function base64UrlDecodeToUint8(str) {
    // returns Uint8Array
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    const bin = atob(str);
    const arr = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  async function sha256(message) {
    // returns hex string of SHA256
    const m = typeof message === 'string' ? textEncoder.encode(message) : message;
    const digest = await crypto.subtle.digest('SHA-256', m);
    // return hex
    const h = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2,'0')).join('');
    return h;
  }

  async function importHmacKey(secret) {
    return crypto.subtle.importKey('raw', textEncoder.encode(secret), {name:'HMAC', hash:'SHA-256'}, false, ['sign','verify']);
  }

  async function hmacSha256Sign(secret, dataStr) {
    const key = await importHmacKey(secret);
    const sig = await crypto.subtle.sign('HMAC', key, textEncoder.encode(dataStr));
    return base64UrlEncode(sig);
  }

  async function hmacSha256Verify(secret, dataStr, signature) {
    try {
      const key = await importHmacKey(secret);
      const sigBuf = base64UrlDecodeToUint8(signature);
      const ok = await crypto.subtle.verify('HMAC', key, sigBuf, textEncoder.encode(dataStr));
      return ok;
    } catch(e) { return false; }
  }

  // ---------- Simple persistent storage (localStorage) ----------
  const STORAGE_KEY_USERS = 'demo_users_v1';
  const STORAGE_KEY_TASKS = 'demo_tasks_v1';

  function loadUsers() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY_USERS) || '[]'); }
    catch(e){ return []; }
  }
  function saveUsers(users) { localStorage.setItem(STORAGE_KEY_USERS, JSON.stringify(users)); }

  function loadTasks() {
    try { return JSON.parse(localStorage.getItem(STORAGE_KEY_TASKS) || '[]'); }
    catch(e){ return []; }
  }
  function saveTasks(tasks) { localStorage.setItem(STORAGE_KEY_TASKS, JSON.stringify(tasks)); }

  // ---------- Mock Server Implementation ----------
  const MockServer = (function(){
    const JWT_SECRET = 'demo_secret_change_in_prod'; // demo only
    const TOKEN_EXPIRY_SECONDS = 7 * 24 * 3600; // 7 days

    async function signJwt(payloadObj) {
      const header = { alg:'HS256', typ:'JWT' };
      const payload = { ...payloadObj };
      const headerB = base64UrlEncode(textEncoder.encode(JSON.stringify(header)));
      const payloadB = base64UrlEncode(textEncoder.encode(JSON.stringify(payload)));
      const data = `${headerB}.${payloadB}`;
      const sig = await hmacSha256Sign(JWT_SECRET, data);
      return `${data}.${sig}`;
    }

    async function verifyJwt(token) {
      try {
        const parts = token.split('.');
        if (parts.length !== 3) return null;
        const [headerB, payloadB, sig] = parts;
        const data = `${headerB}.${payloadB}`;
        const ok = await hmacSha256Verify(JWT_SECRET, data, sig);
        if (!ok) return null;
        const payloadJson = JSON.parse(textDecoder.decode(base64UrlDecodeToUint8(payloadB)));
        if (payloadJson.exp && nowSeconds() > payloadJson.exp) return null;
        return payloadJson;
      } catch (e) { return null; }
    }

    async function hashPassword(password) {
      // Demo-only: use SHA-256 to hash password + salt derived from email ideally.
      // In production use bcrypt/scrypt/argon2 on the server.
      return await sha256(password);
    }

    // small simulated delay to mimic network
    function delay(ms=200){ return new Promise(r=>setTimeout(r,ms)); }

    // routes
    return {
      async register({ email, password, name }) {
        await delay(200);
        if (!email || !password) return { status:400, body:{ message:'Missing fields' } };
        const users = loadUsers();
        if (users.find(u => u.email.toLowerCase() === email.toLowerCase())) {
          return { status:400, body:{ message:'Email already registered' } };
        }
        const pwdHash = await hashPassword(password);
        const id = uuid();
        const user = { id, email, name: name||'', passwordHash: pwdHash, createdAt: Date.now() };
        users.push(user);
        saveUsers(users);
        const token = await signJwt({ id:user.id, email:user.email, exp: nowSeconds() + TOKEN_EXPIRY_SECONDS });
        return { status:200, body:{ token } };
      },

      async login({ email, password }) {
        await delay(150);
        if (!email || !password) return { status:400, body:{ message:'Missing fields' } };
        const users = loadUsers();
        const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
        if (!user) return { status:400, body:{ message:'Invalid credentials' } };
        const pwdHash = await hashPassword(password);
        if (pwdHash !== user.passwordHash) return { status:400, body:{ message:'Invalid credentials' } };
        const token = await signJwt({ id:user.id, email:user.email, exp: nowSeconds() + TOKEN_EXPIRY_SECONDS });
        return { status:200, body:{ token } };
      },

      async getProfile(token) {
        await delay(80);
        const payload = await verifyJwt(token);
        if (!payload) return { status:401, body:{ message:'Unauthorized' } };
        const users = loadUsers();
        const user = users.find(u => u.id === payload.id);
        if (!user) return { status:404, body:{ message:'User not found' } };
        const safe = { id:user.id, email:user.email, name:user.name, createdAt:user.createdAt };
        return { status:200, body: safe };
      },

      async updateProfile(token, { name }) {
        await delay(80);
        const payload = await verifyJwt(token);
        if (!payload) return { status:401, body:{ message:'Unauthorized' } };
        const users = loadUsers();
        const user = users.find(u => u.id === payload.id);
        if (!user) return { status:404, body:{ message:'User not found' } };
        user.name = typeof name === 'string' ? name : user.name;
        saveUsers(users);
        return { status:200, body:{ message:'ok' } };
      },

      async listTasks(token) {
        await delay(80);
        const payload = await verifyJwt(token);
        if (!payload) return { status:401, body:{ message:'Unauthorized' } };
        const tasks = loadTasks().filter(t => t.ownerId === payload.id).sort((a,b)=>b.createdAt-a.createdAt);
        return { status:200, body: tasks };
      },

      async createTask(token, { title }) {
        await delay(80);
        if (!title) return { status:400, body:{ message:'Missing title' } };
        const payload = await verifyJwt(token);
        if (!payload) return { status:401, body:{ message:'Unauthorized' } };
        const tasks = loadTasks();
        const task = { _id: uuid(), title, done:false, ownerId: payload.id, createdAt: Date.now() };
        tasks.push(task);
        saveTasks(tasks);
        return { status:200, body:task };
      },

      async updateTask(token, id, data) {
        await delay(80);
        const payload = await verifyJwt(token);
        if (!payload) return { status:401, body:{ message:'Unauthorized' } };
        const tasks = loadTasks();
        const t = tasks.find(x => x._id === id && x.ownerId === payload.id);
        if (!t) return { status:404, body:{ message:'Not found' } };
        t.title = typeof data.title === 'string' ? data.title : t.title;
        if (typeof data.done === 'boolean') t.done = data.done;
        saveTasks(tasks);
        return { status:200, body:t };
      },

      async deleteTask(token, id) {
        await delay(80);
        const payload = await verifyJwt(token);
        if (!payload) return { status:401, body:{ message:'Unauthorized' } };
        let tasks = loadTasks();
        const idx = tasks.findIndex(x => x._id === id && x.ownerId === payload.id);
        if (idx === -1) return { status:404, body:{ message:'Not found' } };
        tasks.splice(idx,1);
        saveTasks(tasks);
        return { status:200, body:{ ok:true } };
      }
    };
  })();

  // ---------- Intercept fetch to /api/* and route to MockServer ----------
  (function patchFetch(){
    const originalFetch = window.fetch.bind(window);
    window.fetch = async function(input, init = {}) {
      try {
        const url = (typeof input === 'string')? input : (input.url || '');
        const u = new URL(url, location.origin);
        if (u.pathname.startsWith('/api/')) {
          // parse request and delegate to MockServer
          const path = u.pathname;
          const method = (init.method || 'GET').toUpperCase();
          let body = null;
          if (init.body) {
            try { body = JSON.parse(init.body); } catch(e){ body = null; }
          } else if (input instanceof Request && input.bodyUsed) {
            // ignore
          }
          const authHeader = (init.headers && init.headers['Authorization']) ||
                             (init.headers && init.headers.get && init.headers.get('Authorization')) ||
                             (input instanceof Request && input.headers.get('Authorization')) || null;
          const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;

          // route mapping
          if (path === '/api/auth/register' && method === 'POST') {
            const res = await MockServer.register(body || {});
            return new Response(JSON.stringify(res.body), { status: res.status, headers:{'Content-Type':'application/json'} });
          }
          if (path === '/api/auth/login' && method === 'POST') {
            const res = await MockServer.login(body || {});
            return new Response(JSON.stringify(res.body), { status: res.status, headers:{'Content-Type':'application/json'} });
          }
          if (path === '/api/profile' && method === 'GET') {
            const res = await MockServer.getProfile(token);
            return new Response(JSON.stringify(res.body), { status: res.status, headers:{'Content-Type':'application/json'} });
          }
          if (path === '/api/profile' && method === 'PUT') {
            const res = await MockServer.updateProfile(token, body || {});
            return new Response(JSON.stringify(res.body), { status: res.status, headers:{'Content-Type':'application/json'} });
          }
          if (path === '/api/tasks' && method === 'GET') {
            const res = await MockServer.listTasks(token);
            return new Response(JSON.stringify(res.body), { status: res.status, headers:{'Content-Type':'application/json'} });
          }
          if (path === '/api/tasks' && method === 'POST') {
            const res = await MockServer.createTask(token, body || {});
            return new Response(JSON.stringify(res.body), { status: res.status, headers:{'Content-Type':'application/json'} });
          }
          // /api/tasks/:id
          const match = path.match(/^\/api\/tasks\/([^\/]+)$/);
          if (match) {
            const id = match[1];
            if (method === 'PUT') {
              const res = await MockServer.updateTask(token, id, body || {});
              return new Response(JSON.stringify(res.body), { status: res.status, headers:{'Content-Type':'application/json'} });
            }
            if (method === 'DELETE') {
              const res = await MockServer.deleteTask(token, id);
              return new Response(JSON.stringify(res.body), { status: res.status, headers:{'Content-Type':'application/json'} });
            }
          }

          // unknown api route
          return new Response(JSON.stringify({ message:'Not found' }), { status:404, headers:{'Content-Type':'application/json'} });
        } else {
          return originalFetch(input, init);
        }
      } catch (err) {
        return new Response(JSON.stringify({ message: 'Server error', error: err.message }), { status:500, headers:{'Content-Type':'application/json'} });
      }
    };
  })();

  // ---------- Client-side app that uses fetch('/api/...') ----------
  (function clientApp(){
    const qs = sel => document.querySelector(sel);
    const authForm = qs('#auth-form');
    const authTitle = qs('#auth-title');
    const toggleAuth = qs('#toggle-auth');
    const labelName = qs('#label-name');
    const nameInput = qs('#name-input');
    const emailInput = qs('#email-input');
    const passInput = qs('#password-input');
    const authMsg = qs('#auth-msg');
    const btnShowLogin = qs('#btn-show-login');
    const btnLogout = qs('#btn-logout');
    const dashboard = qs('#dashboard');
    const profileName = qs('#profile-name');
    const profileEmail = qs('#profile-email');
    const btnRefresh = qs('#btn-refresh');

    const taskForm = qs('#task-form');
    const taskTitle = qs('#task-title');
    const taskListEl = qs('#task-list');
    const taskSearch = qs('#task-search');
    const taskFilter = qs('#task-filter');

    let isRegister = false;

    function showMsg(msg, isError=false) {
      authMsg.textContent = msg;
      authMsg.style.color = isError ? 'var(--danger)' : 'var(--muted)';
    }

    function getToken(){ return localStorage.getItem('demo_token'); }
    function setToken(t){ localStorage.setItem('demo_token', t); }
    function clearToken(){ localStorage.removeItem('demo_token'); }

    async function api(path, opts = {}) {
      const headers = opts.headers || {};
      const token = getToken();
      if (token) headers['Authorization'] = 'Bearer ' + token;
      if (!headers['Content-Type'] && opts.body && !(opts.body instanceof FormData)) headers['Content-Type'] = 'application/json';
      const res = await fetch(path, { ...opts, headers });
      const text = await res.text();
      let body = null;
      try { body = text ? JSON.parse(text) : null; } catch(e) { body = text; }
      if (!res.ok) {
        const msg = (body && body.message) ? body.message : ('HTTP ' + res.status);
        throw Object.assign(new Error(msg), { status: res.status, body });
      }
      return body;
    }

    async function loginFlow(email, password) {
      const body = await api('/api/auth/login', { method:'POST', body: JSON.stringify({ email, password }) });
      setToken(body.token);
      return body.token;
    }

    async function registerFlow(name, email, password) {
      const body = await api('/api/auth/register', { method:'POST', body: JSON.stringify({ name, email, password }) });
      setToken(body.token);
      return body.token;
    }

    function showAuth() {
      qs('#auth-area').classList.remove('hidden');
      dashboard.classList.add('hidden');
      btnLogout.classList.add('hidden');
      btnShowLogin.classList.remove('hidden');
    }

    function showDashboardUI() {
      qs('#auth-area').classList.add('hidden');
      dashboard.classList.remove('hidden');
      btnLogout.classList.remove('hidden');
      btnShowLogin.classList.add('hidden');
    }

    // auth toggle
    toggleAuth.addEventListener('click', ()=>{
      isRegister = !isRegister;
      if (isRegister) {
        authTitle.textContent = 'Register';
        toggleAuth.textContent = 'Switch to Login';
        labelName.classList.remove('hidden'); nameInput.classList.remove('hidden');
      } else {
        authTitle.textContent = 'Login';
        toggleAuth.textContent = 'Switch to Register';
        labelName.classList.add('hidden'); nameInput.classList.add('hidden');
      }
      showMsg('');
    });

    // form submit
    authForm.addEventListener('submit', async (e)=>{
      e.preventDefault();
      const email = emailInput.value.trim();
      const password = passInput.value;
      const name = nameInput.value.trim();
      if (!email || password.length < 6) { showMsg('Email + password(>=6) required', true); return; }
      try {
        if (isRegister) {
          await registerFlow(name,email,password);
          showMsg('Registered & logged in ✓');
        } else {
          await loginFlow(email,password);
          showMsg('Logged in ✓');
        }
        await loadProfileAndTasks();
      } catch (err) {
        showMsg(err.message || 'Auth failed', true);
      }
    });

    // show login button toggles UI
    btnShowLogin.addEventListener('click', ()=>{ showAuth(); });

    // logout
    btnLogout.addEventListener('click', ()=>{
      clearToken();
      showAuth();
      showMsg('Logged out');
    });

    // profile + tasks fetching
    async function loadProfileAndTasks(){
      try {
        const profile = await api('/api/profile', { method:'GET' });
        profileName.textContent = profile.name ? profile.name : 'Name: —';
        profileEmail.textContent = 'Email: ' + (profile.email || '—');
        showDashboardUI();
        await loadTasks();
      } catch (err) {
        showMsg('Session expired or error: ' + err.message, true);
        clearToken();
        showAuth();
      }
    }

    // tasks
    async function loadTasks() {
      try {
        const tasks = await api('/api/tasks', { method:'GET' });
        window.__tasksCache = tasks;
        renderTasks(tasks);
      } catch (err) {
        console.error(err);
      }
    }

    function renderTasks(tasks) {
      const search = (taskSearch.value || '').toLowerCase();
      const filter = taskFilter.value;
      const list = (tasks || window.__tasksCache || []).filter(t=>{
        if (filter === 'done') return !!t.done;
        if (filter === 'open') return !t.done;
        return true;
      }).filter(t => t.title.toLowerCase().includes(search));
      taskListEl.innerHTML = '';
      if (list.length === 0) {
        taskListEl.innerHTML = '<li class="muted">No tasks</li>';
        return;
      }
      for (const t of list) {
        const li = document.createElement('li'); li.className = 'task-item';
        const left = document.createElement('div'); left.textContent = t.title + (t.done? ' (done)':'');
        const right = document.createElement('div'); right.style.display='flex'; right.style.gap='8px';
        const btnToggle = document.createElement('button'); btnToggle.textContent = t.done? 'Reopen':'Done';
        btnToggle.addEventListener('click', async ()=> {
          try {
            await api('/api/tasks/' + t._id, { method:'PUT', body: JSON.stringify({ ...t, done: !t.done }) });
            await loadTasks();
          } catch (err) { console.error(err); }
        });
        const btnEdit = document.createElement('button'); btnEdit.textContent = 'Edit';
        btnEdit.addEventListener('click', async ()=>{
          const nt = prompt('Edit title', t.title);
          if (nt && nt.trim()) {
            try { await api('/api/tasks/' + t._id, { method:'PUT', body: JSON.stringify({ ...t, title: nt.trim() }) }); await loadTasks(); }
            catch(e){ console.error(e) }
          }
        });
        const btnDel = document.createElement('button'); btnDel.textContent = 'Delete';
        btnDel.addEventListener('click', async ()=>{
          if (!confirm('Delete?')) return;
          try { await api('/api/tasks/' + t._id, { method:'DELETE' }); await loadTasks(); } catch(e){ console.error(e) }
        });
        right.appendChild(btnToggle); right.appendChild(btnEdit); right.appendChild(btnDel);
        li.appendChild(left); li.appendChild(right);
        taskListEl.appendChild(li);
      }
    }

    taskForm.addEventListener('submit', async (e)=>{
      e.preventDefault();
      const title = taskTitle.value.trim();
      if (!title) return;
      try {
        await api('/api/tasks', { method:'POST', body: JSON.stringify({ title }) });
        taskTitle.value = '';
        await loadTasks();
      } catch (err) { console.error(err); }
    });

    taskSearch.addEventListener('input', ()=> renderTasks(window.__tasksCache || []));
    taskFilter.addEventListener('change', ()=> renderTasks(window.__tasksCache || []));

    btnRefresh.addEventListener('click', ()=> loadProfileAndTasks() );

    // On load: if token exists, try load dashboard
    (async function init(){
      const token = getToken();
      if (token) {
        try { await loadProfileAndTasks(); } catch(e){ console.warn('auto-load failed',e); showAuth(); }
      } else {
        showAuth();
      }
    })();

  })();

  // ---------- End of main script ----------
  </script>
</body>
</html>
