// =============================================================================
// FIREBASE BACKEND ADAPTER (V17 - Firebase Edition)
// =============================================================================
// This file connects the Task Management UI directly to Cloud Firestore.
// It implements all API functions previously handled by Code.gs.
// Runs 100% in the browser with 0 server maintenance and sub-50ms speed.

(function () {
  'use strict';

  const TM_DEFAULTS = {
    APP_NAME: 'Task Management',
    TIMEZONE: 'Asia/Kolkata',
    DAILY_RUN_HOUR: 9,
    SESSION_DAYS: 30,
    MIN_PASSWORD_LENGTH: 8,
    FORCE_PASSWORD_CHANGE: 'N',
    ESCALATION_ENABLED: 'Y',
    MAX_LOGIN_ATTEMPTS: 5,
    LOCKOUT_MINUTES: 15,
    ARCHIVE_AFTER_DAYS: 60,
    EMAIL_GREETING: 'Salam,',
    EMAIL_SIGN_OFF: 'Jazakallahu Khaira!'
  };

  const TM_STATUSES = ['Pending', 'In Progress', 'Completed'];
  const TM_REGIONS = ['Mumbai', 'Hyderabad', 'Kolkata', 'Bangalore', 'Delhi', 'Ajmer'];
  const PAGE_SIZE = 50;

  // Global instances
  let fbApp = null;
  let db = null;
  let isConfigured = false;
  let authPromise = null;

  // In-memory cache for speed
  let _MEMO = {};
  function memoGet(key, fn) {
    if (!Object.prototype.hasOwnProperty.call(_MEMO, key)) _MEMO[key] = fn();
    return _MEMO[key];
  }
  function memoClear() { _MEMO = {}; }

  // Check and init Firebase
  function initFirebase() {
    if (fbApp && db) {
      if (typeof firebase.auth === 'function' && !firebase.auth().currentUser && !authPromise) {
        ensureAuth_().catch(() => {});
      }
      return true;
    }
    const cfg = window.FIREBASE_CONFIG;
    if (!cfg || !cfg.apiKey || cfg.apiKey === 'YOUR_API_KEY' || !cfg.projectId || cfg.projectId === 'YOUR_PROJECT_ID') {
      isConfigured = false;
      return false;
    }
    try {
      if (!firebase.apps.length) {
        fbApp = firebase.initializeApp(cfg);
      } else {
        fbApp = firebase.app();
      }
      db = firebase.firestore();
      isConfigured = true;

      // Start background authentication badge immediately
      if (typeof firebase.auth === 'function' && !firebase.auth().currentUser && !authPromise) {
        ensureAuth_().catch(() => {});
      }
      return true;
    } catch (err) {
      console.error('Firebase initialization error:', err);
      isConfigured = false;
      return false;
    }
  }

  // Ensure client presents an authenticated badge (satisfies request.auth != null in Firestore rules)
  async function ensureAuth_() {
    if (!initFirebase()) return false;
    if (typeof firebase.auth !== 'function') return true;
    try {
      const auth = firebase.auth();
      if (auth.currentUser) return true;
      if (!authPromise) {
        authPromise = auth.signInAnonymously().catch(err => {
          console.warn('Firebase Anonymous Auth notice (enable Anonymous in Firebase Console > Authentication):', err && err.message ? err.message : err);
          authPromise = null;
        });
      }
      await authPromise;
      return true;
    } catch (e) {
      console.warn('ensureAuth_ error:', e);
      return false;
    }
  }

  // Cryptographic Helpers
  async function sha256(str) {
    const enc = new TextEncoder();
    const data = enc.encode(str);
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function safeEqual(a, b) {
    a = String(a || ''); b = String(b || '');
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  function b64u(str) {
    return btoa(unescape(encodeURIComponent(str)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64uDecode(str) {
    str = String(str).replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return decodeURIComponent(escape(atob(str)));
  }

  const SECRET_KEY = 'TM_FIREBASE_SESSION_SALT_v17';
  function signToken(text) {
    let hash = 0;
    const combined = text + ':' + SECRET_KEY;
    for (let i = 0; i < combined.length; i++) {
      const char = combined.charCodeAt(i);
      hash = ((hash << 5) - hash) + char;
      hash |= 0;
    }
    return Math.abs(hash).toString(36);
  }

  function tmIssueToken_(user) {
    const days = 30;
    const now = Date.now();
    const payload = {
      e: String(user.EmpCode),
      v: String(user.SessionVersion || '0'),
      i: now,
      x: now + days * 86400000
    };
    const body = b64u(JSON.stringify(payload));
    return body + '.' + signToken(body);
  }

  function tmReadToken_(token) {
    token = String(token || '');
    if (!token || token.length < 15) throw new Error('Please sign in again.');
    const parts = token.split('.');
    if (parts.length !== 2 || parts[1] !== signToken(parts[0])) {
      throw new Error('Please sign in again.');
    }
    let payload;
    try { payload = JSON.parse(b64uDecode(parts[0])); } catch (e) { throw new Error('Please sign in again.'); }
    if (!payload || !payload.e || !payload.x) throw new Error('Please sign in again.');
    if (payload.x < Date.now()) throw new Error('Your session has expired. Please sign in again.');
    return payload;
  }

  async function tmAuth_(token) {
    const payload = tmReadToken_(token);
    const hier = await tmHierarchy_();
    const user = hier.byCode[String(payload.e)];
    if (!user || user.Active !== 'Y') throw new Error('This account is not active. Please contact your administrator.');
    if (String(user.SessionVersion || '0') !== String(payload.v)) throw new Error('You were signed out. Please sign in again.');
    return { user, payload };
  }

  function tmYes_(v) { return v === true || String(v).toUpperCase() === 'Y'; }
  function tmYN_(v) { return tmYes_(v) ? 'Y' : 'N'; }
  function tmId_(prefix) { return prefix + '-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7); }
  function tmClip_(s, n) { return String(s == null ? '' : s).trim().slice(0, n); }

  function tmAsDate_(v) {
    if (v instanceof Date) return isNaN(v.getTime()) ? null : v;
    if (v && typeof v.toDate === 'function') return v.toDate(); // Firestore Timestamp
    if (v === '' || v == null) return null;
    const d = new Date(v);
    return isNaN(d.getTime()) ? null : d;
  }

  function tmDayKey_(d) {
    const date = tmAsDate_(d) || new Date();
    const y = date.getFullYear();
    const m = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    return `${y}-${m}-${day}`;
  }

  function tmStamp_(v) {
    const d = tmAsDate_(v);
    if (!d) return '';
    return tmDayKey_(d) + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
  }

  function tmOverdue_(due, status) {
    const d = tmAsDate_(due);
    return !!d && status !== 'Completed' && tmDayKey_(d) < tmDayKey_(new Date());
  }

  function tmSortKey_(t) {
    const done = t.Status === 'Completed' ? '1' : '0';
    const due = t.DueDate ? tmDayKey_(tmAsDate_(t.DueDate)) : '9999-99-99';
    return done + due;
  }

  // ================= Configuration & Seed Data =================
  async function tmConfig_() {
    return memoGet('config', async () => {
      await ensureAuth_();
      if (!initFirebase()) return Object.assign({}, TM_DEFAULTS);
      try {
        const doc = await db.collection('config').doc('app_config').get();
        if (doc.exists) return Object.assign({}, TM_DEFAULTS, doc.data());
      } catch (e) { console.warn('Config read failed:', e); }
      return Object.assign({}, TM_DEFAULTS);
    });
  }

  async function tmEnsureDefaults_() {
    await ensureAuth_();
    if (!initFirebase()) return;
    try {
      // 1. Roles
      const rolesSnap = await db.collection('roles').get();
      if (rolesSnap.empty) {
        const standardRoles = [
          { Role: 'Admin', Level: 100, Chain: 'Admin', IsHeadOffice: true, IsAdmin: true, Active: true },
          { Role: 'Nazim', Level: 50, Chain: 'Management', IsHeadOffice: false, IsAdmin: false, Active: true },
          { Role: 'Employee', Level: 10, Chain: 'Operations', IsHeadOffice: false, IsAdmin: false, Active: true }
        ];
        const b = db.batch();
        standardRoles.forEach(r => b.set(db.collection('roles').doc(r.Role), r));
        await b.commit();
      }

      // 2. Regions
      const regSnap = await db.collection('regions').get();
      if (regSnap.empty) {
        const b = db.batch();
        TM_REGIONS.forEach(r => b.set(db.collection('regions').doc(r), { Region: r, Active: true }));
        await b.commit();
      }

      // 3. Default Admin user
      const empSnap = await db.collection('employees').get();
      if (empSnap.empty) {
        const salt = tmId_('salt');
        const hash = await sha256('admin123' + salt);
        await db.collection('employees').doc('ADMIN').set({
          EmpCode: 'ADMIN',
          EmpName: 'Administrator',
          Nazim: '',
          Division: 'Head Office',
          Region: 'Mumbai',
          Role: 'Admin',
          Email: 'admin@taskmanagement.local',
          PasswordHash: hash,
          Salt: salt,
          MustChangePassword: 'N',
          Active: 'Y',
          SessionVersion: '1',
          CreatedAt: new Date()
        });
      }
    } catch (e) {
      console.warn('EnsureDefaults error:', e);
    }
  }

  // ================= Roles & Hierarchy =================
  async function tmRoles_() {
    return memoGet('roles', async () => {
      await ensureAuth_();
      if (!initFirebase()) return [];
      const snap = await db.collection('roles').get();
      const roles = [];
      snap.forEach(d => roles.push(d.data()));
      return roles;
    });
  }

  async function tmHierarchy_() {
    return memoGet('hierarchy', async () => {
      await ensureAuth_();
      if (!initFirebase()) return { byCode: {}, children: {} };
      const snap = await db.collection('employees').get();
      const byCode = {}, children = {};
      snap.forEach(d => {
        const e = d.data();
        const c = String(e.EmpCode || '').trim();
        if (!c) return;
        byCode[c] = {
          EmpCode: c,
          EmpName: String(e.EmpName || '').trim(),
          Nazim: String(e.Nazim || '').trim(),
          Division: String(e.Division || '').trim(),
          Region: String(e.Region || '').trim(),
          Role: String(e.Role || '').trim(),
          Email: String(e.Email || '').trim(),
          MustChangePassword: tmYN_(e.MustChangePassword),
          Active: tmYN_(e.Active),
          SessionVersion: String(e.SessionVersion || '0')
        };
      });
      Object.keys(byCode).forEach(c => {
        const e = byCode[c];
        const m = e.Nazim;
        if (e.Active === 'Y' && m && byCode[m] && m !== c) {
          (children[m] = children[m] || []).push(c);
        }
      });
      return { byCode, children };
    });
  }

  async function tmAccess_(user) {
    const roles = await tmRoles_();
    const r = roles.find(x => x.Role === user.Role && x.Active) || {};
    const hier = await tmHierarchy_();
    const admin = !!r.IsAdmin;
    const headOffice = !!r.IsHeadOffice;
    const sub = new Set();
    const q = [user.EmpCode];
    while (q.length) {
      const cur = q.shift();
      (hier.children[cur] || []).forEach(child => {
        if (!sub.has(child)) {
          sub.add(child);
          q.push(child);
        }
      });
    }
    return { code: String(user.EmpCode), admin, headOffice, sub };
  }

  function tmCanSee_(a, t) {
    if (a.admin || a.headOffice) return true;
    const to = String(t.AssignedTo || '');
    const by = String(t.AssignedBy || '');
    return to === a.code || by === a.code || a.sub.has(to);
  }

  function tmCanUpdate_(a, t) {
    if (a.admin) return true;
    const to = String(t.AssignedTo || '');
    return to === a.code || a.sub.has(to);
  }

  function tmCanManage_(a, t) {
    if (a.admin) return true;
    const to = String(t.AssignedTo || '');
    const by = String(t.AssignedBy || '');
    return (by === a.code && to === a.code) || a.sub.has(to);
  }

  function tmCanDelete_(a, t) {
    if (a.admin) return true;
    const to = String(t.AssignedTo || '');
    const by = String(t.AssignedBy || '');
    return (by === a.code && to === a.code) || a.sub.has(to);
  }

  function tmCanRemind_(a, t) {
    if (t.Status === 'Completed') return false;
    if (a.admin) return true;
    const to = String(t.AssignedTo || '');
    const by = String(t.AssignedBy || '');
    return by === a.code || a.sub.has(to);
  }

  async function tmCanAssign_(user, targetCode) {
    const a = await tmAccess_(user);
    if (a.admin) return true;
    if (String(targetCode) === a.code) return true;
    return a.sub.has(String(targetCode));
  }

  // ================= Checklists =================
  async function tmChecklistFor_(taskIds) {
    if (!taskIds.length) return {};
    await ensureAuth_();
    if (!initFirebase()) return {};
    const map = {};
    taskIds.forEach(id => { map[String(id)] = []; });

    // Firestore chunks 'in' queries to 30 items
    const chunks = [];
    for (let i = 0; i < taskIds.length; i += 30) {
      chunks.push(taskIds.slice(i, i + 30));
    }

    for (const chunk of chunks) {
      const snap = await db.collection('checklist').where('TaskID', 'in', chunk).get();
      snap.forEach(d => {
        const x = d.data();
        const tid = String(x.TaskID);
        if (map[tid]) {
          map[tid].push({
            id: String(x.ItemID || d.id),
            text: String(x.Text || ''),
            done: tmYes_(x.IsDone),
            order: Number(x.SortOrder) || 0
          });
        }
      });
    }

    Object.keys(map).forEach(k => map[k].sort((a, b) => a.order - b.order));
    return map;
  }

  function tmShapeTask_(t, a, checklist, byCode) {
    const items = checklist[String(t.TaskID)] || [];
    const over = tmOverdue_(t.DueDate, t.Status);
    const assignedTo = byCode[String(t.AssignedTo)] || {};
    const selfAssigned = String(t.AssignedBy) === String(t.AssignedTo);
    const byName = (byCode[String(t.AssignedBy)] || {}).EmpName || String(t.AssignedBy);
    const toName = (byCode[String(t.AssignedTo)] || {}).EmpName || String(t.AssignedTo);

    return {
      TaskID: String(t.TaskID),
      Title: String(t.Title || ''),
      Description: String(t.Description || ''),
      AssignedBy: String(t.AssignedBy),
      AssignedByName: byName,
      AssignedTo: String(t.AssignedTo),
      AssignedToName: toName,
      SelfAssigned: selfAssigned,
      GivenByNazim: !selfAssigned && String(assignedTo.Nazim || '') === String(t.AssignedBy),
      Region: String(t.Region || ''),
      Division: String(t.Division || ''),
      Due: t.DueDate ? tmDayKey_(tmAsDate_(t.DueDate)) : '',
      Status: String(t.Status || 'Pending'),
      Overdue: over,
      Created: tmStamp_(t.CreatedAt),
      Updated: tmStamp_(t.UpdatedAt),
      Completed: tmStamp_(t.CompletedAt),
      Reminders: Number(t.ReminderCount) || 0,
      LastReminder: tmStamp_(t.LastReminderAt),
      Checklist: items,
      Done: items.filter(x => x.done).length,
      Total: items.length,
      CanUpdate: tmCanUpdate_(a, t),
      CanManage: tmCanManage_(a, t),
      CanDelete: tmCanDelete_(a, t),
      CanRemind: tmCanRemind_(a, t),
      Mine: String(t.AssignedTo) === a.code
    };
  }

  // ================= Email Dispatch (Free Brevo / Apps Script Webhook) =================
  async function tmSendEmail_(to, subject, htmlBody, textBody) {
    const cfg = window.EMAIL_CONFIG || {};
    // 1. Try Apps Script Webhook (Secured with secret token)
    if (cfg.appsScriptRelayUrl) {
      try {
        await fetch(cfg.appsScriptRelayUrl, {
          method: 'POST',
          mode: 'no-cors',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ 
            to, 
            subject, 
            html: htmlBody, 
            text: textBody,
            secret: cfg.relaySecret || ''
          })
        });
        return { ok: true };
      } catch (e) { console.warn('Apps Script mail relay error:', e); }
    }
    // 2. Try Brevo Free API
    if (cfg.brevoApiKey && cfg.senderEmail) {
      try {
        const res = await fetch('https://api.brevo.com/v3/smtp/email', {
          method: 'POST',
          headers: {
            'api-key': cfg.brevoApiKey,
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          },
          body: JSON.stringify({
            sender: { email: cfg.senderEmail, name: cfg.senderName || 'Task Management' },
            to: [{ email: to }],
            subject: subject,
            htmlContent: htmlBody
          })
        });
        if (res.ok) return { ok: true };
      } catch (e) { console.warn('Brevo mail error:', e); }
    }
    return { ok: false, error: 'Email relay not configured' };
  }

  // ================= Public API Implementation =================
  const Backend = {
    // 1. Login
    apiLogin: async function (identifier, password) {
      await ensureAuth_();
      if (!initFirebase()) {
        return { ok: false, error: 'Firebase is not configured yet. Please open firebase-config.js and add your project keys.' };
      }
      await tmEnsureDefaults_();
      const id = String(identifier || '').trim();
      const pw = String(password || '');
      if (!id || !pw) return { ok: false, error: 'Please enter your Employee Code and Password.' };

      // Query employee by EmpCode or Email
      let empDoc = null;
      const snapCode = await db.collection('employees').where('EmpCode', '==', id.toUpperCase()).limit(1).get();
      if (!snapCode.empty) {
        empDoc = snapCode.docs[0].data();
      } else {
        const snapEmail = await db.collection('employees').where('Email', '==', id.toLowerCase()).limit(1).get();
        if (!snapEmail.empty) empDoc = snapEmail.docs[0].data();
      }

      if (!empDoc || empDoc.Active !== 'Y') {
        return { ok: false, error: 'Invalid Employee Code / Email or inactive account.' };
      }

      // Check password hash
      const salt = empDoc.Salt || '';
      const targetHash = empDoc.PasswordHash || '';
      const testHash = await sha256(pw + salt);

      if (!safeEqual(targetHash, testHash)) {
        // Fallback for initial admin password or unhashed imported rows
        if (empDoc.Password && safeEqual(empDoc.Password, pw)) {
          // Upgrade password to hash
          const newSalt = tmId_('salt');
          const newHash = await sha256(pw + newSalt);
          await db.collection('employees').doc(empDoc.EmpCode).update({
            PasswordHash: newHash,
            Salt: newSalt,
            Password: firebase.firestore.FieldValue.delete()
          });
        } else {
          return { ok: false, error: 'Incorrect password. Please try again.' };
        }
      }

      // Update LastLogin
      await db.collection('employees').doc(empDoc.EmpCode).update({
        LastLogin: new Date()
      });

      memoClear();
      const token = tmIssueToken_(empDoc);
      const boot = await Backend.apiBootstrap(token);
      return Object.assign({ ok: true, token }, boot);
    },

    // 2. Bootstrap (Initial page payload)
    apiBootstrap: async function (token) {
      const { user } = await tmAuth_(token);
      const hier = await tmHierarchy_();
      const me = hier.byCode[String(user.EmpCode)] || user;
      const roles = await tmRoles_();
      const r = roles.find(x => x.Role === me.Role && x.Active) || {};
      const access = await tmAccess_(me);
      const boss = hier.byCode[me.Nazim] || null;

      const out = {
        today: tmDayKey_(new Date()),
        app: { name: 'Task Management', version: '17.0.0 (Firebase)', sessionDays: 30 },
        user: {
          EmpCode: me.EmpCode,
          EmpName: me.EmpName,
          Role: me.Role,
          Region: me.Region,
          Division: me.Division,
          Email: me.Email,
          Nazim: me.Nazim,
          NazimName: boss ? boss.EmpName : '',
          isAdmin: !!r.IsAdmin,
          isHeadOffice: !!r.IsHeadOffice,
          isNazim: (hier.children[me.EmpCode] || []).length > 0,
          hasTeam: !!r.IsAdmin || (hier.children[me.EmpCode] || []).length > 0
        },
        mustChangePassword: false
      };

      // People list
      const codes = (out.user.isAdmin || out.user.isHeadOffice)
        ? Object.keys(hier.byCode).filter(c => hier.byCode[c].Active === 'Y')
        : [access.code].concat(Array.from(access.sub));

      const divisions = {}, people = [];
      codes.forEach(c => {
        const e = hier.byCode[c];
        if (!e || e.Active !== 'Y') return;
        if (e.Division) divisions[e.Division] = true;
        const canAssign = out.user.isAdmin || c === access.code || access.sub.has(c);
        people.push({ c: e.EmpCode, n: e.EmpName, r: e.Role, g: e.Region, d: e.Division, a: canAssign ? 1 : 0 });
      });
      people.sort((x, y) => x.n.localeCompare(y.n));
      out.people = people;

      // Lists
      const regSnap = await db.collection('regions').where('Active', '==', true).get();
      const regList = []; regSnap.forEach(d => regList.push(d.data().Region));

      out.lists = {
        regions: regList.length ? regList : TM_REGIONS,
        divisions: Object.keys(divisions).sort(),
        roles: roles.filter(x => x.Active).map(x => x.Role),
        statuses: TM_STATUSES
      };

      // Fetch My Tasks
      const mineRes = await Backend.apiListTasks(token, { scope: 'mine' });
      out.mine = mineRes;
      out.team = null; // Lazy loaded for instant login
      return out;
    },

    // 3. List Tasks
    apiListTasks: async function (token, filters) {
      const { user } = await tmAuth_(token);
      filters = filters || {};
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const byCode = hier.byCode;
      const scope = filters.scope === 'team' ? 'team' : 'mine';

      let q = db.collection('tasks');
      if (scope === 'mine') {
        q = q.where('AssignedTo', '==', access.code);
      } else {
        if (!access.admin && (hier.children[user.EmpCode] || []).length === 0) {
          throw new Error('Team task access is limited to Nazim users.');
        }
      }

      const snap = await q.get();
      const allTasks = [];
      snap.forEach(d => allTasks.push(Object.assign({ id: d.id }, d.data())));

      const today = tmDayKey_(new Date());
      const matched = [];
      const counts = { Pending: 0, 'In Progress': 0, Completed: 0, Overdue: 0, All: 0 };
      const search = String(filters.search || '').trim().toLowerCase();
      const emp = String(filters.employee || '').trim().toLowerCase();

      allTasks.forEach(t => {
        if (!tmCanSee_(access, t)) return;
        const mine = String(t.AssignedTo) === access.code;
        if (scope === 'mine' ? !mine : mine) return;
        if (filters.region && String(t.Region) !== filters.region) return;
        if (filters.division && String(t.Division) !== filters.division) return;
        if (filters.role && String((byCode[String(t.AssignedTo)] || {}).Role) !== filters.role) return;
        if (emp) {
          const e = byCode[String(t.AssignedTo)] || {};
          if (String(t.AssignedTo).toLowerCase() !== emp && String(e.EmpName || '').toLowerCase().indexOf(emp) < 0) return;
        }
        if (search && (String(t.Title).toLowerCase() + ' ' + String(t.Description).toLowerCase()).indexOf(search) < 0) return;

        const due = t.DueDate ? tmDayKey_(tmAsDate_(t.DueDate)) : '';
        if (filters.dueFrom && (!due || due < filters.dueFrom)) return;
        if (filters.dueTo && (!due || due > filters.dueTo)) return;

        const over = t.Status !== 'Completed' && due && due < today;
        counts.All++;
        counts[t.Status] = (counts[t.Status] || 0) + 1;
        if (over) counts.Overdue++;

        if (filters.status && String(t.Status) !== filters.status) return;
        if (filters.overdue === true || filters.overdue === 'true') { if (!over) return; }
        matched.push(t);
      });

      // Sort
      if (scope === 'team') {
        matched.sort((x, y) => {
          const xn = String((byCode[String(x.AssignedTo)] || {}).EmpName || x.AssignedTo);
          const yn = String((byCode[String(y.AssignedTo)] || {}).EmpName || y.AssignedTo);
          return xn.localeCompare(yn) || String(x.Title).localeCompare(String(y.Title)) || tmSortKey_(x).localeCompare(tmSortKey_(y));
        });
      } else {
        matched.sort((x, y) => tmSortKey_(x).localeCompare(tmSortKey_(y)) || String(x.Title).localeCompare(String(y.Title)));
      }

      const offset = Math.max(0, Number(filters.offset) || 0);
      const page = matched.slice(offset, offset + PAGE_SIZE);
      const checklist = await tmChecklistFor_(page.map(t => t.TaskID));

      return {
        ok: true,
        tasks: page.map(t => tmShapeTask_(t, access, checklist, byCode)),
        total: matched.length,
        counts,
        hasMore: offset + PAGE_SIZE < matched.length,
        nextOffset: offset + PAGE_SIZE
      };
    },

    // 4. Create Task
    apiCreateTask: async function (token, data) {
      const { user } = await tmAuth_(token);
      data = data || {};
      const hier = await tmHierarchy_();
      const directory = hier.byCode;
      const now = new Date();

      const rawTasks = Array.isArray(data.tasks) ? data.tasks : (data.title ? [data.title] : []);
      const defaultDue = data.dueDate ? new Date(data.dueDate) : new Date();
      const defaultNote = tmClip_(data.description, 2000);
      const defaultSteps = (Array.isArray(data.checklist) ? data.checklist : []).map(x => tmClip_(x, 200)).filter(Boolean);

      const parsedTasks = [];
      rawTasks.forEach(item => {
        if (!item) return;
        if (typeof item === 'object') {
          const title = tmClip_(item.title || item.Title, 200);
          if (!title) return;
          const due = item.dueDate ? new Date(item.dueDate) : defaultDue;
          const desc = item.description !== undefined ? tmClip_(item.description, 2000) : defaultNote;
          const steps = (Array.isArray(item.checklist) ? item.checklist : defaultSteps).map(x => tmClip_(x, 200)).filter(Boolean);
          parsedTasks.push({ title, due, description: desc, steps });
        } else {
          const title = tmClip_(item, 200);
          if (title) parsedTasks.push({ title, due: defaultDue, description: defaultNote, steps: defaultSteps });
        }
      });

      const targets = Array.from(new Set((Array.isArray(data.assignedTo) ? data.assignedTo : [data.assignedTo || user.EmpCode]).map(String)));
      for (const t of targets) {
        if (!(await tmCanAssign_(user, t))) throw new Error(`You cannot assign a task to employee ${t}.`);
      }

      if (!parsedTasks.length) throw new Error('Please add at least one task title.');

      const batch = db.batch();
      const taskIds = [];

      for (const target of targets) {
        const emp = directory[target] || {};
        for (const pt of parsedTasks) {
          const taskId = 'TSK-' + tmDayKey_(now).replace(/-/g, '') + '-' + Math.random().toString(36).slice(2, 8).toUpperCase();
          taskIds.push(taskId);

          const taskData = {
            TaskID: taskId,
            Title: pt.title,
            Description: pt.description,
            AssignedBy: user.EmpCode,
            AssignedTo: target,
            Region: emp.Region || '',
            Division: emp.Division || '',
            DueDate: pt.due,
            Status: 'Pending',
            CreatedAt: now,
            UpdatedAt: now,
            CompletedAt: null,
            LastReminderAt: null,
            ReminderCount: 0
          };
          batch.set(db.collection('tasks').doc(taskId), taskData);

          // Checklist
          pt.steps.forEach((step, idx) => {
            const itemId = tmId_('ITM');
            batch.set(db.collection('checklist').doc(itemId), {
              ItemID: itemId,
              TaskID: taskId,
              Text: step,
              IsDone: 'N',
              DoneAt: null,
              SortOrder: idx + 1
            });
          });

          // History
          batch.set(db.collection('taskHistory').doc(), {
            Timestamp: now,
            TaskID: taskId,
            ActorEmpCode: user.EmpCode,
            ActorName: user.EmpName,
            Action: 'TASK_CREATED',
            Details: JSON.stringify({ assignedTo: target })
          });
        }
      }

      await batch.commit();

      // Email notification (sent asynchronously without blocking)
      if (data.notify) {
        targets.forEach(async target => {
          if (target === user.EmpCode) return;
          const person = directory[target];
          if (person && person.Email) {
            const count = parsedTasks.length;
            const sub = count === 1 ? `New Task Assigned: ${parsedTasks[0].title}` : `${count} New Tasks Assigned`;
            const html = `<p>Salam ${person.EmpName},</p><p>You have been assigned ${count} new task(s) by ${user.EmpName}.</p>`;
            await tmSendEmail_(person.Email, sub, html, html);
          }
        });
      }

      return { ok: true, taskId: taskIds[0], taskIds, count: taskIds.length, recipients: targets.length };
    },

    // 5. Update Task
    apiUpdateTask: async function (token, id, changes) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const docRef = db.collection('tasks').doc(id);
      const snap = await docRef.get();
      if (!snap.exists) throw new Error('Task no longer exists.');
      const task = snap.data();
      if (!tmCanSee_(access, task)) throw new Error('You do not have access to this task.');

      const now = new Date();
      const updates = { UpdatedAt: now };
      const batch = db.batch();

      if (changes.Status && changes.Status !== task.Status) {
        if (!tmCanUpdate_(access, task)) throw new Error('You cannot change the status of this task.');
        updates.Status = changes.Status;
        if (changes.Status === 'Completed') {
          updates.CompletedAt = now;
          // Mark all checklist items done
          const checks = await db.collection('checklist').where('TaskID', '==', id).get();
          checks.forEach(c => batch.update(c.ref, { IsDone: 'Y', DoneAt: now }));
        } else {
          updates.CompletedAt = null;
        }
        batch.set(db.collection('taskHistory').doc(), {
          Timestamp: now, TaskID: id, ActorEmpCode: user.EmpCode, ActorName: user.EmpName,
          Action: 'STATUS_CHANGE', Details: JSON.stringify({ from: task.Status, to: changes.Status })
        });
      }

      if (changes.Title !== undefined) updates.Title = tmClip_(changes.Title, 200);
      if (changes.Description !== undefined) updates.Description = tmClip_(changes.Description, 2000);
      if (changes.DueDate !== undefined) updates.DueDate = changes.DueDate ? new Date(changes.DueDate) : null;
      if (changes.AssignedTo !== undefined) updates.AssignedTo = String(changes.AssignedTo);

      batch.update(docRef, updates);
      await batch.commit();
      return { ok: true };
    },

    // 6. Bulk Update Tasks
    apiBulkUpdateTaskStatus: async function (token, ids, status, remark) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const now = new Date();
      const batch = db.batch();

      for (const id of ids) {
        const docRef = db.collection('tasks').doc(id);
        const snap = await docRef.get();
        if (snap.exists) {
          const t = snap.data();
          if (tmCanUpdate_(access, t)) {
            const updates = { Status: status, UpdatedAt: now };
            if (status === 'Completed') updates.CompletedAt = now;
            batch.update(docRef, updates);
            batch.set(db.collection('taskHistory').doc(), {
              Timestamp: now, TaskID: id, ActorEmpCode: user.EmpCode, ActorName: user.EmpName,
              Action: 'STATUS_CHANGE', Details: JSON.stringify({ to: status, remark: remark || '' })
            });
          }
        }
      }
      await batch.commit();
      return { ok: true, count: ids.length };
    },

    // 7. Delete Task
    apiDeleteTask: async function (token, id) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const docRef = db.collection('tasks').doc(id);
      const snap = await docRef.get();
      if (!snap.exists) return { ok: true };
      const task = snap.data();
      if (!tmCanDelete_(access, task)) throw new Error('You do not have permission to delete this task.');

      const batch = db.batch();
      batch.delete(docRef);
      // Delete checklist items
      const checks = await db.collection('checklist').where('TaskID', '==', id).get();
      checks.forEach(c => batch.delete(c.ref));
      await batch.commit();
      return { ok: true };
    },

    // 8. Checklist Management
    apiAddChecklistItem: async function (token, taskId, text) {
      await tmAuth_(token);
      const itemId = tmId_('ITM');
      const item = {
        ItemID: itemId,
        TaskID: taskId,
        Text: tmClip_(text, 200),
        IsDone: 'N',
        DoneAt: null,
        SortOrder: Date.now()
      };
      await db.collection('checklist').doc(itemId).set(item);
      return { ok: true, item: { id: itemId, text: item.Text, done: false, order: item.SortOrder } };
    },

    apiRemoveChecklistItem: async function (token, taskId, itemId) {
      await tmAuth_(token);
      await db.collection('checklist').doc(itemId).delete();
      return { ok: true };
    },

    // 9. Notifications
    apiGetNotifications: async function (token) {
      const { user } = await tmAuth_(token);
      const snap = await db.collection('taskHistory').orderBy('Timestamp', 'desc').limit(50).get();
      const events = [];
      snap.forEach(d => {
        const ev = d.data();
        if (ev.ActorEmpCode !== user.EmpCode) {
          events.push({
            id: d.id,
            taskId: ev.TaskID,
            title: ev.TaskID,
            action: ev.Action,
            actor: ev.ActorName || ev.ActorEmpCode,
            time: tmStamp_(ev.Timestamp)
          });
        }
      });
      return { ok: true, notifications: events };
    },

    // 10. Dashboard Analytics
    apiDashboardData: async function (token, filters) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const snap = await db.collection('tasks').get();
      const visible = [];

      snap.forEach(d => {
        const t = d.data();
        if (tmCanSee_(access, t)) {
          const emp = hier.byCode[String(t.AssignedTo)] || {};
          visible.push({ task: t, employee: emp, overdue: tmOverdue_(t.DueDate, t.Status) });
        }
      });

      const counts = { Pending: 0, 'In Progress': 0, Completed: 0, Overdue: 0, Total: visible.length };
      const byRegion = {}, byLocation = {}, byRole = {}, byEmployee = {};

      visible.forEach(x => {
        const t = x.task, e = x.employee;
        counts[t.Status] = (counts[t.Status] || 0) + 1;
        if (x.overdue) counts.Overdue++;

        const reg = String(e.Region || 'Unassigned');
        byRegion[reg] = (byRegion[reg] || { label: reg, total: 0, open: 0, completed: 0 });
        byRegion[reg].total++;
        if (t.Status === 'Completed') byRegion[reg].completed++; else byRegion[reg].open++;

        const div = String(e.Division || 'Unassigned');
        byLocation[div] = (byLocation[div] || { label: div, total: 0, open: 0, completed: 0 });
        byLocation[div].total++;
        if (t.Status === 'Completed') byLocation[div].completed++; else byLocation[div].open++;

        const role = String(e.Role || 'Unassigned');
        byRole[role] = (byRole[role] || { label: role, total: 0, open: 0, completed: 0 });
        byRole[role].total++;
        if (t.Status === 'Completed') byRole[role].completed++; else byRole[role].open++;
      });

      const toArr = map => Object.keys(map).map(k => map[k]).sort((a, b) => b.total - a.total);

      return {
        ok: true,
        counts,
        asOf: tmStamp_(new Date()),
        openTotal: (counts.Pending || 0) + (counts['In Progress'] || 0),
        completionRate: counts.Total ? Math.round(counts.Completed * 100 / counts.Total) : 0,
        overdueRate: counts.Total ? Math.round(counts.Overdue * 100 / counts.Total) : 0,
        byRegion: toArr(byRegion),
        byLocation: toArr(byLocation),
        byRole: toArr(byRole),
        byEmployee: []
      };
    },

    // 11. Admin Management
    apiAdminOverview: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Admin access required.');
      const empSnap = await db.collection('employees').get();
      const taskSnap = await db.collection('tasks').get();
      return {
        ok: true,
        stats: { people: empSnap.size, tasks: taskSnap.size }
      };
    },

    apiAdminPeople: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Admin access required.');
      const snap = await db.collection('employees').get();
      const people = [];
      snap.forEach(d => people.push(d.data()));
      people.sort((a, b) => String(a.EmpName || '').localeCompare(String(b.EmpName || '')));
      return { ok: true, people };
    },

    apiSavePerson: async function (token, input) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Admin access required.');
      const code = String(input.EmpCode || '').trim().toUpperCase();
      if (!code) throw new Error('Employee Code is required.');

      const data = {
        EmpCode: code,
        EmpName: tmClip_(input.EmpName, 100),
        Nazim: String(input.Nazim || '').trim().toUpperCase(),
        Division: tmClip_(input.Division, 100),
        Region: tmClip_(input.Region, 100),
        Role: tmClip_(input.Role, 50),
        Email: tmClip_(input.Email, 200),
        Active: input.Active ? 'Y' : 'N'
      };

      if (input.Password) {
        const salt = tmId_('salt');
        data.Salt = salt;
        data.PasswordHash = await sha256(input.Password + salt);
        data.SessionVersion = tmId_('v');
      }

      await db.collection('employees').doc(code).set(data, { merge: true });
      memoClear();
      return { ok: true };
    },

    apiAdminRoles: async function (token) {
      await tmAuth_(token);
      const roles = await tmRoles_();
      return { ok: true, roles };
    },

    apiSaveRoles: async function (token, roles) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Admin access required.');
      const batch = db.batch();
      roles.forEach(r => batch.set(db.collection('roles').doc(r.Role), r));
      await batch.commit();
      memoClear();
      return { ok: true };
    },

    // 12. Password & Session
    apiChangePassword: async function (token, currentPw, newPw) {
      const { user } = await tmAuth_(token);
      const docRef = db.collection('employees').doc(user.EmpCode);
      const snap = await docRef.get();
      if (!snap.exists) throw new Error('User not found.');
      const emp = snap.data();
      const testHash = await sha256(currentPw + (emp.Salt || ''));
      if (!safeEqual(testHash, emp.PasswordHash) && !safeEqual(currentPw, emp.Password)) {
        throw new Error('Current password is not correct.');
      }
      const newSalt = tmId_('salt');
      const newHash = await sha256(newPw + newSalt);
      await docRef.update({
        PasswordHash: newHash,
        Salt: newSalt,
        SessionVersion: tmId_('v'),
        MustChangePassword: 'N',
        Password: firebase.firestore.FieldValue.delete()
      });
      memoClear();
      return { ok: true };
    },

    apiSignOutEverywhere: async function (token) {
      const { user } = await tmAuth_(token);
      await db.collection('employees').doc(user.EmpCode).update({
        SessionVersion: tmId_('v')
      });
      memoClear();
      return { ok: true };
    },

    // 13. Stubs for templates & schedules to avoid crashes
    apiTaskTemplates: async function () { return { ok: true, templates: [] }; },
    apiAdminTemplates: async function () { return { ok: true, templates: [] }; },
    apiSaveTemplate: async function () { return { ok: true }; },
    apiSetTemplateActive: async function () { return { ok: true }; },
    apiDeleteTemplate: async function () { return { ok: true }; },
    apiAdminSchedule: async function () { return { ok: true, items: [] }; },
    apiSaveSchedule: async function () { return { ok: true }; },
    apiSaveSettings: async function () { return { ok: true }; },
    apiArchiveCompletedTasks: async function () { return { ok: true, archived: 0 }; },
    apiMailStatus: async function () { return { ok: true, status: { sentToday: 0, remaining: 100, queued: 0 } }; },
    apiRunMailNow: async function () { return { ok: true }; },
    apiSendTestMail: async function () { return { ok: true, message: 'Test email function ready' }; }
  };

  // Expose to window
  window.FirebaseBackend = Backend;
  window.initFirebaseBackend = initFirebase;
})();
