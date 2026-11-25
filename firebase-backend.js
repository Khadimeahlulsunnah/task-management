// =============================================================================
// FIREBASE BACKEND ADAPTER (V18.0 - Full Business Logic + Hardened Security)
// =============================================================================
// Implements the full backend specification from Appscript_Backend.gs on
// Cloud Firestore + Firebase Auth + WebCrypto End-to-End Encryption:
//   Phase 1: Real Firebase Auth, UID->Role rules, AES-256-GCM confidential vault
//   Phase 2: Roles, Multi-level Nazim hierarchy, Region/Division logic,
//            Dashboard analytics, Templates, Schedules, Digests, Export,
//            Email Change Requests, Archiving, Backups, Self-Test & Repair
// =============================================================================

(function () {
  'use strict';

  const TM_VERSION = '18.0.0 (Firebase)';
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
  const TM_HO_ROLES = [
    'Compliance Head Office', 'Compliance Team CA',
    'Assistant Compliance Manager', 'Compliance Manager',
    'Compliance Head', 'System Admin', 'Admin'
  ];
  const PAGE_SIZE = 50;
  const MAX_FILES_PER_TASK = 5;
  const TM_TPL_ALL = '*';

  let fbApp = null;
  let db = null;
  let fbAuth = null;
  let isConfigured = false;
  let authReadyPromise = null;

  let _MEMO = {};
  const _CREATE_DEDUP = {};

  function memoGet(key, fn) {
    if (!Object.prototype.hasOwnProperty.call(_MEMO, key)) _MEMO[key] = fn();
    return _MEMO[key];
  }
  function memoClear() { _MEMO = {}; }

  // ================= Firebase Initialization =================
  function initFirebase() {
    if (fbApp && db && fbAuth) return true;
    const cfg = window.FIREBASE_CONFIG;
    if (!cfg || !cfg.apiKey || cfg.apiKey === 'YOUR_API_KEY' || !cfg.projectId || cfg.projectId === 'YOUR_PROJECT_ID') {
      isConfigured = false;
      return false;
    }
    try {
      fbApp = !firebase.apps.length ? firebase.initializeApp(cfg) : firebase.app();
      db = firebase.firestore();
      fbAuth = firebase.auth();
      isConfigured = true;
      return true;
    } catch (err) {
      console.error('Firebase initialization error:', err);
      isConfigured = false;
      return false;
    }
  }

  function waitForFirebaseUser_() {
    if (!initFirebase()) return Promise.resolve(null);
    if (fbAuth.currentUser) {
      return Promise.resolve(fbAuth.currentUser.isAnonymous ? null : fbAuth.currentUser);
    }
    if (!authReadyPromise) {
      authReadyPromise = new Promise(resolve => {
        let settled = false;
        const timer = setTimeout(() => {
          if (!settled) { settled = true; resolve(null); }
        }, 3000);
        const unsub = fbAuth.onAuthStateChanged(user => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          unsub();
          if (user && user.isAnonymous) {
            fbAuth.signOut().catch(() => {});
            resolve(null);
          } else {
            resolve(user || null);
          }
        });
      }).finally(() => { authReadyPromise = null; });
    }
    return authReadyPromise;
  }

  // ================= Small & Crypto Helpers =================
  async function sha256(str) {
    const enc = new TextEncoder();
    const hashBuffer = await window.crypto.subtle.digest('SHA-256', enc.encode(str));
    return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function safeEqual(a, b) {
    a = String(a || ''); b = String(b || '');
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
    return diff === 0;
  }

  function tmYes_(v) { return v === true || String(v).toUpperCase() === 'Y'; }
  function tmYN_(v) { return tmYes_(v) ? 'Y' : 'N'; }
  function tmId_(prefix) { return prefix + '-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7); }
  function tmClip_(s, n) { return String(s == null ? '' : s).trim().slice(0, n); }
  function tmIsEmail_(s) { return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || '')) && String(s).length <= 254; }
  function tmEscape_(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }

  function tmAsDate_(v) {
    if (v instanceof Date) return isNaN(v.getTime()) ? null : v;
    if (v && typeof v.toDate === 'function') return v.toDate();
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

  function tmParseDay_(v) {
    if (v instanceof Date) return isNaN(v.getTime()) ? null : v;
    const s = String(v || '').trim();
    if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) return null;
    const p = s.split('-').map(Number);
    const d = new Date(p[0], p[1] - 1, p[2]);
    return (d.getFullYear() === p[0] && d.getMonth() === p[1] - 1 && d.getDate() === p[2]) ? d : null;
  }

  function tmStamp_(v) {
    const d = tmAsDate_(v);
    if (!d) return '';
    return tmDayKey_(d) + ' ' + String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
  }

  function tmIso_(v) {
    const d = tmAsDate_(v);
    return d ? d.toISOString() : '';
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

  function authEmailFor_(empCode, email) {
    const clean = String(email || '').trim().toLowerCase();
    return clean || (String(empCode).toLowerCase() + '@tm.internal');
  }

  function mapAuthError_(err) {
    const code = err && err.code ? err.code : '';
    if (code === 'auth/too-many-requests') return 'Too many failed login attempts. Please wait a few minutes and try again.';
    if (code === 'auth/wrong-password' || code === 'auth/invalid-credential' || code === 'auth/user-not-found') return 'Invalid Employee Code / Email or password.';
    if (code === 'auth/user-disabled') return 'This account has been disabled. Contact your administrator.';
    if (code === 'auth/weak-password') return 'Password must be at least 6 characters (8+ recommended).';
    if (code === 'auth/email-already-in-use') return 'An account with this email already exists.';
    if (code === 'auth/operation-not-allowed') return 'Email/Password sign-in is not enabled in Firebase Console -> Authentication -> Sign-in method.';
    if (code === 'auth/operation-not-supported-in-this-environment') return 'Firebase Auth cannot run from a local file:// URL. Open your GitHub Pages link or run a local web server.';
    return err && err.message ? err.message : 'Authentication failed.';
  }

  // ================= Config, Audit & Standard Roles =================
  async function tmConfig_() {
    return memoGet('config', async () => {
      if (!initFirebase()) return Object.assign({}, TM_DEFAULTS);
      try {
        const snap = await db.collection('config').doc('app_config').get();
        if (snap.exists) {
          const data = snap.data() || {};
          const cfg = Object.assign({}, TM_DEFAULTS);
          Object.keys(data).forEach(k => {
            if (data[k] !== undefined && data[k] !== null && data[k] !== '') cfg[k] = data[k];
          });
          return cfg;
        }
      } catch (e) { /* use defaults */ }
      return Object.assign({}, TM_DEFAULTS);
    });
  }

  function tmStandardRolesMap_() {
    const roles = {};
    const add = (chain, names) => names.forEach((name, i) => {
      const level = (i + 1) * 10;
      if (roles[name]) {
        roles[name].Level = Math.max(roles[name].Level, level);
        if (roles[name].Chain.split(',').indexOf(chain) < 0) roles[name].Chain += ',' + chain;
      } else {
        roles[name] = {
          Role: name,
          Level: level,
          Chain: chain,
          IsHeadOffice: TM_HO_ROLES.indexOf(name) >= 0,
          IsAdmin: false,
          Active: true
        };
      }
    });
    add('1', ['Accountant', 'Accountant Supervisor', 'Region Accountant Supervisor', 'Region Finance']);
    add('2', ['Division Finance', 'State Finance', 'Region Finance']);
    add('3', ['Regional Compliance Staff', 'Regional Compliance Supervisor', 'Compliance Head Office', 'Compliance Team CA', 'Assistant Compliance Manager', 'Compliance Manager', 'Compliance Head']);
    add('4', ['Regional Compliance Staff', 'Regional Compliance Supervisor', 'Region Finance']);
    roles['System Admin'] = { Role: 'System Admin', Level: 1000, Chain: 'Custom', IsHeadOffice: true, IsAdmin: true, Active: true };
    return roles;
  }

  async function tmAudit_(empCode, action, target, details) {
    try {
      await db.collection('auditLog').add({
        Timestamp: new Date(),
        EmpCode: String(empCode || ''),
        Action: String(action || ''),
        Target: String(target || ''),
        Details: typeof details === 'string' ? details : JSON.stringify(details || {})
      });
    } catch (e) {
      console.warn('Audit log skipped:', e && e.message ? e.message : e);
    }
  }

  async function tmEnsureSeedLists_() {
    const rolesSnap = await db.collection('roles').get();
    if (rolesSnap.empty) {
      const std = tmStandardRolesMap_();
      std['Admin'] = { Role: 'Admin', Level: 1000, Chain: 'Admin', IsHeadOffice: true, IsAdmin: true, Active: true };
      const b = db.batch();
      Object.values(std).forEach(r => b.set(db.collection('roles').doc(r.Role), r));
      await b.commit();
    }

    const regSnap = await db.collection('regions').get();
    if (regSnap.empty) {
      const b = db.batch();
      TM_REGIONS.forEach(r => b.set(db.collection('regions').doc(r), { Region: r, Active: true }));
      await b.commit();
    }

    const cfgRef = db.collection('config').doc('app_config');
    const cfgSnap = await cfgRef.get();
    if (!cfgSnap.exists) {
      await cfgRef.set(Object.assign({}, TM_DEFAULTS, { LAST_BACKUP: 'Never', ARCHIVE_AT: '' }));
    }
  }

  async function syncUserMapping_(uid, empData, roles, overrideAuthEmail) {
    const roleObj = (roles || []).find(x => x.Role === empData.Role && tmYes_(x.Active)) || {};
    const isAdmin = empData.Role === 'Admin' || empData.Role === 'System Admin' || !!roleObj.IsAdmin;
    const isHeadOffice = !!roleObj.IsHeadOffice || isAdmin;
    const contactEmail = String(empData.Email || '').trim();
    const loginEmail = String(overrideAuthEmail || empData.AuthEmail || authEmailFor_(empData.EmpCode, contactEmail)).toLowerCase();

    const batch = db.batch();
    batch.set(db.collection('users').doc(uid), {
      uid,
      EmpCode: empData.EmpCode,
      Email: contactEmail || loginEmail,
      AuthEmail: loginEmail,
      Role: empData.Role || 'Employee',
      Nazim: empData.Nazim || '',
      Region: empData.Region || '',
      Division: empData.Division || '',
      Active: tmYN_(empData.Active),
      IsAdmin: isAdmin,
      IsHeadOffice: isHeadOffice,
      SessionVersion: String(empData.SessionVersion || '1'),
      UpdatedAt: new Date()
    }, { merge: true });

    batch.set(db.collection('authLookup').doc(empData.EmpCode), {
      email: loginEmail,
      migrated: true
    });
    await batch.commit();
  }

  async function createAuthUserAsAdmin_(email, password) {
    const workerName = 'admin-worker-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6);
    const workerApp = firebase.initializeApp(window.FIREBASE_CONFIG, workerName);
    const workerAuth = workerApp.auth();
    try {
      const cred = await workerAuth.createUserWithEmailAndPassword(email, password);
      const uid = cred.user.uid;
      await workerAuth.signOut();
      return uid;
    } finally {
      await workerApp.delete().catch(() => {});
    }
  }

  // ================= Auth Guard =================
  async function tmAuth_() {
    const fbUser = await waitForFirebaseUser_();
    if (!fbUser) throw new Error('Please sign in again.');

    const userSnap = await db.collection('users').doc(fbUser.uid).get();
    if (!userSnap.exists) throw new Error('Your account profile is missing. Please sign in again.');
    const profile = userSnap.data();
    if (profile.Active !== 'Y') throw new Error('This account is not active. Please contact your administrator.');

    const hier = await tmHierarchy_();
    const emp = hier.byCode[String(profile.EmpCode)];
    if (!emp || emp.Active !== 'Y') throw new Error('This account is not active. Please contact your administrator.');
    if (String(emp.SessionVersion || '1') !== String(profile.SessionVersion || '1')) {
      await fbAuth.signOut().catch(() => {});
      if (window.CryptoVault) window.CryptoVault.clearSession();
      throw new Error('You were signed out. Please sign in again.');
    }

    if (window.CryptoVault) {
      await window.CryptoVault.restoreSession(emp.EmpCode);
    }
    return { user: emp, profile, fbUser };
  }

  // ================= Roles, Hierarchy & Exact Business Rules =================
  async function tmRoles_() {
    return memoGet('roles', async () => {
      if (!initFirebase()) return [];
      const snap = await db.collection('roles').get();
      const roles = [];
      snap.forEach(d => {
        const r = d.data() || {};
        roles.push({
          Role: String(r.Role || d.id || '').trim(),
          Level: Number(r.Level) || 0,
          Chain: String(r.Chain || ''),
          IsHeadOffice: tmYes_(r.IsHeadOffice),
          IsAdmin: tmYes_(r.IsAdmin),
          Active: tmYes_(r.Active)
        });
      });
      return roles.filter(r => r.Role).sort((a, b) => a.Role.localeCompare(b.Role));
    });
  }

  async function tmRegions_() {
    return memoGet('regions', async () => {
      if (!initFirebase()) return TM_REGIONS.map(r => ({ Region: r, Active: true }));
      const snap = await db.collection('regions').get();
      const list = [];
      snap.forEach(d => {
        const r = d.data() || {};
        const name = String(r.Region || d.id || '').trim();
        if (name) list.push({ Region: name, Active: tmYes_(r.Active) });
      });
      return list.sort((a, b) => a.Region.localeCompare(b.Region));
    });
  }

  async function tmHierarchy_() {
    return memoGet('hierarchy', async () => {
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
          AuthEmail: String(e.AuthEmail || '').trim(),
          AuthUid: String(e.AuthUid || '').trim(),
          MustChangePassword: tmYN_(e.MustChangePassword),
          Active: tmYN_(e.Active),
          LastLogin: e.LastLogin || null,
          SessionVersion: String(e.SessionVersion || '1')
        };
      });
      const upperMap = {};
      Object.keys(byCode).forEach(c => { upperMap[c.toUpperCase()] = c; });
      Object.keys(byCode).forEach(c => {
        const e = byCode[c];
        const m = e.Nazim ? (byCode[e.Nazim] ? e.Nazim : (upperMap[e.Nazim.toUpperCase()] || '')) : '';
        if (e.Active === 'Y' && m && byCode[m] && m !== c) {
          (children[m] = children[m] || []).push(c);
        }
      });
      return { byCode, children };
    });
  }

  function tmSubtreeFrom_(children, code, includeSelf) {
    const seen = {}, todo = [String(code)];
    while (todo.length) {
      const n = todo.pop();
      if (seen[n]) continue;
      seen[n] = true;
      (children[n] || []).forEach(x => todo.push(x));
    }
    if (!includeSelf) delete seen[String(code)];
    return seen;
  }

  function tmFindCycle_(managerMap) {
    const done = {};
    for (const start of Object.keys(managerMap)) {
      const pos = {}, path = [];
      let cur = start;
      while (cur && Object.prototype.hasOwnProperty.call(managerMap, cur) && !done[cur]) {
        if (pos[cur] !== undefined) return path.slice(pos[cur]);
        pos[cur] = path.length;
        path.push(cur);
        cur = String(managerMap[cur] || '');
      }
      path.forEach(x => { done[x] = true; });
    }
    return null;
  }

  async function tmAccess_(user) {
    const roles = await tmRoles_();
    const r = roles.find(x => x.Role === user.Role && x.Active) || {};
    const hier = await tmHierarchy_();
    const admin = user.Role === 'Admin' || user.Role === 'System Admin' || !!r.IsAdmin;
    const headOffice = !!r.IsHeadOffice || admin;
    const sub = new Set(Object.keys(tmSubtreeFrom_(hier.children, user.EmpCode, false)));
    return { code: String(user.EmpCode), admin, headOffice, level: Number(r.Level) || 0, sub };
  }

  function getWatcherCodes_(assignedTo, assignedBy, hier) {
    const set = new Set();
    if (assignedTo) set.add(String(assignedTo));
    if (assignedBy) set.add(String(assignedBy));
    let cur = String(assignedTo || '');
    const seen = new Set();
    while (cur && !seen.has(cur)) {
      seen.add(cur);
      const emp = hier.byCode[cur];
      if (!emp || !emp.Nazim) break;
      set.add(emp.Nazim);
      cur = emp.Nazim;
    }
    return Array.from(set);
  }

  async function getAllowedKeyCodes_(assignedTo, assignedBy, hier) {
    const codes = new Set(getWatcherCodes_(assignedTo, assignedBy, hier));
    const roles = await tmRoles_();
    const privilegedRoles = new Set(
      roles.filter(r => r.Active && (r.IsAdmin || r.IsHeadOffice)).map(r => r.Role)
    );
    privilegedRoles.add('Admin');
    privilegedRoles.add('System Admin');
    Object.keys(hier.byCode).forEach(c => {
      const e = hier.byCode[c];
      if (e.Active === 'Y' && privilegedRoles.has(e.Role)) codes.add(c);
    });
    return Array.from(codes);
  }

  async function fetchPublicKeys_(codes) {
    const map = {};
    await Promise.all(codes.map(async c => {
      try {
        const snap = await db.collection('userKeys').doc(String(c)).get();
        if (snap.exists && snap.data().publicKeyJwk) map[String(c)] = snap.data().publicKeyJwk;
      } catch (e) { /* ignore missing keys */ }
    }));
    return map;
  }

  // Exact permission rules matching Appscript_Backend.gs
  function tmCanSee_(a, t) {
    if (a.admin || a.headOffice) return true;
    const to = String(t.AssignedTo || ''), by = String(t.AssignedBy || '');
    return to === a.code || by === a.code || a.sub.has(to);
  }

  function tmCanUpdate_(a, t) {
    const to = String(t.AssignedTo || '');
    return a.admin || to === a.code || String(t.AssignedBy || '') === a.code || a.sub.has(to);
  }

  function tmCanManage_(a, t) {
    if (a.admin) return true;
    const to = String(t.AssignedTo || '');
    if (to === a.code) return false; // Nazim cannot edit details of tasks assigned to himself
    return a.sub.has(to);
  }

  function tmCanDelete_(a, t) {
    if (a.admin) return true;
    const to = String(t.AssignedTo || '');
    if (to === a.code) return false;
    return a.sub.has(to);
  }

  function tmCanRemind_(a, t) {
    if (t.Status === 'Completed') return false;
    const to = String(t.AssignedTo || '');
    if (to === a.code) return false;
    return a.admin || a.sub.has(to) || String(t.AssignedBy || '') === a.code;
  }

  async function tmCanAssign_(user, targetCode) {
    const hier = await tmHierarchy_();
    const target = hier.byCode[String(targetCode)];
    if (!target || target.Active !== 'Y') return false;
    const a = await tmAccess_(user);
    if (a.admin) return true;
    if (String(targetCode) === a.code) return true;
    return a.sub.has(String(targetCode));
  }

  async function tmValidatePerson_(p, existingByCode, minPwLen) {
    const errs = [];
    const rolesList = await tmRoles_();
    const regionsList = await tmRegions_();
    const activeRoles = new Set(rolesList.filter(r => r.Active).map(r => r.Role));
    const activeRegions = new Set(regionsList.filter(r => r.Active).map(r => r.Region));

    const final = {};
    Object.keys(existingByCode).forEach(c => {
      const e = existingByCode[c];
      final[c] = { EmpCode: c, Nazim: e.Nazim || '', Email: e.Email || '', Role: e.Role || '', Region: e.Region || '', Active: e.Active };
    });
    const old = final[p.EmpCode];
    const isNew = !old;
    final[p.EmpCode] = {
      EmpCode: p.EmpCode,
      Nazim: p.Nazim,
      Email: p.Email,
      Role: p.Role,
      Region: p.Region,
      Active: p.Active === undefined ? (old ? old.Active : 'Y') : tmYN_(p.Active)
    };

    if (!p.EmpCode) errs.push('Employee code is required.');
    else if (!/^[A-Za-z0-9._-]{1,30}$/.test(p.EmpCode)) errs.push('Employee code may only use letters, numbers, dot, dash and underscore.');
    if (!p.EmpName) errs.push('Full name is required.');
    if (!activeRoles.has(p.Role)) errs.push(`Role "${p.Role}" does not exist or is switched off.`);
    if (!activeRegions.has(p.Region)) errs.push(`Region "${p.Region}" does not exist or is switched off.`);
    if (!tmIsEmail_(p.Email)) errs.push('Email address is not valid.');
    if (p.Nazim && p.Nazim === p.EmpCode) errs.push('A person cannot be their own manager (Nazim).');
    if (p.Nazim && !final[p.Nazim]) errs.push(`Manager code "${p.Nazim}" was not found.`);

    const minLen = Number(minPwLen) || 8;
    if (isNew && !p.Password) errs.push('A password is required for a new person.');
    if (p.Password) {
      if (p.Password.length < Math.min(minLen, 6)) errs.push(`Password must be at least ${Math.min(minLen, 6)} characters.`);
      if (p.Password.toLowerCase() === p.EmpCode.toLowerCase()) errs.push('Password cannot be the same as the employee code.');
    }

    const mail = String(p.Email || '').toLowerCase();
    if (mail) {
      const dup = Object.keys(final).find(c => c !== p.EmpCode && String(final[c].Email).toLowerCase() === mail);
      if (dup) errs.push(`Email is already used by employee ${dup}.`);
    }

    const managers = {};
    Object.keys(final).forEach(c => { managers[c] = final[c].Nazim; });
    const cycle = tmFindCycle_(managers);
    if (cycle) errs.push('Reporting line loop: ' + cycle.join(' -> ') + ' -> ' + cycle[0] + '.');

    const rf = {};
    Object.keys(final).forEach(c => {
      const e = final[c];
      if (e.Active === 'Y' && e.Role === 'Region Finance') {
        (rf[e.Region] = rf[e.Region] || []).push(c);
      }
    });
    Object.keys(rf).forEach(r => {
      if (rf[r].length > 1) errs.push(`Region ${r} already has an active Region Finance (${rf[r].join(', ')}).`);
    });

    return errs;
  }

  // ================= Templates Helpers =================
  function tmParseDesignations_(raw) {
    if (Array.isArray(raw)) {
      const list = raw.map(x => String(x).trim()).filter(Boolean);
      if (list.indexOf(TM_TPL_ALL) >= 0) return { all: true, roles: [] };
      return { all: false, roles: Array.from(new Set(list)) };
    }
    const s = String(raw == null ? '' : raw).trim();
    if (!s) return { all: false, roles: [] };
    if (s === TM_TPL_ALL) return { all: true, roles: [] };
    let list = null;
    try { const j = JSON.parse(s); if (Array.isArray(j)) list = j; } catch (e) { /* ignore */ }
    if (!list) list = s.split(',');
    list = list.map(x => String(x).trim()).filter(Boolean);
    if (list.indexOf(TM_TPL_ALL) >= 0) return { all: true, roles: [] };
    return { all: false, roles: Array.from(new Set(list)) };
  }

  function tmTemplateAllows_(tpl, role) {
    return !!tpl.active && (!!tpl.all || !tpl.roles.length || tpl.roles.indexOf(String(role || '')) >= 0);
  }

  async function tmTemplates_() {
    const snap = await db.collection('taskTemplates').get();
    const list = [];
    snap.forEach(d => {
      const r = d.data() || {};
      const id = String(r.TemplateID || d.id || '').trim();
      const title = String(r.Title || '').trim();
      if (!id || !title) return;
      const dsg = r.All !== undefined
        ? { all: !!r.All, roles: Array.isArray(r.Roles) ? r.Roles : [] }
        : tmParseDesignations_(r.Designations);
      const steps = Array.isArray(r.Checklist)
        ? r.Checklist.map(x => String(x).trim()).filter(Boolean)
        : String(r.Checklist || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean);
      list.push({
        id,
        title,
        description: String(r.Description || ''),
        checklist: steps,
        all: dsg.all,
        roles: dsg.roles,
        active: tmYes_(r.Active),
        updated: tmStamp_(r.UpdatedAt)
      });
    });
    return list.sort((a, b) => a.title.localeCompare(b.title));
  }

  // ================= Checklists & Decryption =================
  async function tmChecklistFor_(taskIds, taskMap, viewerCode, isPrivileged) {
    if (!taskIds.length) return {};
    const map = {};
    taskIds.forEach(id => { map[String(id)] = []; });

    const docs = [];
    if (isPrivileged) {
      const chunks = [];
      for (let i = 0; i < taskIds.length; i += 30) {
        chunks.push(taskIds.slice(i, i + 30));
      }
      for (const chunk of chunks) {
        const snap = await db.collection('checklist').where('TaskID', 'in', chunk).get();
        snap.forEach(d => docs.push(d));
      }
    } else {
      // Query by WatcherCodes so Firestore security rules statically verify access
      const snap = await db.collection('checklist').where('WatcherCodes', 'array-contains', viewerCode).get();
      snap.forEach(d => {
        if (map[String(d.data().TaskID)]) docs.push(d);
      });
    }

    const dekCache = {};
    for (const d of docs) {
      const x = d.data();
      const tid = String(x.TaskID);
      if (!map[tid]) continue;

      let text = String(x.Text || '');
      if (x.IsConfidential && x.TextEnc && window.CryptoVault && window.CryptoVault.isUnlocked(viewerCode)) {
        try {
          const parentTask = taskMap && taskMap[tid];
          if (parentTask && parentTask.KeyEnvelopes) {
            if (!Object.prototype.hasOwnProperty.call(dekCache, tid)) {
              dekCache[tid] = await window.CryptoVault.unwrapDekFromEnvelopes(parentTask.KeyEnvelopes, viewerCode);
            }
            if (dekCache[tid]) text = await window.CryptoVault.decryptText(dekCache[tid], x.TextEnc);
          }
        } catch (e) {
          text = '[Encrypted Step]';
        }
      }

      map[tid].push({
        id: String(x.ItemID || d.id),
        text,
        done: tmYes_(x.IsDone),
        order: Number(x.SortOrder) || 0
      });
    }

    Object.keys(map).forEach(k => map[k].sort((a, b) => a.order - b.order));
    return map;
  }

  async function tmShapeTask_(t, a, checklist, byCode) {
    const items = checklist[String(t.TaskID)] || [];
    const over = tmOverdue_(t.DueDate, t.Status);
    const assignedTo = byCode[String(t.AssignedTo)] || {};
    const selfAssigned = String(t.AssignedBy) === String(t.AssignedTo);
    const byName = (byCode[String(t.AssignedBy)] || {}).EmpName || String(t.AssignedBy);
    const toName = (byCode[String(t.AssignedTo)] || {}).EmpName || String(t.AssignedTo);

    let title = String(t.Title || '');
    let description = String(t.Description || '');
    let decryptLocked = false;

    if (t.IsConfidential) {
      if (window.CryptoVault && window.CryptoVault.isUnlocked(a.code) && t.KeyEnvelopes) {
        try {
          const dek = await window.CryptoVault.unwrapDekFromEnvelopes(t.KeyEnvelopes, a.code);
          if (dek) {
            if (t.TitleEnc) title = await window.CryptoVault.decryptText(dek, t.TitleEnc);
            if (t.DescriptionEnc) description = await window.CryptoVault.decryptText(dek, t.DescriptionEnc);
          } else {
            decryptLocked = true;
          }
        } catch (e) {
          decryptLocked = true;
        }
      } else {
        decryptLocked = true;
      }
    }

    return {
      TaskID: String(t.TaskID),
      Title: title,
      Description: description,
      IsConfidential: !!t.IsConfidential,
      DecryptLocked: decryptLocked,
      FileCount: Number(t.FileCount) || 0,
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

  // ================= Task Fetching Helper =================
  async function tmFetchVisibleTasks_(access, scope) {
    const taskMap = {};
    if (scope === 'mine') {
      const snap = await db.collection('tasks').where('AssignedTo', '==', access.code).get();
      snap.forEach(d => { taskMap[d.id] = Object.assign({ id: d.id }, d.data()); });
    } else if (access.admin || access.headOffice) {
      const snap = await db.collection('tasks').get();
      snap.forEach(d => { taskMap[d.id] = Object.assign({ id: d.id }, d.data()); });
    } else {
      const queries = [
        db.collection('tasks').where('WatcherCodes', 'array-contains', access.code).get(),
        db.collection('tasks').where('AssignedTo', '==', access.code).get(),
        db.collection('tasks').where('AssignedBy', '==', access.code).get()
      ];
      const snaps = await Promise.all(queries);
      snaps.forEach(s => s.forEach(d => { taskMap[d.id] = Object.assign({ id: d.id }, d.data()); }));
    }
    return Object.values(taskMap);
  }

  // ================= Secure Email & Digest Engine =================
  async function tmSendEmail_(to, subject, htmlBody, textBody) {
    const cfg = window.EMAIL_CONFIG || {};
    if (!cfg.appsScriptRelayUrl || !fbAuth || !fbAuth.currentUser) {
      return { ok: false, error: 'Email relay not configured or user not signed in.' };
    }
    try {
      const idToken = await fbAuth.currentUser.getIdToken();
      await fetch(cfg.appsScriptRelayUrl, {
        method: 'POST',
        mode: 'no-cors',
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        body: JSON.stringify({
          to,
          subject,
          html: htmlBody,
          text: textBody,
          idToken
        })
      });
      return { ok: true };
    } catch (e) {
      return { ok: false, error: e && e.message ? e.message : 'Mail relay error' };
    }
  }

  function tmSafeTaskTitleForEmail_(t) {
    return t.IsConfidential ? `[Confidential Task ${t.TaskID}]` : String(t.Title || '');
  }

  function tmMailShell_(cfg, bodyHtml, intro) {
    const app = tmEscape_(cfg.APP_NAME || 'Task Management');
    const greeting = tmEscape_(cfg.EMAIL_GREETING || TM_DEFAULTS.EMAIL_GREETING);
    const signOff = tmEscape_(cfg.EMAIL_SIGN_OFF || TM_DEFAULTS.EMAIL_SIGN_OFF);
    const appUrl = (typeof window !== 'undefined' && window.location && /^https?:/.test(window.location.href))
      ? window.location.href.split('#')[0].split('?')[0] : '';
    const introHtml = intro ? (intro.trim().startsWith('<p') ? intro : '<p>' + tmEscape_(intro) + '</p>') : '';
    return '<div style="font-family:Segoe UI,Arial,sans-serif;font-size:14px;line-height:1.5">' +
      '<p>' + greeting + '</p>' +
      introHtml +
      bodyHtml +
      (appUrl ? '<p><a href="' + tmEscape_(appUrl) + '">Open ' + app + '</a></p>' : '') +
      '<p>' + signOff + '</p></div>';
  }

  function tmDigestContent_(type, tasks, byCode, cfg) {
    const isManagerGrouped = type === 'MANAGER_TASK_DIGEST' || type === 'ESCALATION_DIGEST';
    const dirName = c => (byCode[String(c)] && byCode[String(c)].EmpName) || String(c || '');
    const rows = tasks.map(t => ({
      t,
      over: tmOverdue_(t.DueDate, t.Status),
      due: t.DueDate ? tmDayKey_(tmAsDate_(t.DueDate)) : '9999'
    })).sort((a, b) => isManagerGrouped
      ? dirName(a.t.AssignedTo).localeCompare(dirName(b.t.AssignedTo)) || (Number(b.over) - Number(a.over)) || a.due.localeCompare(b.due)
      : (Number(b.over) - Number(a.over)) || a.due.localeCompare(b.due));

    const title = type === 'ESCALATION_DIGEST'
      ? 'Overdue tasks in your team'
      : type === 'MANAGER_TASK_DIGEST'
        ? 'Pending tasks in your team'
        : type === 'TASK_ASSIGNMENT'
          ? (tasks.length > 1 ? tasks.length + ' new tasks assigned' : 'A new task has been assigned to you')
          : 'Your pending tasks';

    const thead = '<tr><th align="left" style="padding:8px;border-bottom:2px solid #a0a6ab">Task</th><th align="left" style="padding:8px;border-bottom:2px solid #a0a6ab">Status</th><th align="left" style="padding:8px;border-bottom:2px solid #a0a6ab">Due</th></tr>';
    const greeting = cfg.EMAIL_GREETING || TM_DEFAULTS.EMAIL_GREETING;
    const signOff = cfg.EMAIL_SIGN_OFF || TM_DEFAULTS.EMAIL_SIGN_OFF;

    if (isManagerGrouped) {
      const grouped = {};
      rows.forEach(x => { const c = String(x.t.AssignedTo); (grouped[c] = grouped[c] || []).push(x); });
      const people = Object.keys(grouped).map(code => {
        const e = byCode[code] || {};
        return { code, name: String(e.EmpName || code), email: String(e.Email || ''), tasks: grouped[code] };
      }).sort((a, b) => a.name.localeCompare(b.name) || a.code.localeCompare(b.code));

      let bodyRows = '', textRows = '';
      for (const person of people) {
        bodyRows += '<tr><td colspan="3" style="padding:14px 8px 6px;border-bottom:1px solid #a0a6ab"><b>' +
          tmEscape_(person.name) + '</b> &nbsp;' + tmEscape_(person.code) + (person.email ? ' &nbsp;' + tmEscape_(person.email) : '') + '</td></tr>';
        person.tasks.forEach((x, i) => {
          const dueStr = x.due === '9999' ? 'No date' : x.due;
          const dueHtml = x.over ? '<span style="color:#d93025;font-weight:700">' + tmEscape_(dueStr) + ' (Overdue)</span>' : tmEscape_(dueStr);
          const safeTitle = tmSafeTaskTitleForEmail_(x.t);
          bodyRows += '<tr><td style="padding:6px 8px">' + (i + 1) + '. ' + tmEscape_(safeTitle) + '</td><td style="padding:6px 8px">' + tmEscape_(x.t.Status) + '</td><td style="padding:6px 8px">' + dueHtml + '</td></tr>';
        });
        textRows += `${person.name} (${person.code}): ` + person.tasks.map((x, i) => `${i + 1}. ${tmSafeTaskTitleForEmail_(x.t)} [${x.t.Status}]`).join('; ') + '\n';
      }
      const intro = type === 'ESCALATION_DIGEST'
        ? 'Here is an update on overdue work assigned to your team.'
        : 'Here are the open tasks in your team, grouped by employee.';
      const table = '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%">' + thead + bodyRows + '</table>';
      return {
        title,
        text: `${greeting}\n\n${title}\n\n${intro}\n\n${textRows}\n${signOff}`,
        html: tmMailShell_(cfg, table, intro)
      };
    }

    let bodyRows = '', textRows = '';
    rows.forEach((x, i) => {
      const dueStr = x.due === '9999' ? 'No date' : x.due;
      const dueHtml = x.over ? '<span style="color:#d93025;font-weight:700">' + tmEscape_(dueStr) + ' (Overdue)</span>' : tmEscape_(dueStr);
      const safeTitle = tmSafeTaskTitleForEmail_(x.t);
      bodyRows += '<tr><td style="padding:6px 8px 0"><b>' + (i + 1) + '. ' + tmEscape_(safeTitle) + '</b></td><td style="padding:6px 8px 0">' + tmEscape_(x.t.Status) + '</td><td style="padding:6px 8px 0">' + dueHtml + '</td></tr>';
      if (!x.t.IsConfidential && x.t.Description) {
        bodyRows += '<tr><td colspan="3" style="padding:0 8px 8px 26px;opacity:.75">' + tmEscape_(x.t.Description).replace(/\n/g, '<br>') + '</td></tr>';
      }
      textRows += `${i + 1}. ${x.over ? 'OVERDUE: ' : ''}${safeTitle} — ${x.t.Status} — due ${dueStr}\n`;
    });
    const intro = type === 'TASK_ASSIGNMENT'
      ? (tasks.length > 1 ? tasks.length + ' new tasks have been assigned to you. Review the details below.' : 'A new task has been assigned to you. Review the details below.')
      : 'Here is your current list of open work.';
    const table = '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%">' + thead + bodyRows + '</table>';
    return {
      title,
      text: `${greeting}\n\n${title}\n\n${intro}\n\n${textRows}\n${signOff}`,
      html: tmMailShell_(cfg, table, intro)
    };
  }

  async function tmBumpReminders_(taskIds) {
    const ids = Array.from(new Set([].concat(taskIds).join(',').split(',').filter(Boolean)));
    if (!ids.length) return;
    const now = new Date();
    await Promise.all(ids.map(async id => {
      try {
        await db.collection('tasks').doc(id).update({
          LastReminderAt: now,
          ReminderCount: firebase.firestore.FieldValue.increment(1)
        });
      } catch (e) { /* ignore deleted tasks */ }
    }));
  }

  async function tmLogAndSendMail_(type, taskIds, toEmp, subject, html, text) {
    const now = new Date();
    if (!toEmp || !tmIsEmail_(toEmp.Email)) {
      return { ok: false, queued: false, error: 'Recipient has no valid email address.' };
    }
    const res = await tmSendEmail_(toEmp.Email, subject, html, text);
    const result = res.ok ? 'SENT' : 'FAILED';
    await db.collection('mailLog').add({
      Timestamp: now,
      DayKey: tmDayKey_(now),
      Type: type,
      ToEmpCode: toEmp.EmpCode || '',
      ToEmail: toEmp.Email,
      Subject: subject,
      RecipientCount: 1,
      Result: result,
      Error: res.error || ''
    }).catch(() => {});

    if (res.ok) {
      if (type !== 'REOPEN_NOTICE' && taskIds && taskIds.length) {
        await tmBumpReminders_(taskIds);
      }
      return { ok: true, sent: true, queued: false };
    }

    await db.collection('mailQueue').add({
      QueueID: tmId_('MAIL'),
      Type: type,
      TaskID: [].concat(taskIds || []).join(','),
      ToEmpCode: toEmp.EmpCode || '',
      ToEmail: toEmp.Email,
      Subject: subject,
      BodyHtml: html,
      BodyText: text,
      CreatedAt: now,
      Status: 'QUEUED',
      Attempts: 1,
      LastError: res.error || 'Relay unavailable'
    }).catch(() => {});
    return { ok: false, queued: true, error: res.error };
  }

  async function tmMailReopen_(task, toEmp, actor, remark, byCode) {
    const cfg = await tmConfig_();
    const safeTitle = tmSafeTaskTitleForEmail_(task);
    const title = 'Task reopened: ' + safeTitle;
    const actorName = actor.EmpName || (byCode[actor.EmpCode] && byCode[actor.EmpCode].EmpName) || actor.EmpCode;
    const text = `${cfg.EMAIL_GREETING}\n\nA task has been reopened.\n\nTask: ${safeTitle}\nCurrent status: ${task.Status}\nReopened by: ${actorName}\nReason: ${remark}\n\n${cfg.EMAIL_SIGN_OFF}`;
    const table = '<table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;width:100%">' +
      `<tr><td style="padding:8px;border-bottom:1px solid #a0a6ab;width:30%"><b>Task</b></td><td style="padding:8px;border-bottom:1px solid #a0a6ab">${tmEscape_(safeTitle)}</td></tr>` +
      `<tr><td style="padding:8px;border-bottom:1px solid #a0a6ab;width:30%"><b>Current status</b></td><td style="padding:8px;border-bottom:1px solid #a0a6ab">${tmEscape_(task.Status)}</td></tr>` +
      `<tr><td style="padding:8px;border-bottom:1px solid #a0a6ab;width:30%"><b>Reopened by</b></td><td style="padding:8px;border-bottom:1px solid #a0a6ab">${tmEscape_(actorName)}</td></tr>` +
      `<tr><td style="padding:8px;border-bottom:1px solid #a0a6ab;width:30%"><b>Reason</b></td><td style="padding:8px;border-bottom:1px solid #a0a6ab"><span style="white-space:pre-wrap">${tmEscape_(remark)}</span></td></tr>` +
      '</table>';
    return tmLogAndSendMail_('REOPEN_NOTICE', [task.TaskID], toEmp, title, tmMailShell_(cfg, table, 'A task has been reopened. Please review the reason and continue work on it.'), text);
  }

  async function tmMailStatusSummary_() {
    const today = tmDayKey_(new Date());
    let sentToday = 0, scheduledSent = 0, manualSent = 0, failedToday = 0;
    try {
      const logSnap = await db.collection('mailLog').where('DayKey', '==', today).get();
      logSnap.forEach(d => {
        const x = d.data();
        if (x.Result === 'SENT') {
          const n = Number(x.RecipientCount) || 1;
          sentToday += n;
          if (['ASSIGNMENT', 'REOPEN_NOTICE', 'USER_TASK_DIGEST', 'MANAGER_TASK_DIGEST', 'EMPLOYEE_TASK_DIGEST'].indexOf(String(x.Type)) >= 0) {
            manualSent += n;
          } else {
            scheduledSent += n;
          }
        } else {
          failedToday++;
        }
      });
    } catch (e) { /* ignore */ }

    let queued = 0, quotaBlocked = 0;
    try {
      const qSnap = await db.collection('mailQueue').get();
      qSnap.forEach(d => {
        const x = d.data();
        if (x.Status === 'QUEUED') queued++;
        if (x.Status === 'FAILED' && /quota|limit|too many/i.test(String(x.LastError || ''))) quotaBlocked++;
      });
    } catch (e) { /* ignore */ }

    const dailyLimit = 100;
    const remaining = Math.max(0, dailyLimit - sentToday);
    return {
      sentToday,
      remaining,
      queued,
      scheduledSent,
      manualSent,
      failedToday,
      scheduledLeft: remaining,
      quotaBlocked
    };
  }

  // ================= Public API Implementation =================
  const Backend = {
    // 1. Login (Real Firebase Auth + seamless legacy migration + CryptoVault unlock)
    apiLogin: async function (identifier, password) {
      if (!initFirebase()) {
        return { ok: false, error: 'Firebase is not configured yet. Please open firebase-config.js and add your project keys.' };
      }
      const id = String(identifier || '').trim();
      const pw = String(password || '');
      if (!id || !pw) return { ok: false, error: 'Please enter your Employee Code / Email and Password.' };

      if (fbAuth.currentUser && fbAuth.currentUser.isAnonymous) {
        await fbAuth.signOut().catch(() => {});
      }

      const isEmailLogin = id.indexOf('@') >= 0;
      const upperCode = id.toUpperCase();
      let email = isEmailLogin ? id.toLowerCase() : '';
      let migrated = false;

      if (!isEmailLogin) {
        try {
          const lookSnap = await db.collection('authLookup').doc(upperCode).get();
          if (lookSnap.exists) {
            email = String(lookSnap.data().email || '').toLowerCase();
            migrated = !!lookSnap.data().migrated;
          }
        } catch (e) { /* ignore */ }
      }

      let fbUser = null;
      if (email) {
        try {
          const cred = await fbAuth.signInWithEmailAndPassword(email, pw);
          fbUser = cred.user;
        } catch (err) {
          if (err && (err.code === 'auth/operation-not-allowed' || err.code === 'auth/operation-not-supported-in-this-environment' || err.code === 'auth/too-many-requests')) {
            return { ok: false, error: mapAuthError_(err) };
          }
          if (migrated) return { ok: false, error: mapAuthError_(err) };
        }
      }

      if (!fbUser) {
        let legacyDoc = null;
        if (!isEmailLogin) {
          try {
            const snap = await db.collection('employees').doc(upperCode).get();
            if (snap.exists) legacyDoc = snap.data();
          } catch (e) { /* Permission denied means already migrated */ }
        }

        if (legacyDoc && !legacyDoc.AuthUid) {
          if (!tmYes_(legacyDoc.Active)) {
            return { ok: false, error: 'This account is not active. Please contact your administrator.' };
          }
          const salt = legacyDoc.Salt || '';
          const targetHash = legacyDoc.PasswordHash || '';
          const testHash = await sha256(pw + salt);
          const legacyMatch = (targetHash && safeEqual(targetHash, testHash)) ||
            (legacyDoc.Password != null && safeEqual(legacyDoc.Password, pw));

          if (!legacyMatch) return { ok: false, error: 'Invalid Employee Code / Email or password.' };

          const targetEmail = authEmailFor_(legacyDoc.EmpCode, legacyDoc.Email);
          try {
            const cred = await fbAuth.createUserWithEmailAndPassword(targetEmail, pw);
            fbUser = cred.user;
          } catch (createErr) {
            if (createErr && createErr.code === 'auth/email-already-in-use') {
              try {
                const cred2 = await fbAuth.signInWithEmailAndPassword(targetEmail, pw);
                fbUser = cred2.user;
              } catch (e2) { return { ok: false, error: mapAuthError_(e2) }; }
            } else {
              return { ok: false, error: mapAuthError_(createErr) };
            }
          }

          const seedRole = [{
            Role: legacyDoc.Role || 'Employee',
            IsAdmin: legacyDoc.Role === 'Admin' || legacyDoc.Role === 'System Admin',
            IsHeadOffice: legacyDoc.Role === 'Admin' || legacyDoc.Role === 'System Admin',
            Active: true
          }];
          await syncUserMapping_(fbUser.uid, Object.assign({}, legacyDoc, { Active: tmYN_(legacyDoc.Active) }), seedRole, targetEmail);
          await db.collection('employees').doc(legacyDoc.EmpCode).update({
            AuthUid: fbUser.uid,
            AuthEmail: targetEmail,
            Active: tmYN_(legacyDoc.Active),
            SessionVersion: String(legacyDoc.SessionVersion || '1'),
            PasswordHash: firebase.firestore.FieldValue.delete(),
            Salt: firebase.firestore.FieldValue.delete(),
            Password: firebase.firestore.FieldValue.delete()
          });
          await tmEnsureSeedLists_().catch(() => {});
          memoClear();
          const roles = await tmRoles_().catch(() => seedRole);
          const matchedRole = roles.find(x => x.Role === (legacyDoc.Role || 'Employee') && x.Active);
          if (matchedRole && (!!matchedRole.IsHeadOffice !== seedRole[0].IsHeadOffice || !!matchedRole.IsAdmin !== seedRole[0].IsAdmin)) {
            await syncUserMapping_(fbUser.uid, Object.assign({}, legacyDoc, { Active: tmYN_(legacyDoc.Active) }), roles, targetEmail).catch(() => {});
          }
        } else if ((upperCode === 'ADMIN' || email === 'admin@taskmanagement.local') && pw === 'admin123') {
          let adminExists = false;
          try {
            const checkAdmin = await db.collection('employees').doc('ADMIN').get();
            adminExists = checkAdmin.exists;
          } catch (e) { adminExists = true; }
          if (adminExists) return { ok: false, error: 'Invalid Employee Code / Email or password.' };

          try {
            const cred = await fbAuth.createUserWithEmailAndPassword('admin@taskmanagement.local', pw);
            fbUser = cred.user;
          } catch (createErr) {
            if (createErr && createErr.code === 'auth/email-already-in-use') {
              try {
                const cred2 = await fbAuth.signInWithEmailAndPassword('admin@taskmanagement.local', pw);
                fbUser = cred2.user;
              } catch (e2) { return { ok: false, error: mapAuthError_(e2) }; }
            } else {
              return { ok: false, error: mapAuthError_(createErr) };
            }
          }
          const adminRecord = {
            EmpCode: 'ADMIN',
            EmpName: 'System Administrator',
            Nazim: '',
            Division: 'Head Office',
            Region: 'Mumbai',
            Role: 'Admin',
            Email: 'admin@taskmanagement.local',
            AuthEmail: 'admin@taskmanagement.local',
            AuthUid: fbUser.uid,
            MustChangePassword: 'N',
            Active: 'Y',
            SessionVersion: '1',
            CreatedAt: new Date()
          };
          await db.collection('employees').doc('ADMIN').set(adminRecord);
          await syncUserMapping_(fbUser.uid, adminRecord, [{ Role: 'Admin', IsAdmin: true, IsHeadOffice: true, Active: true }], 'admin@taskmanagement.local');
          await tmEnsureSeedLists_();
        } else if (isEmailLogin) {
          return { ok: false, error: 'Invalid credentials, or if this is your first login after the security update, sign in once with your Employee Code (e.g. ADMIN).' };
        } else {
          return { ok: false, error: 'Invalid Employee Code / Email or password.' };
        }
      }

      const userSnap = await db.collection('users').doc(fbUser.uid).get();
      if (!userSnap.exists || userSnap.data().Active !== 'Y') {
        await fbAuth.signOut().catch(() => {});
        return { ok: false, error: 'This account is not active. Please contact your administrator.' };
      }

      const empCode = userSnap.data().EmpCode;
      if (window.CryptoVault) {
        try { await window.CryptoVault.initForUser(db, empCode, pw); }
        catch (vaultErr) { console.warn('CryptoVault init warning:', vaultErr); }
      }

      await db.collection('employees').doc(empCode).update({ LastLogin: new Date() }).catch(() => {});
      await tmAudit_(empCode, 'LOGIN', '', {});
      memoClear();
      const token = 'fb:' + fbUser.uid;
      const boot = await Backend.apiBootstrap(token);
      return Object.assign({ ok: true, token }, boot);
    },

    // 2. Bootstrap
    apiBootstrap: async function (token) {
      const { user } = await tmAuth_(token);
      const cfg = await tmConfig_();
      const hier = await tmHierarchy_();
      const me = hier.byCode[String(user.EmpCode)] || user;
      const roles = await tmRoles_();
      const r = roles.find(x => x.Role === me.Role && x.Active) || {};
      const access = await tmAccess_(me);
      const boss = hier.byCode[me.Nazim] || null;
      const isAdmin = me.Role === 'Admin' || me.Role === 'System Admin' || !!r.IsAdmin;
      const isHeadOffice = !!r.IsHeadOffice || isAdmin;
      const isNazim = (hier.children[me.EmpCode] || []).length > 0;

      const out = {
        today: tmDayKey_(new Date()),
        app: { name: cfg.APP_NAME || 'Task Management', version: TM_VERSION, sessionDays: Number(cfg.SESSION_DAYS) || 30 },
        user: {
          EmpCode: me.EmpCode,
          EmpName: me.EmpName,
          Role: me.Role,
          Region: me.Region,
          Division: me.Division,
          Email: me.Email,
          Nazim: me.Nazim,
          NazimName: boss ? boss.EmpName : '',
          isAdmin,
          isHeadOffice,
          isNazim,
          hasTeam: isAdmin || isHeadOffice || isNazim,
          vaultUnlocked: window.CryptoVault ? window.CryptoVault.isUnlocked(me.EmpCode) : false
        },
        mustChangePassword: false
      };

      const codes = (isAdmin || isHeadOffice)
        ? Object.keys(hier.byCode).filter(c => hier.byCode[c].Active === 'Y')
        : [access.code].concat(Array.from(access.sub));

      const divisions = {}, people = [];
      codes.forEach(c => {
        const e = hier.byCode[c];
        if (!e || e.Active !== 'Y') return;
        if (e.Division) divisions[e.Division] = true;
        const canAssign = isAdmin || c === access.code || access.sub.has(c);
        people.push({ c: e.EmpCode, n: e.EmpName, r: e.Role, g: e.Region, d: e.Division, a: canAssign ? 1 : 0 });
      });
      people.sort((x, y) => x.n.localeCompare(y.n));
      out.people = people;

      const regionsList = await tmRegions_();
      out.lists = {
        regions: regionsList.filter(x => x.Active).map(x => x.Region),
        divisions: Object.keys(divisions).sort(),
        roles: roles.filter(x => x.Active).map(x => x.Role),
        statuses: TM_STATUSES
      };
      if (!out.lists.regions.length) out.lists.regions = TM_REGIONS;

      out.mine = await Backend.apiListTasks(token, { scope: 'mine' });
      out.team = null;
      return out;
    },

    apiUnlockVault: async function (token, password) {
      const { user, fbUser } = await tmAuth_(token);
      if (!password) throw new Error('Enter your password to unlock encrypted items.');
      const cred = firebase.auth.EmailAuthProvider.credential(fbUser.email, password);
      try { await fbUser.reauthenticateWithCredential(cred); }
      catch (e) { throw new Error('Incorrect password.'); }
      if (window.CryptoVault) await window.CryptoVault.initForUser(db, user.EmpCode, password);
      return { ok: true, unlocked: true };
    },

    // 3. List & Export Tasks
    apiListTasks: async function (token, filters) {
      const { user } = await tmAuth_(token);
      filters = filters || {};
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const byCode = hier.byCode;
      const scope = filters.scope === 'team' ? 'team' : 'mine';

      if (scope === 'team' && !access.admin && !access.headOffice && (hier.children[user.EmpCode] || []).length === 0) {
        throw new Error('Team task access is limited to Nazim users.');
      }

      const allTasks = await tmFetchVisibleTasks_(access, scope);
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
      const pageMap = {};
      page.forEach(t => { pageMap[String(t.TaskID)] = t; });
      const checklist = await tmChecklistFor_(page.map(t => t.TaskID), pageMap, access.code, access.admin || access.headOffice);
      const shaped = await Promise.all(page.map(t => tmShapeTask_(t, access, checklist, byCode)));

      return {
        ok: true,
        tasks: shaped,
        total: matched.length,
        counts,
        hasMore: offset + PAGE_SIZE < matched.length,
        nextOffset: offset + PAGE_SIZE
      };
    },

    apiExportTasks: async function (token, filters) {
      const { user } = await tmAuth_(token);
      filters = filters || {};
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const byCode = hier.byCode;
      const scope = filters.scope === 'team' ? 'team' : 'mine';
      const isNazim = (hier.children[user.EmpCode] || []).length > 0;
      if (scope === 'team' && !isNazim && !access.admin && !access.headOffice) {
        throw new Error('Team task export is limited to Nazim users.');
      }

      const allTasks = await tmFetchVisibleTasks_(access, scope);
      const today = tmDayKey_(new Date());
      const search = String(filters.search || '').trim().toLowerCase();
      const emp = String(filters.employee || '').trim().toLowerCase();
      const matched = [];

      allTasks.forEach(t => {
        if (!tmCanSee_(access, t)) return;
        const mine = String(t.AssignedTo) === access.code;
        if (scope === 'mine' ? !mine : mine) return;
        const e = byCode[String(t.AssignedTo)] || {};
        if (filters.location && String(e.Division || t.Division || '') !== filters.location) return;
        if (filters.region && String(t.Region || e.Region || '') !== filters.region) return;
        if (filters.division && String(t.Division || e.Division || '') !== filters.division) return;
        if (filters.role && String(e.Role || '') !== filters.role) return;
        if (emp && String(t.AssignedTo).toLowerCase() !== emp && String(e.EmpName || '').toLowerCase().indexOf(emp) < 0) return;
        if (search && (String(t.Title).toLowerCase() + ' ' + String(t.Description).toLowerCase()).indexOf(search) < 0) return;
        const due = t.DueDate ? tmDayKey_(tmAsDate_(t.DueDate)) : '';
        if (filters.dueFrom && (!due || due < filters.dueFrom)) return;
        if (filters.dueTo && (!due || due > filters.dueTo)) return;
        const over = t.Status !== 'Completed' && due && due < today;
        if (filters.status && (filters.status === 'Overdue' ? !over : String(t.Status) !== filters.status)) return;
        if ((filters.overdue === true || filters.overdue === 'true') && !over) return;
        matched.push(t);
      });

      if (scope === 'team') {
        matched.sort((x, y) => {
          const xn = String((byCode[String(x.AssignedTo)] || {}).EmpName || x.AssignedTo);
          const yn = String((byCode[String(y.AssignedTo)] || {}).EmpName || y.AssignedTo);
          return xn.localeCompare(yn) || String(x.Title).localeCompare(String(y.Title)) || tmSortKey_(x).localeCompare(tmSortKey_(y));
        });
      } else {
        matched.sort((x, y) => tmSortKey_(x).localeCompare(tmSortKey_(y)) || String(x.Title).localeCompare(String(y.Title)));
      }

      const map = {};
      matched.forEach(t => { map[String(t.TaskID)] = t; });
      const checklist = await tmChecklistFor_(matched.map(t => t.TaskID), map, access.code, access.admin || access.headOffice);
      const shapedList = await Promise.all(matched.map(t => tmShapeTask_(t, access, checklist, byCode)));

      const headers = [
        'Task ID', 'Title', 'Description', 'Assigned To (Name)', 'Assigned To (Code)',
        'Assigned By (Name)', 'Assigned By (Code)', 'Region', 'Division', 'Due Date',
        'Status', 'Checklist Total', 'Checklist Completed', 'Created At', 'Completed At'
      ];
      const csvEsc = v => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
      const rows = [headers.map(csvEsc).join(',')];

      shapedList.forEach(s => {
        rows.push([
          s.TaskID, s.Title, s.Description || '', s.AssignedToName, s.AssignedTo,
          s.AssignedByName, s.AssignedBy, s.Region, s.Division, s.Due,
          s.Status, s.Total || 0, s.Done || 0, s.Created, s.Completed
        ].map(csvEsc).join(','));
      });

      return {
        ok: true,
        csv: '\uFEFF' + rows.join('\r\n'),
        filename: `tasks_${scope}_${tmDayKey_(new Date())}.csv`,
        count: matched.length
      };
    },

    // 4. Create Task (Deduplication + Templates + End-to-End Confidential Encryption)
    apiCreateTask: async function (token, data) {
      const { user } = await tmAuth_(token);
      data = data || {};
      const requestId = String(data.requestId || '');
      if (requestId) {
        if (!/^[A-Za-z0-9_-]{16,100}$/.test(requestId)) {
          throw new Error('Invalid task submission reference. Refresh the task form and try again.');
        }
        const dedupKey = user.EmpCode + ':' + requestId;
        if (_CREATE_DEDUP[dedupKey]) return _CREATE_DEDUP[dedupKey];
      }

      const hier = await tmHierarchy_();
      const directory = hier.byCode;
      const now = new Date();
      const isConfidential = !!data.confidential;

      if (isConfidential && (!window.CryptoVault || !window.CryptoVault.isUnlocked(user.EmpCode))) {
        throw new Error('Encryption vault is locked. Unlock your vault or sign in again to create confidential tasks.');
      }

      const uniq = list => Array.from(new Set((Array.isArray(list) ? list : []).map(x => String(x).trim()).filter(Boolean)));
      const rawTasks = Array.isArray(data.tasks) ? data.tasks : (data.title ? [data.title] : []);
      const defaultDue = tmParseDay_(data.dueDate) || tmAsDate_(data.dueDate) || new Date();
      const defaultNote = tmClip_(data.description, 2000);
      const defaultSteps = (Array.isArray(data.checklist) ? data.checklist : []).map(x => tmClip_(x, 200)).filter(Boolean).slice(0, 40);

      const parsedTasks = [];
      rawTasks.forEach(item => {
        if (!item) return;
        if (typeof item === 'object') {
          const title = tmClip_(item.title || item.Title, 200);
          if (!title) return;
          const due = tmParseDay_(item.dueDate || item.DueDate || item.due) || tmAsDate_(item.dueDate) || defaultDue;
          const desc = item.description !== undefined ? tmClip_(item.description, 2000) : defaultNote;
          const stepsRaw = Array.isArray(item.checklist) ? item.checklist : (Array.isArray(item.steps) ? item.steps : defaultSteps);
          const steps = stepsRaw.map(x => tmClip_(x, 200)).filter(Boolean).slice(0, 40);
          parsedTasks.push({ title, due, description: desc, steps });
        } else {
          const title = tmClip_(item, 200);
          if (title) parsedTasks.push({ title, due: defaultDue, description: defaultNote, steps: defaultSteps });
        }
      });

      const typedTargets = uniq(Array.isArray(data.assignedTo) ? data.assignedTo : [data.assignedTo || user.EmpCode]);
      const groups = Array.isArray(data.templateGroups) ? data.templateGroups : [];
      if (parsedTasks.length > 40) throw new Error('You can create at most 40 tasks at once.');
      if (parsedTasks.length && (!typedTargets.length || typedTargets.length > 100)) throw new Error('Choose between 1 and 100 employees.');
      if (groups.length > 50) throw new Error('Too many designation groups in one save.');

      const wanted = new Set(parsedTasks.length ? typedTargets : []);
      groups.forEach(g => { if (uniq(g && g.templateIds).length) uniq(g && g.assignedTo).forEach(c => wanted.add(c)); });
      for (const target of wanted) {
        if (!(await tmCanAssign_(user, target))) throw new Error(`You cannot assign a task to employee ${target}.`);
      }

      const specs = [];
      typedTargets.forEach(target => {
        if (wanted.has(target)) {
          parsedTasks.forEach(pt => {
            specs.push({ target, title: pt.title, due: pt.due, description: pt.description, steps: pt.steps, templateId: '' });
          });
        }
      });

      if (groups.length) {
        const allTpls = await tmTemplates_();
        const byId = {};
        allTpls.forEach(t => { byId[t.id] = t; });
        const seen = {};
        groups.forEach(g => {
          const ids = uniq(g && g.templateIds), to = uniq(g && g.assignedTo);
          if (ids.length > 40 || to.length > 100) throw new Error('Too many templates or employees in one group.');
          ids.forEach(id => {
            const t = byId[id];
            if (!t || !t.active) throw new Error('A selected task template is no longer available. Refresh and try again.');
            to.forEach(target => {
              const person = directory[target];
              if (!person || !tmTemplateAllows_(t, person.Role)) {
                throw new Error(`The template "${t.title}" is not available for ${person ? person.EmpName : target} (${person ? person.Role : ''}).`);
              }
              const key = target + '|' + id;
              if (seen[key]) return;
              seen[key] = true;
              specs.push({
                target,
                title: t.title,
                due: defaultDue,
                description: [t.description, defaultNote].filter(Boolean).join('\n\n').slice(0, 2000),
                steps: t.checklist.slice(0, 40),
                templateId: id
              });
            });
          });
        });
      }

      if (!specs.length) throw new Error('Please add at least one task.');
      if (specs.length > 200) throw new Error('A single save can create at most 200 tasks.');

      const targetKeyCache = {};
      const taskRowsForMail = {};
      const taskIds = [];
      const taskWrites = [];
      const subWrites = [];

      for (const sp of specs) {
        const emp = directory[sp.target] || {};
        const watcherCodes = getWatcherCodes_(sp.target, user.EmpCode, hier);
        const taskId = 'TSK-' + tmDayKey_(now).replace(/-/g, '') + '-' + Math.random().toString(36).slice(2, 8).toUpperCase();
        taskIds.push(taskId);

        let taskData;
        let dek = null;
        if (isConfidential) {
          if (!targetKeyCache[sp.target]) {
            const allowedCodes = await getAllowedKeyCodes_(sp.target, user.EmpCode, hier);
            const jwks = await fetchPublicKeys_(allowedCodes);
            targetKeyCache[sp.target] = { allowedCodes, jwks };
          }
          const { allowedCodes, jwks } = targetKeyCache[sp.target];
          dek = await window.CryptoVault.generateDek();
          const keyEnvelopes = await window.CryptoVault.wrapDekForRecipients(dek, jwks);
          const titleEnc = await window.CryptoVault.encryptText(dek, sp.title);
          const descEnc = sp.description ? await window.CryptoVault.encryptText(dek, sp.description) : null;

          taskData = {
            TaskID: taskId,
            Title: '[Confidential Task]',
            Description: '',
            IsConfidential: true,
            TitleEnc: titleEnc,
            DescriptionEnc: descEnc,
            KeyEnvelopes: keyEnvelopes,
            AllowedCodes: allowedCodes,
            WatcherCodes: watcherCodes,
            AssignedBy: user.EmpCode,
            AssignedTo: sp.target,
            Region: emp.Region || '',
            Division: emp.Division || '',
            DueDate: sp.due || defaultDue,
            Status: 'Pending',
            FileCount: 0,
            CreatedAt: now,
            UpdatedAt: now,
            CompletedAt: null,
            LastReminderAt: null,
            ReminderCount: 0
          };
        } else {
          taskData = {
            TaskID: taskId,
            Title: sp.title,
            Description: sp.description,
            IsConfidential: false,
            WatcherCodes: watcherCodes,
            AssignedBy: user.EmpCode,
            AssignedTo: sp.target,
            Region: emp.Region || '',
            Division: emp.Division || '',
            DueDate: sp.due || defaultDue,
            Status: 'Pending',
            FileCount: 0,
            CreatedAt: now,
            UpdatedAt: now,
            CompletedAt: null,
            LastReminderAt: null,
            ReminderCount: 0
          };
        }

        (taskRowsForMail[sp.target] = taskRowsForMail[sp.target] || []).push(taskData);
        taskWrites.push({ ref: db.collection('tasks').doc(taskId), data: taskData });

        for (let idx = 0; idx < sp.steps.length; idx++) {
          const step = sp.steps[idx];
          const itemId = tmId_('ITM');
          const itemDoc = {
            ItemID: itemId,
            TaskID: taskId,
            Text: isConfidential ? '[Confidential Step]' : step,
            IsConfidential: isConfidential,
            IsDone: 'N',
            DoneAt: null,
            SortOrder: idx + 1,
            WatcherCodes: watcherCodes
          };
          if (isConfidential && dek) itemDoc.TextEnc = await window.CryptoVault.encryptText(dek, step);
          subWrites.push({ ref: db.collection('checklist').doc(itemId), data: itemDoc });
        }

        subWrites.push({
          ref: db.collection('taskHistory').doc(),
          data: {
            Timestamp: now,
            TaskID: taskId,
            ActorEmpCode: user.EmpCode,
            ActorName: user.EmpName,
            Action: 'TASK_CREATED',
            Details: JSON.stringify(sp.templateId ? { assignedTo: sp.target, templateId: sp.templateId, confidential: isConfidential } : { assignedTo: sp.target, confidential: isConfidential }),
            WatcherCodes: watcherCodes
          }
        });
      }

      // Commit tasks FIRST so Firestore rules can verify parent task existence for checklist & history
      for (let i = 0; i < taskWrites.length; i += 450) {
        const b = db.batch();
        taskWrites.slice(i, i + 450).forEach(w => b.set(w.ref, w.data));
        await b.commit();
      }
      for (let i = 0; i < subWrites.length; i += 450) {
        const b = db.batch();
        subWrites.slice(i, i + 450).forEach(w => b.set(w.ref, w.data));
        await b.commit();
      }

      const recipients = Object.keys(taskRowsForMail);
      let mail = null;
      const mailTargets = recipients.filter(t => t !== user.EmpCode);
      if (data.notify && mailTargets.length) {
        const cfg = await tmConfig_();
        let queued = false, errMsg = '';
        for (const target of mailTargets) {
          const person = directory[target];
          if (!person || !tmIsEmail_(person.Email)) continue;
          const owned = taskRowsForMail[target];
          const c = tmDigestContent_('TASK_ASSIGNMENT', owned, directory, cfg);
          const mr = await tmLogAndSendMail_('ASSIGNMENT', owned.map(x => x.TaskID), person, c.title, c.html, c.text);
          if (mr.queued) queued = true;
          if (mr.error && !errMsg) errMsg = mr.error;
        }
        mail = { recipients: mailTargets.length, queued, error: errMsg || undefined };
      }

      const result = { ok: true, taskId: taskIds[0], taskIds, count: taskIds.length, recipients: recipients.length, mail };
      if (requestId) _CREATE_DEDUP[user.EmpCode + ':' + requestId] = result;
      return result;
    },

    // 5. Update Task (Exact permissions + Reopen remark & email)
    apiUpdateTask: async function (token, id, changes) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const docRef = db.collection('tasks').doc(id);
      const snap = await docRef.get();
      if (!snap.exists) throw new Error('Task no longer exists.');
      const task = snap.data();
      if (!tmCanSee_(access, task)) throw new Error('You do not have access to this task.');

      changes = changes || {};
      const now = new Date();
      const updates = { UpdatedAt: now };
      const batch = db.batch();
      const watcherCodes = task.WatcherCodes || getWatcherCodes_(task.AssignedTo, task.AssignedBy, hier);
      const changedFields = [];
      let reopening = false, reopenRemark = '', reopenRecipient = null;

      if (Array.isArray(changes.checklist)) {
        if (!tmCanUpdate_(access, task)) throw new Error('You cannot change the checklist of this task.');
        changes.checklist.forEach(c => {
          if (!c || !c.id) return;
          batch.update(db.collection('checklist').doc(String(c.id)), {
            IsDone: c.done ? 'Y' : 'N',
            DoneAt: c.done ? now : null
          });
        });
        changedFields.push('checklist');
      }

      const nextTitle = changes.title !== undefined ? changes.title : changes.Title;
      const nextDesc = changes.description !== undefined ? changes.description : changes.Description;
      const nextDue = changes.dueDate !== undefined ? changes.dueDate : changes.DueDate;
      const nextAssigned = changes.assignedTo !== undefined ? changes.assignedTo : changes.AssignedTo;

      if (nextTitle !== undefined || nextDesc !== undefined || nextDue !== undefined || nextAssigned !== undefined) {
        if (!tmCanManage_(access, task)) {
          throw new Error('Only a Nazim (for team tasks) or an administrator can edit task details.');
        }
        if (task.IsConfidential) {
          if (!window.CryptoVault || !window.CryptoVault.isUnlocked(user.EmpCode)) {
            throw new Error('Unlock your encryption vault before editing a confidential task.');
          }
          const dek = await window.CryptoVault.unwrapDekFromEnvelopes(task.KeyEnvelopes, user.EmpCode);
          if (!dek) throw new Error('Missing encryption key for this confidential task.');
          if (nextTitle !== undefined) {
            const x = tmClip_(nextTitle, 200);
            if (!x) throw new Error('The title cannot be empty.');
            updates.TitleEnc = await window.CryptoVault.encryptText(dek, x);
            changedFields.push('title');
          }
          if (nextDesc !== undefined) {
            updates.DescriptionEnc = await window.CryptoVault.encryptText(dek, tmClip_(nextDesc, 2000));
            changedFields.push('description');
          }
        } else {
          if (nextTitle !== undefined) {
            const x = tmClip_(nextTitle, 200);
            if (!x) throw new Error('The title cannot be empty.');
            if (x !== String(task.Title)) { updates.Title = x; changedFields.push('title'); }
          }
          if (nextDesc !== undefined) {
            const x = tmClip_(nextDesc, 2000);
            if (x !== String(task.Description || '')) { updates.Description = x; changedFields.push('description'); }
          }
        }
        if (nextDue !== undefined) {
          const d = nextDue ? (tmParseDay_(nextDue) || tmAsDate_(nextDue)) : null;
          if (nextDue && !d) throw new Error('Please choose a valid due date.');
          updates.DueDate = d;
          changedFields.push('due date');
        }
        if (nextAssigned !== undefined && String(nextAssigned) !== String(task.AssignedTo)) {
          const target = String(nextAssigned);
          if (!(await tmCanAssign_(user, target))) throw new Error('You cannot assign this task to that person.');
          const e = hier.byCode[target];
          updates.AssignedTo = e.EmpCode;
          updates.Region = e.Region || '';
          updates.Division = e.Division || '';
          updates.WatcherCodes = getWatcherCodes_(e.EmpCode, task.AssignedBy, hier);
          changedFields.push('assignee');
        }
      }

      const nextStatus = changes.status !== undefined ? changes.status : changes.Status;
      if (nextStatus !== undefined && nextStatus !== task.Status) {
        if (!tmCanUpdate_(access, task)) throw new Error('You cannot change the status of this task.');
        if (TM_STATUSES.indexOf(nextStatus) < 0) throw new Error('Unknown status.');
        reopening = task.Status === 'Completed' && nextStatus !== 'Completed';
        if (reopening) {
          reopenRemark = tmClip_(changes.remark, 1000);
          if (!reopenRemark) throw new Error('A remark is required when reopening a task.');
          const recipientCode = String(updates.AssignedTo || task.AssignedTo);
          reopenRecipient = hier.byCode[recipientCode];
          if (!reopenRecipient || reopenRecipient.Active !== 'Y' || !tmIsEmail_(reopenRecipient.Email)) {
            throw new Error('The active assignee needs a valid email before this task can be reopened.');
          }
        }
        updates.Status = nextStatus;
        updates.CompletedAt = nextStatus === 'Completed' ? now : null;
        if (nextStatus === 'Completed') {
          const checks = (access.admin || access.headOffice)
            ? await db.collection('checklist').where('TaskID', '==', id).get()
            : await db.collection('checklist').where('TaskID', '==', id).where('WatcherCodes', 'array-contains', access.code).get();
          checks.forEach(c => batch.update(c.ref, { IsDone: 'Y', DoneAt: now }));
        }
        batch.set(db.collection('taskHistory').doc(), {
          Timestamp: now,
          TaskID: id,
          ActorEmpCode: user.EmpCode,
          ActorName: user.EmpName,
          Action: reopening ? 'TASK_REOPENED' : 'TASK_STATUS_CHANGED',
          Details: JSON.stringify(reopening ? { status: nextStatus, remark: reopenRemark } : { status: nextStatus }),
          WatcherCodes: updates.WatcherCodes || watcherCodes
        });
      }

      if (changedFields.length) {
        batch.set(db.collection('taskHistory').doc(), {
          Timestamp: now,
          TaskID: id,
          ActorEmpCode: user.EmpCode,
          ActorName: user.EmpName,
          Action: 'TASK_UPDATED',
          Details: JSON.stringify({ fields: changedFields }),
          WatcherCodes: updates.WatcherCodes || watcherCodes
        });
      }

      batch.update(docRef, updates);
      await batch.commit();

      let mail = null;
      if (reopening && reopenRecipient) {
        try {
          const freshTask = Object.assign({}, task, updates);
          mail = await tmMailReopen_(freshTask, reopenRecipient, user, reopenRemark, hier.byCode);
        } catch (e) {
          mail = { error: e.message };
        }
      }
      return { ok: true, mail };
    },

    // 6. Bulk Update Tasks
    apiBulkUpdateTaskStatus: async function (token, ids, status, remark) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const wanted = Array.isArray(ids) ? Array.from(new Set(ids.map(String))) : [];
      if (!wanted.length || wanted.length > 100) throw new Error('Select between 1 and 100 tasks.');
      if (TM_STATUSES.indexOf(status) < 0) throw new Error('Unknown status.');

      const comment = tmClip_(remark, 1000);
      const now = new Date();
      const batch = db.batch();
      let updated = 0;
      const failed = [];
      const reopenMails = [];

      for (const id of wanted) {
        const docRef = db.collection('tasks').doc(id);
        const snap = await docRef.get();
        if (!snap.exists) { failed.push({ id, reason: 'Task no longer exists.' }); continue; }
        const t = snap.data();
        if (!tmCanSee_(access, t) || !tmCanUpdate_(access, t)) { failed.push({ id, reason: 'You cannot update this task.' }); continue; }
        if (String(t.Status) === status) { failed.push({ id, reason: 'Already ' + status + '.' }); continue; }

        const reopening = String(t.Status) === 'Completed' && status !== 'Completed';
        if (reopening && !comment) { failed.push({ id, reason: 'A remark is required when reopening a task.' }); continue; }
        const emp = reopening ? hier.byCode[String(t.AssignedTo)] : null;
        if (reopening && (!emp || emp.Active !== 'Y' || !tmIsEmail_(emp.Email))) {
          failed.push({ id, reason: 'The active assignee needs a valid email before reopening.' });
          continue;
        }

        const updates = { Status: status, UpdatedAt: now, CompletedAt: status === 'Completed' ? now : null };
        batch.update(docRef, updates);
        batch.set(db.collection('taskHistory').doc(), {
          Timestamp: now,
          TaskID: id,
          ActorEmpCode: user.EmpCode,
          ActorName: user.EmpName,
          Action: reopening ? 'TASK_REOPENED' : 'TASK_STATUS_CHANGED',
          Details: JSON.stringify(reopening ? { status, remark: comment } : { status }),
          WatcherCodes: t.WatcherCodes || getWatcherCodes_(t.AssignedTo, t.AssignedBy, hier)
        });
        updated++;
        if (reopening && emp) reopenMails.push({ task: Object.assign({}, t, updates), emp });
      }

      if (updated) await batch.commit();
      for (const rm of reopenMails) {
        const mr = await tmMailReopen_(rm.task, rm.emp, user, comment, hier.byCode);
        if (mr && mr.error) failed.push({ id: rm.task.TaskID, reason: mr.error });
      }
      return {
        ok: true,
        count: updated,
        updated,
        failed,
        message: `${updated} task(s) updated; ${failed.length} item(s) could not be applied.`
      };
    },

    // 7. Delete Task (+ its encrypted attachments)
    apiDeleteTask: async function (token, id) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const docRef = db.collection('tasks').doc(id);
      const snap = await docRef.get();
      if (!snap.exists) return { ok: true };
      const task = snap.data();
      if (!tmCanDelete_(access, task)) throw new Error('Only a Nazim or administrator can delete this task.');

      const batch = db.batch();
      batch.delete(docRef);
      const checks = (access.admin || access.headOffice)
        ? await db.collection('checklist').where('TaskID', '==', id).get()
        : await db.collection('checklist').where('TaskID', '==', id).where('WatcherCodes', 'array-contains', access.code).get();
      checks.forEach(c => batch.delete(c.ref));

      const filesSnap = (access.admin || access.headOffice)
        ? await db.collection('taskFiles').where('TaskID', '==', id).get()
        : await db.collection('taskFiles').where('TaskID', '==', id).where('AllowedCodes', 'array-contains', access.code).get();
      for (const fDoc of filesSnap.docs) {
        const chunksSnap = (access.admin || access.headOffice)
          ? await fDoc.ref.collection('chunks').get()
          : await fDoc.ref.collection('chunks').where('AllowedCodes', 'array-contains', access.code).get();
        chunksSnap.forEach(ch => batch.delete(ch.ref));
        batch.delete(fDoc.ref);
      }

      batch.set(db.collection('taskHistory').doc(), {
        Timestamp: new Date(),
        TaskID: id,
        ActorEmpCode: user.EmpCode,
        ActorName: user.EmpName,
        Action: 'TASK_DELETED',
        Details: JSON.stringify({ title: tmSafeTaskTitleForEmail_(task), assignedTo: task.AssignedTo }),
        WatcherCodes: task.WatcherCodes || [task.AssignedTo, task.AssignedBy]
      });

      await batch.commit();
      return { ok: true, taskId: id };
    },

    // 8. Checklist Management
    apiAddChecklistItem: async function (token, taskId, text) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const taskSnap = await db.collection('tasks').doc(taskId).get();
      if (!taskSnap.exists) throw new Error('Task no longer exists.');
      const task = taskSnap.data();
      if (!tmCanManage_(access, task)) throw new Error('You are not permitted to add checklist steps to this task.');

      const cleanText = tmClip_(text, 200);
      if (!cleanText) throw new Error('Please type the checklist item.');
      const existing = (access.admin || access.headOffice)
        ? await db.collection('checklist').where('TaskID', '==', taskId).get()
        : await db.collection('checklist').where('TaskID', '==', taskId).where('WatcherCodes', 'array-contains', access.code).get();
      if (existing.size >= 40) throw new Error('A task can have at most 40 checklist items.');

      const itemId = tmId_('ITM');
      const item = {
        ItemID: itemId,
        TaskID: taskId,
        Text: task.IsConfidential ? '[Confidential Step]' : cleanText,
        IsConfidential: !!task.IsConfidential,
        IsDone: 'N',
        DoneAt: null,
        SortOrder: existing.size + 1,
        WatcherCodes: task.WatcherCodes || [task.AssignedTo, task.AssignedBy]
      };
      if (task.IsConfidential) {
        if (!window.CryptoVault || !window.CryptoVault.isUnlocked(user.EmpCode)) {
          throw new Error('Unlock your vault to add steps to a confidential task.');
        }
        const dek = await window.CryptoVault.unwrapDekFromEnvelopes(task.KeyEnvelopes, user.EmpCode);
        if (!dek) throw new Error('Missing encryption key for this task.');
        item.TextEnc = await window.CryptoVault.encryptText(dek, cleanText);
      }
      await db.collection('checklist').doc(itemId).set(item);
      await db.collection('tasks').doc(taskId).update({ UpdatedAt: new Date() });
      return { ok: true, item: { id: itemId, text: cleanText, done: false, order: item.SortOrder } };
    },

    apiRemoveChecklistItem: async function (token, taskId, itemId) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const taskSnap = await db.collection('tasks').doc(taskId).get();
      if (taskSnap.exists && !tmCanManage_(access, taskSnap.data())) {
        throw new Error('You are not permitted to remove checklist steps from this task.');
      }
      await db.collection('checklist').doc(itemId).delete();
      return { ok: true };
    },

    // 9. Confidential Encrypted File Attachments
    apiUploadTaskFile: async function (token, taskId, file) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!window.CryptoVault || !window.CryptoVault.isUnlocked(user.EmpCode)) {
        throw new Error('Encryption vault is locked. Please unlock or sign in again to upload confidential files.');
      }
      const taskSnap = await db.collection('tasks').doc(taskId).get();
      if (!taskSnap.exists) throw new Error('Task no longer exists.');
      const task = taskSnap.data();
      if (!tmCanSee_(access, task) || (!tmCanUpdate_(access, task) && !tmCanManage_(access, task))) {
        throw new Error('You do not have permission to attach files to this task.');
      }

      const existing = (access.admin || access.headOffice)
        ? await db.collection('taskFiles').where('TaskID', '==', taskId).get()
        : await db.collection('taskFiles').where('TaskID', '==', taskId).where('AllowedCodes', 'array-contains', access.code).get();
      if (existing.size >= MAX_FILES_PER_TASK) throw new Error(`Maximum ${MAX_FILES_PER_TASK} encrypted files allowed per task.`);

      const hier = await tmHierarchy_();
      const allowedCodes = await getAllowedKeyCodes_(task.AssignedTo, task.AssignedBy, hier);
      const recipientJwks = await fetchPublicKeys_(allowedCodes);
      const enc = await window.CryptoVault.encryptFileForRecipients(file, recipientJwks);

      const fileId = tmId_('FIL');
      const fileRef = db.collection('taskFiles').doc(fileId);
      const now = new Date();

      await fileRef.set({
        FileID: fileId,
        TaskID: taskId,
        IsConfidential: true,
        NameEnc: enc.nameEnc,
        MimeEnc: enc.mimeEnc,
        SizeBytes: enc.sizeBytes,
        ChunkCount: enc.chunkCount,
        KeyEnvelopes: enc.envelopes,
        AllowedCodes: allowedCodes,
        UploadedBy: user.EmpCode,
        UploadedByName: user.EmpName,
        CreatedAt: now
      });

      for (let i = 0; i < enc.chunks.length; i++) {
        await fileRef.collection('chunks').doc(String(i).padStart(4, '0')).set({
          idx: i, iv: enc.chunks[i].iv, ct: enc.chunks[i].ct, AllowedCodes: allowedCodes
        });
      }

      await db.collection('tasks').doc(taskId).update({ FileCount: existing.size + 1, UpdatedAt: now });
      return { ok: true, file: { FileID: fileId, name: file.name, sizeBytes: file.size, uploadedBy: user.EmpName, created: tmStamp_(now) } };
    },

    apiListTaskFiles: async function (token, taskId) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const taskSnap = await db.collection('tasks').doc(taskId).get();
      if (!taskSnap.exists) throw new Error('Task no longer exists.');
      if (!tmCanSee_(access, taskSnap.data())) throw new Error('Access denied.');

      const snap = (access.admin || access.headOffice)
        ? await db.collection('taskFiles').where('TaskID', '==', taskId).get()
        : await db.collection('taskFiles').where('TaskID', '==', taskId).where('AllowedCodes', 'array-contains', access.code).get();
      const files = [];
      const unlocked = window.CryptoVault && window.CryptoVault.isUnlocked(access.code);

      for (const d of snap.docs) {
        const f = d.data();
        let name = 'Encrypted Confidential File';
        let locked = true;
        if (unlocked && f.KeyEnvelopes && f.KeyEnvelopes[access.code]) {
          try {
            const dek = await window.CryptoVault.unwrapDekFromEnvelopes(f.KeyEnvelopes, access.code);
            if (dek) {
              name = await window.CryptoVault.decryptText(dek, f.NameEnc);
              locked = false;
            }
          } catch (e) { /* keep locked label */ }
        }
        files.push({
          FileID: f.FileID || d.id,
          name,
          locked,
          sizeBytes: Number(f.SizeBytes) || 0,
          uploadedBy: f.UploadedByName || f.UploadedBy || '',
          canDelete: access.admin || f.UploadedBy === access.code || tmCanManage_(access, taskSnap.data()),
          created: tmStamp_(f.CreatedAt)
        });
      }
      return { ok: true, files };
    },

    apiDownloadTaskFile: async function (token, fileId) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!window.CryptoVault || !window.CryptoVault.isUnlocked(access.code)) {
        throw new Error('Unlock your encryption vault before downloading confidential files.');
      }
      const fileRef = db.collection('taskFiles').doc(fileId);
      const fileSnap = await fileRef.get();
      if (!fileSnap.exists) throw new Error('Confidential file not found.');
      const meta = fileSnap.data();

      const taskSnap = await db.collection('tasks').doc(meta.TaskID).get();
      if (taskSnap.exists && !tmCanSee_(access, taskSnap.data())) throw new Error('You do not have access to this file.');

      const chunksSnap = (access.admin || access.headOffice)
        ? await fileRef.collection('chunks').get()
        : await fileRef.collection('chunks').where('AllowedCodes', 'array-contains', access.code).get();
      const chunkDocs = [];
      chunksSnap.forEach(c => chunkDocs.push(c.data()));
      chunkDocs.sort((a, b) => (Number(a.idx) || 0) - (Number(b.idx) || 0));

      const decrypted = await window.CryptoVault.decryptFileRecord(meta, chunkDocs, access.code);
      return Object.assign({ ok: true }, decrypted);
    },

    apiDeleteTaskFile: async function (token, fileId) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const fileRef = db.collection('taskFiles').doc(fileId);
      const fileSnap = await fileRef.get();
      if (!fileSnap.exists) return { ok: true };
      const meta = fileSnap.data();

      const taskSnap = await db.collection('tasks').doc(meta.TaskID).get();
      const canDel = access.admin || meta.UploadedBy === access.code || (taskSnap.exists && tmCanManage_(access, taskSnap.data()));
      if (!canDel) throw new Error('You do not have permission to remove this file.');

      const batch = db.batch();
      const chunksSnap = (access.admin || access.headOffice)
        ? await fileRef.collection('chunks').get()
        : await fileRef.collection('chunks').where('AllowedCodes', 'array-contains', access.code).get();
      chunksSnap.forEach(c => batch.delete(c.ref));
      batch.delete(fileRef);
      await batch.commit();

      if (taskSnap.exists) {
        const rem = (access.admin || access.headOffice)
          ? await db.collection('taskFiles').where('TaskID', '==', meta.TaskID).get()
          : await db.collection('taskFiles').where('TaskID', '==', meta.TaskID).where('AllowedCodes', 'array-contains', access.code).get();
        await db.collection('tasks').doc(meta.TaskID).update({ FileCount: rem.size });
      }
      return { ok: true };
    },

    // 10. Task History & Formatted Notifications
    apiTaskHistory: async function (token, taskId) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const taskSnap = await db.collection('tasks').doc(taskId).get();
      if (!taskSnap.exists) throw new Error('Task no longer exists.');
      if (!tmCanSee_(access, taskSnap.data())) throw new Error('Access denied.');

      const snap = (access.admin || access.headOffice)
        ? await db.collection('taskHistory').where('TaskID', '==', taskId).orderBy('Timestamp', 'desc').limit(50).get()
        : await db.collection('taskHistory').where('TaskID', '==', taskId).where('WatcherCodes', 'array-contains', access.code).get();
      const events = [];
      snap.forEach(d => {
        const ev = d.data();
        events.push({
          ts: tmAsDate_(ev.Timestamp) ? tmAsDate_(ev.Timestamp).getTime() : 0,
          actor: ev.ActorName || ev.ActorEmpCode,
          action: ev.Action,
          details: ev.Details || '{}',
          time: tmStamp_(ev.Timestamp)
        });
      });
      events.sort((a, b) => b.ts - a.ts);
      return { ok: true, events: events.slice(0, 50) };
    },

    apiGetNotifications: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const q = (access.admin || access.headOffice)
        ? db.collection('taskHistory').orderBy('Timestamp', 'desc').limit(80)
        : db.collection('taskHistory').where('WatcherCodes', 'array-contains', access.code).orderBy('Timestamp', 'desc').limit(80);

      const snap = await q.get();
      const taskCache = {};
      const allVisible = await tmFetchVisibleTasks_(access, 'team').catch(() => []);
      allVisible.forEach(t => { taskCache[String(t.TaskID)] = t; });
      const mineSnap = await db.collection('tasks').where('AssignedTo', '==', access.code).get();
      mineSnap.forEach(d => { taskCache[d.id] = d.data(); });

      const notifs = [];
      for (const d of snap.docs) {
        const e = d.data();
        const actor = String(e.ActorEmpCode || '');
        if (actor === user.EmpCode) continue;
        const taskId = String(e.TaskID || '');
        const task = taskCache[taskId];
        if (!task) continue;
        if (!tmCanSee_(access, task)) continue;

        let title = tmSafeTaskTitleForEmail_(task);
        if (task.IsConfidential && window.CryptoVault && window.CryptoVault.isUnlocked(access.code) && task.KeyEnvelopes) {
          try {
            const dek = await window.CryptoVault.unwrapDekFromEnvelopes(task.KeyEnvelopes, access.code);
            if (dek && task.TitleEnc) title = await window.CryptoVault.decryptText(dek, task.TitleEnc);
          } catch (ignore) { /* keep safe title */ }
        }

        const action = String(e.Action || '');
        const actorName = String(e.ActorName || (hier.byCode[actor] && hier.byCode[actor].EmpName) || 'Someone');
        let details = {};
        try { details = JSON.parse(e.Details || '{}'); } catch (ignore) {}

        let text = '', type = 'info';
        if (action === 'TASK_CREATED') {
          text = `${actorName} assigned a new task: "${title}"`;
          type = 'task_assigned';
        } else if (action === 'TASK_STATUS_CHANGED' || action === 'STATUS_CHANGE') {
          const toStatus = details.status || details.to || details.Status || 'updated';
          if (toStatus === 'Completed') {
            text = `${actorName} completed task: "${title}"`;
            type = 'task_completed';
          } else {
            text = `${actorName} changed status of "${title}" to ${toStatus}`;
            type = 'status_change';
          }
        } else if (action === 'TASK_REOPENED') {
          text = `${actorName} reopened task: "${title}"` + (details.remark ? ` (${details.remark})` : '');
          type = 'task_reopened';
        } else if (action === 'TASK_UPDATED') {
          text = `${actorName} updated details for "${title}"`;
          type = 'task_updated';
        } else {
          text = `${actorName} updated "${title}"`;
          type = 'general';
        }

        notifs.push({
          id: d.id,
          taskId,
          actorCode: actor,
          actorName,
          taskTitle: title,
          action,
          text,
          type,
          timestamp: tmIso_(e.Timestamp) || new Date().toISOString()
        });
        if (notifs.length >= 30) break;
      }
      return { ok: true, notifications: notifs };
    },

    // 11. Full Dashboard Analytics (Roles, Nazim, Location/Region, Trends, Drilldown)
    apiDashboardData: async function (token, filters) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const isNazim = (hier.children[user.EmpCode] || []).length > 0;
      if (!access.admin && !access.headOffice && !isNazim) {
        throw new Error('Dashboard access is limited to Nazim users.');
      }

      const f = filters || {};
      const statusFilter = String(f.status || '');
      if (statusFilter && TM_STATUSES.indexOf(statusFilter) < 0 && statusFilter !== 'Overdue') {
        throw new Error('Invalid dashboard status filter.');
      }

      const rawTasks = await tmFetchVisibleTasks_(access, 'team');
      const visible = rawTasks.filter(t => tmCanSee_(access, t)).map(t => {
        const e = hier.byCode[String(t.AssignedTo)] || {};
        return { task: t, employee: e, due: tmAsDate_(t.DueDate), overdue: tmOverdue_(t.DueDate, t.Status) };
      });

      const employeeCodes = new Set((access.admin || access.headOffice)
        ? Object.keys(hier.byCode)
        : [String(user.EmpCode)].concat(Array.from(access.sub)));
      visible.forEach(x => { if (x.employee.EmpCode) employeeCodes.add(String(x.employee.EmpCode)); });
      const accessiblePeople = Array.from(employeeCodes).map(c => hier.byCode[c]).filter(e => e && e.Active === 'Y');

      const resolveNazim = e => {
        if (/nazim/i.test(String((e || {}).Role || ''))) return e;
        let cursor = e, direct = null, found = null;
        const seen = new Set();
        while (cursor && cursor.Nazim && !seen.has(String(cursor.Nazim))) {
          const code = String(cursor.Nazim), manager = hier.byCode[code];
          seen.add(code);
          if (!manager) break;
          if (!direct) direct = manager;
          if (/nazim/i.test(String(manager.Role || ''))) { found = manager; break; }
          cursor = manager;
        }
        return found || direct || {};
      };

      const managerCodes = new Set();
      accessiblePeople.forEach(e => {
        const manager = resolveNazim(e);
        if (manager.EmpCode) managerCodes.add(String(manager.EmpCode));
      });

      const allOptions = {
        locations: Array.from(new Set(accessiblePeople.map(e => String(e.Division || '')).filter(Boolean))).sort(),
        regions: Array.from(new Set(accessiblePeople.map(e => String(e.Region || '')).filter(Boolean))).sort(),
        roles: Array.from(new Set(accessiblePeople.map(e => String(e.Role || '')).filter(Boolean))).sort(),
        employees: accessiblePeople.map(e => ({ code: String(e.EmpCode), name: String(e.EmpName || '') })).sort((a, b) => a.name.localeCompare(b.name)),
        nazims: Array.from(managerCodes).map(c => hier.byCode[c]).filter(e => e && e.Active === 'Y').map(e => ({ code: String(e.EmpCode), name: String(e.EmpName || '') })).sort((a, b) => a.name.localeCompare(b.name))
      };

      const canFilterAll = access.admin || access.headOffice;
      const options = canFilterAll ? allOptions : { employees: allOptions.employees };
      const permittedCodes = new Set(accessiblePeople.map(e => String(e.EmpCode)));

      if (f.employee && !permittedCodes.has(String(f.employee))) throw new Error('That employee is outside your dashboard access.');
      if (!canFilterAll && (f.location || f.region || f.role || f.nazim)) {
        throw new Error('Those dashboard filters are available to administrators only.');
      }
      if (canFilterAll && f.nazim && !managerCodes.has(String(f.nazim))) {
        throw new Error('That Nazim is outside the available dashboard filters.');
      }

      const nazimScope = canFilterAll && f.nazim ? tmSubtreeFrom_(hier.children, String(f.nazim), true) : null;
      const selected = visible.filter(x => {
        const e = x.employee;
        if (canFilterAll && f.location && String(e.Division || x.task.Division || '') !== String(f.location)) return false;
        if (canFilterAll && f.region && String(e.Region || x.task.Region || '') !== String(f.region)) return false;
        if (canFilterAll && f.role && String(e.Role || '') !== String(f.role)) return false;
        if (f.employee && String(x.task.AssignedTo) !== String(f.employee)) return false;
        if (canFilterAll && nazimScope && !nazimScope[String(x.task.AssignedTo)]) return false;
        return true;
      });

      const counts = { Pending: 0, 'In Progress': 0, Completed: 0, Overdue: 0, Total: selected.length };
      const byRegion = {}, byLocation = {}, byRole = {}, byEmployee = {}, byNazim = {};
      const byDue = { 'Due today': 0, 'Due within 7 days': 0, 'Due later': 0, 'No due date': 0 };
      const byCreated = {}, byCompleted = {};
      const todayKey = tmDayKey_(new Date());

      const bump = (map, key, rec) => {
        key = key || 'Unassigned';
        const x = map[key] || (map[key] = { label: key, total: 0, open: 0, overdue: 0, completed: 0, pending: 0, inProgress: 0 });
        x.total++;
        if (rec.task.Status === 'Completed') x.completed++; else x.open++;
        if (rec.overdue) x.overdue++;
        if (rec.task.Status === 'Pending') x.pending++;
        if (rec.task.Status === 'In Progress') x.inProgress++;
        return x;
      };

      selected.forEach(x => {
        const t = x.task, e = x.employee, n = resolveNazim(e);
        counts[t.Status] = (counts[t.Status] || 0) + 1;
        if (x.overdue) counts.Overdue++;

        if (t.Status !== 'Completed') {
          if (!x.overdue) {
            if (!x.due) byDue['No due date']++;
            else {
              const day = tmDayKey_(x.due);
              const days = Math.round((new Date(day + 'T00:00:00').getTime() - new Date(todayKey + 'T00:00:00').getTime()) / 86400000);
              if (days === 0) byDue['Due today']++;
              else if (days <= 7) byDue['Due within 7 days']++;
              else byDue['Due later']++;
            }
          }
        }

        const created = tmAsDate_(t.CreatedAt);
        if (created) {
          const m = tmDayKey_(created).slice(0, 7);
          byCreated[m] = (byCreated[m] || 0) + 1;
        }
        const completed = tmAsDate_(t.CompletedAt);
        if (t.Status === 'Completed' && completed) {
          const m = tmDayKey_(completed).slice(0, 7);
          byCompleted[m] = (byCompleted[m] || 0) + 1;
        }

        bump(byRegion, String(e.Region || t.Region || 'Unassigned'), x);
        bump(byLocation, String(e.Division || t.Division || 'Unassigned'), x);
        bump(byRole, String(e.Role || 'Unassigned'), x);

        const empKey = String(e.EmpCode || t.AssignedTo);
        const empObj = bump(byEmployee, empKey, x);
        empObj.name = String(e.EmpName || empKey);
        empObj.code = empKey;
        empObj.role = String(e.Role || '');
        empObj.region = String(e.Region || t.Region || '');
        empObj.division = String(e.Division || t.Division || '');

        const mgrKey = String(n.EmpCode || 'Unassigned');
        const mgrObj = bump(byNazim, mgrKey, x);
        mgrObj.name = String(n.EmpName || 'Unassigned');
        mgrObj.code = mgrKey;
        mgrObj.role = String(n.Role || '');
      });

      const values = map => Object.keys(map).map(k => map[k]).sort((a, b) => b.open - a.open || b.total - a.total || a.label.localeCompare(b.label));
      const drill = selected.filter(x => !statusFilter || (statusFilter === 'Overdue' ? x.overdue : x.task.Status === statusFilter));
      drill.sort((a, b) => tmSortKey_(a.task).localeCompare(tmSortKey_(b.task)) || String(a.task.Title).localeCompare(String(b.task.Title)));

      const offset = Math.max(0, Math.min(100000, Number(f.offset) || 0));
      const page = drill.slice(offset, offset + PAGE_SIZE);
      const pageMap = {};
      page.forEach(x => { pageMap[String(x.task.TaskID)] = x.task; });
      const checklist = await tmChecklistFor_(page.map(x => x.task.TaskID), pageMap, access.code, access.admin || access.headOffice);
      const shapedDrill = await Promise.all(page.map(x => tmShapeTask_(x.task, access, checklist, hier.byCode)));

      return {
        ok: true,
        employeeOnly: false,
        asOf: tmStamp_(new Date()),
        counts,
        options,
        openTotal: (counts.Pending || 0) + (counts['In Progress'] || 0),
        completionRate: counts.Total ? Math.round(counts.Completed * 1000 / counts.Total) / 10 : 0,
        overdueRate: counts.Total ? Math.round(counts.Overdue * 1000 / counts.Total) / 10 : 0,
        byRegion: values(byRegion).slice(0, 12),
        byLocation: values(byLocation).slice(0, 12),
        byRole: values(byRole).slice(0, 20),
        byEmployee: values(byEmployee).slice(0, 50),
        byNazim: canFilterAll ? values(byNazim).slice(0, 12) : [],
        due: byDue,
        trends: Object.keys(byCreated).sort().slice(-12).map(month => ({ month, created: byCreated[month], completed: byCompleted[month] || 0 })),
        drilldown: {
          status: statusFilter,
          total: drill.length,
          tasks: shapedDrill,
          hasMore: offset + PAGE_SIZE < drill.length,
          nextOffset: offset + PAGE_SIZE
        }
      };
    },

    // 12. Task Templates
    apiTaskTemplates: async function (token) {
      const { user } = await tmAuth_(token);
      const hier = await tmHierarchy_();
      const access = await tmAccess_(user);
      const codes = access.admin ? Object.keys(hier.byCode) : [String(user.EmpCode)].concat(Array.from(access.sub));
      const reach = new Set();
      codes.forEach(c => { const e = hier.byCode[c]; if (e && e.Active === 'Y' && e.Role) reach.add(e.Role); });
      if (user.Role) reach.add(String(user.Role).trim());

      const isManagerOrAdmin = !!(access.admin || access.headOffice || (hier.children[user.EmpCode] || []).length > 0);
      const allTemplates = (await tmTemplates_()).filter(t => t.active);
      const templates = isManagerOrAdmin
        ? allTemplates.map(t => ({ id: t.id, title: t.title, description: t.description, checklist: t.checklist, all: t.all || !t.roles.length, roles: (t.all || !t.roles.length) ? [] : t.roles }))
        : allTemplates.filter(t => t.all || !t.roles.length || t.roles.some(r => reach.has(r)))
            .map(t => ({ id: t.id, title: t.title, description: t.description, checklist: t.checklist, all: t.all || !t.roles.length, roles: (t.all || !t.roles.length) ? [] : t.roles.filter(r => reach.has(r)) }));
      return { ok: true, templates };
    },

    apiAdminTemplates: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      const roles = await tmRoles_();
      return {
        ok: true,
        templates: await tmTemplates_(),
        roles: roles.filter(r => r.Active).map(r => r.Role).sort()
      };
    },

    apiSaveTemplate: async function (token, input) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      input = input || {};
      const id = tmClip_(input.id, 100);
      const title = tmClip_(input.title, 200);
      if (!title) throw new Error('Please enter a template title.');
      const description = tmClip_(input.description, 2000);
      const steps = (Array.isArray(input.checklist) ? input.checklist : String(input.checklist || '').split(/\r?\n/))
        .map(x => tmClip_(x, 200)).filter(Boolean);
      if (steps.length > 40) throw new Error('A template can have at most 40 checklist steps.');

      const active = tmYN_(input.active);
      const all = input.all === true;
      const valid = {};
      (await tmRoles_()).forEach(r => { if (r.Active) valid[r.Role] = true; });
      const roles = Array.from(new Set((Array.isArray(input.roles) ? input.roles : []).map(x => tmClip_(x, 80)).filter(Boolean)));
      const bad = roles.filter(r => !valid[r]);
      if (!all && bad.length) throw new Error('These designations are unknown or switched off: ' + bad.join(', '));
      if (!all && !roles.length && active === 'Y') throw new Error('Choose at least one designation, or tick "All designations".');

      const allExisting = await tmTemplates_();
      if (allExisting.some(t => t.id !== id && t.title.toLowerCase() === title.toLowerCase())) {
        throw new Error('Another template already uses this title.');
      }

      const now = new Date();
      const tplId = id || tmId_('TPL');
      const rec = {
        TemplateID: tplId,
        Title: title,
        Description: description,
        Checklist: steps,
        Designations: all ? TM_TPL_ALL : JSON.stringify(roles),
        All: all,
        Roles: all ? [] : roles,
        Active: active,
        UpdatedAt: now
      };
      if (!id) { rec.CreatedBy = user.EmpCode; rec.CreatedAt = now; }

      await db.collection('taskTemplates').doc(tplId).set(rec, { merge: true });
      await tmAudit_(user.EmpCode, id ? 'TEMPLATE_UPDATE' : 'TEMPLATE_CREATE', tplId, { title, all, roles, active });
      return { ok: true, id: tplId, created: !id };
    },

    apiSetTemplateActive: async function (token, id, active) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      const docRef = db.collection('taskTemplates').doc(tmClip_(id, 100));
      const snap = await docRef.get();
      if (!snap.exists) throw new Error('That template no longer exists.');
      const row = snap.data();
      if (tmYes_(active) && !row.All && !(Array.isArray(row.Roles) && row.Roles.length)) {
        throw new Error('Choose designations for this template before switching it on.');
      }
      await docRef.update({ Active: tmYN_(active), UpdatedAt: new Date() });
      await tmAudit_(user.EmpCode, 'TEMPLATE_ACTIVE', snap.id, { active: tmYN_(active) });
      return { ok: true };
    },

    apiDeleteTemplate: async function (token, id) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      await db.collection('taskTemplates').doc(tmClip_(id, 100)).delete();
      await tmAudit_(user.EmpCode, 'TEMPLATE_DELETE', id, {});
      return { ok: true };
    },

    // 13. Mail, Digests, & Reminder Schedules
    apiMailStatus: async function (token) {
      await tmAuth_(token);
      return { ok: true, status: await tmMailStatus_() };
    },

    apiSendTaskMail: async function (token, id) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const snap = await db.collection('tasks').doc(id).get();
      if (!snap.exists) throw new Error('Task no longer exists.');
      const t = snap.data();
      if (!tmCanSee_(access, t) || !tmCanRemind_(access, t)) throw new Error('You cannot send a reminder for this task.');

      const target = hier.byCode[String(t.AssignedTo)];
      if (!target || !tmIsEmail_(target.Email)) throw new Error('The assignee has no valid email address.');
      const cfg = await tmConfig_();
      const c = tmDigestContent_('TASK_ASSIGNMENT', [t], hier.byCode, cfg);
      const r = await tmLogAndSendMail_('ASSIGNMENT', [t.TaskID], target, c.title, c.html, c.text);
      return {
        ok: true,
        queued: !!r.queued,
        message: r.queued ? 'Mail relay is unavailable or quota reached; reminder queued.' : 'Reminder sent to ' + target.EmpName + '.'
      };
    },

    apiMailManagerOptions: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      const h = await tmHierarchy_();
      const managers = Object.keys(h.byCode).map(c => h.byCode[c])
        .filter(m => m.Active === 'Y' && (h.children[m.EmpCode] || []).length)
        .map(m => ({ code: String(m.EmpCode), name: String(m.EmpName), email: String(m.Email || ''), employees: (h.children[m.EmpCode] || []).length }))
        .sort((a, b) => a.name.localeCompare(b.name));
      return { ok: true, managers };
    },

    apiSendTaskDigest: async function (token, audience, managerCodes, confirmRepeat) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const admin = access.admin;
      const h = await tmHierarchy_();
      const cfg = await tmConfig_();

      const allTasks = await tmFetchVisibleTasks_(access, 'team');
      const open = {};
      allTasks.forEach(t => { if (t.Status !== 'Completed') (open[String(t.AssignedTo)] = open[String(t.AssignedTo)] || []).push(t); });

      let type, recipients = [];
      if (audience === 'employees') {
        if (!admin && !(h.children[user.EmpCode] || []).length) throw new Error('Only an administrator or a Nazim with employees can email employee task summaries.');
        type = 'EMPLOYEE_TASK_DIGEST';
        const codes = admin ? Object.keys(h.byCode).filter(c => c !== String(user.EmpCode) && h.byCode[c].Active === 'Y') : Array.from(access.sub);
        recipients = codes.map(c => h.byCode[c]).filter(Boolean).map(person => ({ person, tasks: open[person.EmpCode] || [] }));
      } else if (audience === 'team') {
        if (!admin && !(h.children[user.EmpCode] || []).length) throw new Error('A Nazim account is required to prepare a combined team summary.');
        type = 'MANAGER_TASK_DIGEST';
        const tasks = [].concat(open[String(user.EmpCode)] || []);
        access.sub.forEach(c => (open[c] || []).forEach(t => tasks.push(t)));
        recipients = [{ person: user, tasks }];
      } else if (audience === 'managers') {
        if (!admin) throw new Error('Administrator access is required to email every Nazim.');
        type = 'MANAGER_TASK_DIGEST';
        const available = Object.keys(h.byCode).map(c => h.byCode[c]).filter(m => m.Active === 'Y' && (h.children[m.EmpCode] || []).length);
        const requested = Array.isArray(managerCodes) ? Array.from(new Set(managerCodes.map(String))) : available.map(m => String(m.EmpCode));
        if (!requested.length) throw new Error('Select at least one Nazim.');
        const byManagerCode = {};
        available.forEach(m => { byManagerCode[String(m.EmpCode)] = m; });
        const invalid = requested.filter(c => !byManagerCode[c]);
        if (invalid.length) throw new Error('Some selected Nazim codes are inactive or no longer manage employees: ' + invalid.slice(0, 10).join(', '));
        recipients = requested.map(c => byManagerCode[c]).map(m => {
          const codes = Object.keys(tmSubtreeFrom_(h.children, m.EmpCode, false));
          const tasks = [].concat(open[String(m.EmpCode)] || []);
          codes.forEach(c => (open[c] || []).forEach(t => tasks.push(t)));
          return { person: m, tasks };
        });
      } else {
        throw new Error('Unknown email audience.');
      }

      const today = tmDayKey_(new Date());
      const sentOrQueued = new Set();
      const allowRepeat = audience === 'managers' && admin && confirmRepeat === true;
      if (!allowRepeat) {
        const logSnap = await db.collection('mailLog').where('DayKey', '==', today).get();
        logSnap.forEach(d => { const x = d.data(); if (x.Type === type && x.Result === 'SENT') sentOrQueued.add(String(x.ToEmpCode)); });
      }

      const skipped = { noTasks: 0, noEmail: 0, alreadySent: 0 };
      let prepared = 0, sent = 0, queued = 0;

      for (const item of recipients) {
        const { person, tasks: owned } = item;
        if (!owned.length) { skipped.noTasks++; continue; }
        if (!tmIsEmail_(person.Email)) { skipped.noEmail++; continue; }
        if (!allowRepeat && sentOrQueued.has(String(person.EmpCode))) { skipped.alreadySent++; continue; }
        prepared++;
        const c = tmDigestContent_(type, owned, h.byCode, cfg);
        const mr = await tmLogAndSendMail_(type, owned.map(t => t.TaskID), person, c.title, c.html, c.text);
        if (mr.sent) sent++; else queued++;
        if (!allowRepeat) sentOrQueued.add(String(person.EmpCode));
      }

      await tmAudit_(user.EmpCode, 'MAIL_DIGEST_' + audience.toUpperCase(), '', { prepared, sent, queued, skipped });
      return { ok: true, prepared, sent, queued, skipped };
    },

    apiRunMailNow: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');

      const qSnap = await db.collection('mailQueue').where('Status', '==', 'QUEUED').get();
      let sent = 0;
      for (const d of qSnap.docs) {
        const q = d.data();
        const res = await tmSendEmail_(q.ToEmail, q.Subject, q.BodyHtml, q.BodyText);
        if (res.ok) {
          await d.ref.update({ Status: 'SENT', LastError: '' });
          sent++;
        } else {
          await d.ref.update({ Attempts: (Number(q.Attempts) || 0) + 1, LastError: res.error || '' });
        }
      }
      return { ok: true, sent, newDigests: 0 };
    },

    apiRetryQueuedMailTomorrow: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      const qSnap = await db.collection('mailQueue').where('Status', '==', 'FAILED').get();
      let retried = 0;
      const batch = db.batch();
      qSnap.forEach(d => {
        batch.update(d.ref, { Status: 'QUEUED', Attempts: 0, LastError: 'Retry requested by administrator.' });
        retried++;
      });
      if (retried) await batch.commit();
      return { ok: true, retried, message: retried ? `${retried} email(s) requeued.` : 'No failed emails needed retrying.' };
    },

    apiSendTestMail: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      if (!tmIsEmail_(user.Email)) throw new Error('Your admin account has no valid email address.');
      const cfg = await tmConfig_();
      const html = tmMailShell_(cfg, '<p><b>Result:</b> Firebase + Apps Script email relay is working.</p>', 'This is a test email from Task Management.');
      const res = await tmSendEmail_(user.Email, 'Test mail from ' + (cfg.APP_NAME || 'Task Management'), html, 'Test mail from Task Management.');
      if (!res.ok) throw new Error(res.error || 'Could not send test mail.');
      return { ok: true, message: 'Test email dispatched to ' + user.Email };
    },

    apiAdminSchedule: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      const snap = await db.collection('reminderSchedule').get();
      const schedule = [];
      snap.forEach(d => {
        const s = d.data();
        schedule.push({
          Role: String(s.Role || ''),
          Region: String(s.Region || ''),
          DayOfWeek: s.DayOfWeek === '' || s.DayOfWeek == null ? '' : Number(s.DayOfWeek),
          DayOfMonth: s.DayOfMonth === '' || s.DayOfMonth == null ? '' : Number(s.DayOfMonth),
          Active: tmYN_(s.Active)
        });
      });
      const roles = await tmRoles_();
      const regions = await tmRegions_();
      return {
        ok: true,
        schedule,
        roles: roles.filter(r => r.Active).map(r => r.Role),
        regions: regions.filter(r => r.Active).map(r => r.Region)
      };
    },

    apiSaveSchedule: async function (token, items) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      if (!Array.isArray(items)) throw new Error('Nothing to save.');

      const validRoles = new Set((await tmRoles_()).map(r => r.Role));
      const validRegions = new Set((await tmRegions_()).map(r => r.Region));

      const clean = items.map((x, i) => {
        const dow = x.DayOfWeek === '' || x.DayOfWeek == null ? '' : Number(x.DayOfWeek);
        const dom = x.DayOfMonth === '' || x.DayOfMonth == null ? '' : Number(x.DayOfMonth);
        if (!validRoles.has(x.Role)) throw new Error(`Row ${i + 1}: choose a valid role.`);
        if (x.Region && !validRegions.has(x.Region)) throw new Error(`Row ${i + 1}: unknown region.`);
        if (dow === '' && dom === '') throw new Error(`Row ${i + 1}: choose a weekday or day of month.`);
        if (dow !== '' && (dow < 1 || dow > 7 || dow % 1)) throw new Error(`Row ${i + 1}: weekday must be 1..7.`);
        if (dom !== '' && (dom < 1 || dom > 31 || dom % 1)) throw new Error(`Row ${i + 1}: day of month must be 1..31.`);
        return { Role: x.Role, Region: x.Region || '', DayOfWeek: dow, DayOfMonth: dom, Active: tmYN_(x.Active) };
      });

      const oldSnap = await db.collection('reminderSchedule').get();
      const batch = db.batch();
      oldSnap.forEach(d => batch.delete(d.ref));
      clean.forEach((row, idx) => batch.set(db.collection('reminderSchedule').doc('sched-' + idx), row));
      await batch.commit();
      await tmAudit_(user.EmpCode, 'SCHEDULE_UPDATE', 'reminderSchedule', { count: clean.length });
      return { ok: true };
    },

    // 14. Admin Overview, Settings, People, Roles, Email Change Requests
    apiAdminOverview: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');

      const cfg = await tmConfig_();
      const hier = await tmHierarchy_();
      const empCount = Object.keys(hier.byCode).filter(c => hier.byCode[c].Active === 'Y').length;
      const taskSnap = await db.collection('tasks').get();
      const stats = { employees: empCount, people: empCount, tasks: taskSnap.size, pending: 0, inProgress: 0, completed: 0, overdue: 0 };

      taskSnap.forEach(d => {
        const t = d.data();
        if (t.Status === 'Completed') stats.completed++;
        else {
          if (t.Status === 'In Progress') stats.inProgress++; else stats.pending++;
          if (tmOverdue_(t.DueDate, t.Status)) stats.overdue++;
        }
      });

      const mail = await tmMailStatus_();
      const appUrl = (typeof window !== 'undefined' && window.location) ? window.location.href.split('#')[0].split('?')[0] : '';
      return {
        ok: true,
        mail,
        stats,
        urls: { system: 'https://console.firebase.google.com/project/' + window.FIREBASE_CONFIG.projectId + '/firestore', dashboard: 'https://console.firebase.google.com/project/' + window.FIREBASE_CONFIG.projectId + '/authentication', app: appUrl },
        timers: { daily: !!(window.EMAIL_CONFIG && window.EMAIL_CONFIG.appsScriptRelayUrl), dashboard: true },
        settings: {
          APP_NAME: cfg.APP_NAME,
          DAILY_RUN_HOUR: Number(cfg.DAILY_RUN_HOUR) || 9,
          SESSION_DAYS: Number(cfg.SESSION_DAYS) || 30,
          MIN_PASSWORD_LENGTH: Number(cfg.MIN_PASSWORD_LENGTH) || 8,
          ESCALATION_ENABLED: tmYN_(cfg.ESCALATION_ENABLED),
          ARCHIVE_AFTER_DAYS: Number(cfg.ARCHIVE_AFTER_DAYS) || 60,
          EMAIL_GREETING: cfg.EMAIL_GREETING || TM_DEFAULTS.EMAIL_GREETING,
          EMAIL_SIGN_OFF: cfg.EMAIL_SIGN_OFF || TM_DEFAULTS.EMAIL_SIGN_OFF
        },
        version: TM_VERSION,
        lastBackup: cfg.LAST_BACKUP || 'Never',
        lastArchive: cfg.ARCHIVE_AT ? tmStamp_(cfg.ARCHIVE_AT) : 'Never'
      };
    },

    apiSaveSettings: async function (token, s) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      s = s || {};
      const intVal = (key, label, min, max) => {
        const n = Number(s[key]);
        if (!isFinite(n) || n % 1 || n < min || n > max) throw new Error(`${label} must be a whole number from ${min} to ${max}.`);
        return n;
      };
      const v = {
        APP_NAME: tmClip_(s.APP_NAME, 60),
        DAILY_RUN_HOUR: intVal('DAILY_RUN_HOUR', 'Reminder hour', 0, 23),
        SESSION_DAYS: intVal('SESSION_DAYS', 'Stay signed in (days)', 1, 180),
        MIN_PASSWORD_LENGTH: intVal('MIN_PASSWORD_LENGTH', 'Minimum password length', 6, 32),
        ESCALATION_ENABLED: tmYN_(s.ESCALATION_ENABLED),
        ARCHIVE_AFTER_DAYS: intVal('ARCHIVE_AFTER_DAYS', 'Archive completed tasks after (days)', 7, 365),
        EMAIL_GREETING: tmClip_(s.EMAIL_GREETING, 100) || TM_DEFAULTS.EMAIL_GREETING,
        EMAIL_SIGN_OFF: tmClip_(s.EMAIL_SIGN_OFF, 100) || TM_DEFAULTS.EMAIL_SIGN_OFF
      };
      if (!v.APP_NAME) throw new Error('Please enter an app name.');
      await db.collection('config').doc('app_config').set(v, { merge: true });
      memoClear();
      await tmAudit_(user.EmpCode, 'SETTINGS_UPDATE', 'app_config', v);
      return { ok: true, timersReinstalled: false, settings: v };
    },

    apiAdminPeople: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      const hier = await tmHierarchy_();
      const people = Object.values(hier.byCode).map(e => ({
        EmpCode: e.EmpCode, EmpName: e.EmpName, Nazim: e.Nazim, Division: e.Division,
        Region: e.Region, Role: e.Role, Email: e.Email, Active: e.Active, LastLogin: tmStamp_(e.LastLogin)
      })).sort((a, b) => a.EmpName.localeCompare(b.EmpName));

      const roles = await tmRoles_();
      const regions = await tmRegions_();
      return {
        ok: true,
        people,
        roles: roles.filter(x => x.Active).map(x => x.Role),
        regions: regions.filter(x => x.Active).map(x => x.Region)
      };
    },

    apiSavePerson: async function (token, input) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');

      input = input || {};
      const code = tmClip_(input.EmpCode, 30).toUpperCase();
      if (!code) throw new Error('Employee code is required.');

      const cfg = await tmConfig_();
      const hier = await tmHierarchy_();
      const existing = hier.byCode[code] || null;
      const isNew = !existing;

      const p = {
        EmpCode: code,
        EmpName: tmClip_(input.EmpName, 100),
        Nazim: tmClip_(input.Nazim, 30).toUpperCase(),
        Division: tmClip_(input.Division, 80),
        Region: tmClip_(input.Region, 60),
        Role: tmClip_(input.Role, 80),
        Email: tmClip_(input.Email, 254),
        Password: String(input.Password == null ? '' : input.Password),
        Active: isNew ? 'Y' : (input.Active === undefined ? existing.Active : tmYN_(input.Active))
      };

      const errs = await tmValidatePerson_(p, hier.byCode, cfg.MIN_PASSWORD_LENGTH);
      if (errs.length) throw new Error(errs.join('\n'));

      if (existing && p.Active === 'N' && existing.Active === 'Y') {
        if (code === user.EmpCode) throw new Error('You cannot switch off your own account.');
        const activeTeam = Object.values(hier.byCode).filter(e => e.Nazim === code && e.Active === 'Y');
        if (activeTeam.length) {
          throw new Error(`This person still manages ${activeTeam.length} active employee(s). Reassign them to another Nazim first.`);
        }
      }

      const authEmail = (existing && existing.AuthEmail) || authEmailFor_(code, p.Email);
      const data = {
        EmpCode: code,
        EmpName: p.EmpName,
        Nazim: p.Nazim,
        Division: p.Division,
        Region: p.Region,
        Role: p.Role,
        Email: p.Email,
        AuthEmail: authEmail,
        Active: p.Active,
        MustChangePassword: 'N',
        SessionVersion: existing ? String(existing.SessionVersion || '1') : '1'
      };

      if (isNew || !existing.AuthUid) {
        if (!p.Password || p.Password.length < 6) {
          throw new Error('Please enter an initial password of at least 6 characters.');
        }
        try {
          data.AuthUid = await createAuthUserAsAdmin_(authEmail, p.Password);
        } catch (err) {
          throw new Error(mapAuthError_(err));
        }
        data.CreatedAt = new Date();
      } else {
        data.AuthUid = existing.AuthUid;
        if (p.Active === 'N' && existing.Active === 'Y') {
          data.SessionVersion = tmId_('v');
        }
        if (p.Password) {
          if (code === user.EmpCode) {
            await fbAuth.currentUser.updatePassword(p.Password);
            if (window.CryptoVault) await window.CryptoVault.rewrapOnPasswordChange(db, code, p.Password);
          } else {
            await fbAuth.sendPasswordResetEmail(authEmail).catch(() => {});
            throw new Error('Existing users reset passwords via a secure email link. A password-reset email was sent to ' + authEmail + '.');
          }
        }
      }

      await db.collection('employees').doc(code).set(data, { merge: true });
      const roles = await tmRoles_();
      if (data.AuthUid) {
        await syncUserMapping_(data.AuthUid, data, roles, authEmail);
      }

      // If Nazim changed on an existing employee, update WatcherCodes on their open tasks
      if (existing && (existing.Nazim !== p.Nazim || existing.Region !== p.Region || existing.Division !== p.Division)) {
        memoClear();
        const freshHier = await tmHierarchy_();
        const taskSnap = await db.collection('tasks').where('AssignedTo', '==', code).get();
        const batch = db.batch();
        let count = 0;
        taskSnap.forEach(d => {
          const t = d.data();
          if (t.Status !== 'Completed') {
            batch.update(d.ref, {
              Region: p.Region,
              Division: p.Division,
              WatcherCodes: getWatcherCodes_(code, t.AssignedBy, freshHier)
            });
            count++;
          }
        });
        if (count) await batch.commit().catch(() => {});
      }

      memoClear();
      await tmAudit_(user.EmpCode, isNew ? 'PERSON_ADD' : 'PERSON_UPDATE', code, {});
      return { ok: true, created: isNew };
    },

    apiSendPasswordReset: async function (token, empCode) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      const snap = await db.collection('employees').doc(String(empCode).toUpperCase()).get();
      if (!snap.exists) throw new Error('Employee not found.');
      const targetEmail = snap.data().AuthEmail || snap.data().Email;
      if (!targetEmail) throw new Error('This employee does not have a valid email address.');
      await fbAuth.sendPasswordResetEmail(targetEmail);
      return { ok: true, message: 'Password reset link sent to ' + targetEmail };
    },

    apiAdminRoles: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      return { ok: true, roles: await tmRoles_() };
    },

    apiSaveRoles: async function (token, roles) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      if (!Array.isArray(roles)) throw new Error('Nothing to save.');

      const seen = {};
      const clean = roles.map(r => ({
        Role: tmClip_(r.Role, 80),
        Level: Number(r.Level) || 0,
        Chain: tmClip_(r.Chain || 'Custom', 30) || 'Custom',
        IsHeadOffice: tmYes_(r.IsHeadOffice),
        IsAdmin: tmYes_(r.IsAdmin),
        Active: tmYes_(r.Active)
      }));

      clean.forEach((r, i) => {
        if (!r.Role) throw new Error(`Row ${i + 1}: role name is empty.`);
        if (seen[r.Role.toLowerCase()]) throw new Error(`The role "${r.Role}" appears twice.`);
        seen[r.Role.toLowerCase()] = true;
      });

      const h = await tmHierarchy_();
      const inUse = {};
      Object.keys(h.byCode).forEach(c => {
        if (h.byCode[c].Active === 'Y') inUse[h.byCode[c].Role] = (inUse[h.byCode[c].Role] || 0) + 1;
      });

      Object.keys(inUse).forEach(name => {
        const r = clean.find(x => x.Role === name);
        if (!r) throw new Error(`The role "${name}" is used by ${inUse[name]} employee(s) and cannot be removed.`);
        if (!r.Active) throw new Error(`The role "${name}" is used by ${inUse[name]} employee(s) and cannot be switched off.`);
      });

      const adminRoleNames = new Set(clean.filter(r => r.Active && r.IsAdmin).map(r => r.Role));
      const hasAdmin = Object.keys(h.byCode).some(c => h.byCode[c].Active === 'Y' && adminRoleNames.has(h.byCode[c].Role));
      if (!hasAdmin) throw new Error('At least one active employee must keep an administrator role.');

      const existingSnap = await db.collection('roles').get();
      const batch = db.batch();
      const keepSet = new Set(clean.map(r => r.Role));
      existingSnap.forEach(d => { if (!keepSet.has(d.id)) batch.delete(d.ref); });
      clean.forEach(r => batch.set(db.collection('roles').doc(r.Role), r));
      await batch.commit();

      // Sync IsAdmin / IsHeadOffice to /users/{uid}
      const usersSnap = await db.collection('users').get();
      const uBatch = db.batch();
      let uChanged = 0;
      usersSnap.forEach(d => {
        const u = d.data();
        const roleObj = clean.find(x => x.Role === u.Role && x.Active);
        if (roleObj) {
          const wantAdmin = u.Role === 'Admin' || u.Role === 'System Admin' || roleObj.IsAdmin;
          const wantHO = wantAdmin || roleObj.IsHeadOffice;
          if (u.IsAdmin !== wantAdmin || u.IsHeadOffice !== wantHO) {
            uBatch.update(d.ref, { IsAdmin: wantAdmin, IsHeadOffice: wantHO, UpdatedAt: new Date() });
            uChanged++;
          }
        }
      });
      if (uChanged) await uBatch.commit();

      memoClear();
      await tmAudit_(user.EmpCode, 'ROLES_UPDATE', 'roles', { count: clean.length });
      return { ok: true };
    },

    apiRequestEmailChange: async function (token, requestedEmail, reason) {
      const { user } = await tmAuth_(token);
      const email = tmClip_(requestedEmail, 254);
      const why = tmClip_(reason, 1000);
      if (!tmIsEmail_(email)) throw new Error('Please enter a valid requested email address.');
      if (why.length < 10) throw new Error('Please provide a reason of at least 10 characters.');
      if (email.toLowerCase() === String(user.Email || '').toLowerCase()) {
        throw new Error('The requested email is already on your account.');
      }

      const h = await tmHierarchy_();
      if (Object.keys(h.byCode).some(c => c !== user.EmpCode && String(h.byCode[c].Email).toLowerCase() === email.toLowerCase())) {
        throw new Error('That email address is already used by another employee.');
      }

      const existing = await db.collection('emailChangeRequests').where('EmpCode', '==', user.EmpCode).get();
      let hasPending = false;
      existing.forEach(d => { if (d.data().Status === 'PENDING') hasPending = true; });
      if (hasPending) throw new Error('You already have a pending email change request.');

      const id = tmId_('EMAIL');
      await db.collection('emailChangeRequests').doc(id).set({
        RequestID: id,
        EmpCode: user.EmpCode,
        EmpName: user.EmpName,
        CurrentEmail: user.Email,
        RequestedEmail: email,
        Reason: why,
        RequestedAt: new Date(),
        Status: 'PENDING',
        ReviewedBy: '',
        ReviewedAt: null,
        ReviewNote: ''
      });
      await tmAudit_(user.EmpCode, 'EMAIL_CHANGE_REQUEST', id, { requestedEmail: email });
      return { ok: true, requestId: id };
    },

    apiAdminEmailChangeRequests: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');

      const snap = await db.collection('emailChangeRequests').orderBy('RequestedAt', 'desc').limit(200).get();
      const requests = [];
      snap.forEach(d => {
        const r = d.data();
        if (r.Status === 'PENDING' || r.Status === 'APPROVED') {
          requests.push({
            requestId: String(r.RequestID || d.id),
            empCode: String(r.EmpCode || ''),
            empName: String(r.EmpName || ''),
            currentEmail: String(r.CurrentEmail || ''),
            requestedEmail: String(r.RequestedEmail || ''),
            reason: String(r.Reason || ''),
            requestedAt: tmStamp_(r.RequestedAt),
            status: String(r.Status || ''),
            reviewNote: String(r.ReviewNote || '')
          });
        }
      });
      return { ok: true, requests };
    },

    apiReviewEmailChangeRequest: async function (token, requestId, decision, note) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      const id = tmClip_(requestId, 100);
      const action = String(decision || '').toUpperCase();
      if (action !== 'APPROVED' && action !== 'REJECTED') throw new Error('Choose approve or reject.');

      const reqRef = db.collection('emailChangeRequests').doc(id);
      const reqSnap = await reqRef.get();
      if (!reqSnap.exists || reqSnap.data().Status !== 'PENDING') {
        throw new Error('This request is no longer pending. Refresh the list.');
      }
      const req = reqSnap.data();

      if (action === 'APPROVED') {
        const email = String(req.RequestedEmail || '').trim();
        if (!tmIsEmail_(email)) throw new Error('The requested email is invalid.');
        const h = await tmHierarchy_();
        if (Object.keys(h.byCode).some(c => c !== String(req.EmpCode) && String(h.byCode[c].Email).toLowerCase() === email.toLowerCase())) {
          throw new Error('That email address is now used by another employee.');
        }
        const empRef = db.collection('employees').doc(req.EmpCode);
        const empSnap = await empRef.get();
        if (!empSnap.exists) throw new Error('The employee account was not found.');
        await empRef.update({ Email: email });
        if (empSnap.data().AuthUid) {
          await db.collection('users').doc(empSnap.data().AuthUid).update({ Email: email }).catch(() => {});
        }
        memoClear();
      }

      await reqRef.update({
        Status: action,
        ReviewedBy: user.EmpCode,
        ReviewedAt: new Date(),
        ReviewNote: tmClip_(note, 500)
      });
      await tmAudit_(user.EmpCode, 'EMAIL_CHANGE_' + action, id, { empCode: req.EmpCode, note: tmClip_(note, 500) });
      return { ok: true };
    },

    // 15. Password & Session
    apiChangePassword: async function (token, currentPw, newPw) {
      const { user, fbUser } = await tmAuth_(token);
      const cfg = await tmConfig_();
      const minLen = Number(cfg.MIN_PASSWORD_LENGTH) || 8;
      if (!newPw || String(newPw).length < minLen) throw new Error(`Password must be at least ${minLen} characters.`);
      if (String(newPw).toLowerCase() === user.EmpCode.toLowerCase()) throw new Error('Password cannot be the same as your employee code.');

      const cred = firebase.auth.EmailAuthProvider.credential(fbUser.email, currentPw);
      try {
        await fbUser.reauthenticateWithCredential(cred);
        await fbUser.updatePassword(newPw);
      } catch (err) {
        throw new Error(mapAuthError_(err));
      }

      if (window.CryptoVault) await window.CryptoVault.rewrapOnPasswordChange(db, user.EmpCode, newPw);
      const nextVer = tmId_('v');
      await db.collection('employees').doc(user.EmpCode).update({ SessionVersion: nextVer, MustChangePassword: 'N' });
      await db.collection('users').doc(fbUser.uid).update({ SessionVersion: nextVer });
      await tmAudit_(user.EmpCode, 'PASSWORD_CHANGE', '', {});
      memoClear();
      return { ok: true };
    },

    apiSignOut: async function () {
      if (window.CryptoVault) window.CryptoVault.clearSession();
      if (initFirebase() && fbAuth) await fbAuth.signOut().catch(() => {});
      memoClear();
      return { ok: true };
    },

    apiSignOutEverywhere: async function (token) {
      const { user, fbUser } = await tmAuth_(token);
      const nextVer = tmId_('v');
      await db.collection('employees').doc(user.EmpCode).update({ SessionVersion: nextVer });
      await db.collection('users').doc(fbUser.uid).update({ SessionVersion: nextVer });
      if (window.CryptoVault) window.CryptoVault.clearSession();
      await fbAuth.signOut().catch(() => {});
      memoClear();
      return { ok: true };
    },

    // 16. Archive, Backup, Self-Test, Repair & Demo Data
    apiArchiveCompletedTasks: async function (token, daysParam) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');

      const cfg = await tmConfig_();
      const days = Number(daysParam) > 0 ? Number(daysParam) : (Number(cfg.ARCHIVE_AFTER_DAYS) || 60);
      const cutoffDay = tmDayKey_(new Date(Date.now() - days * 86400000));
      const snap = await db.collection('tasks').where('Status', '==', 'Completed').get();
      const toArchive = [];
      const now = new Date();

      snap.forEach(d => {
        const t = d.data();
        const doneDate = tmAsDate_(t.CompletedAt) || tmAsDate_(t.UpdatedAt) || tmAsDate_(t.DueDate);
        const doneDay = doneDate ? tmDayKey_(doneDate) : '';
        if (doneDay && doneDay < cutoffDay) toArchive.push({ ref: d.ref, data: t });
      });

      if (!toArchive.length) {
        return { ok: true, archived: 0, message: `No completed tasks older than ${days} days to archive.` };
      }

      let checksCount = 0;
      for (const item of toArchive) {
        const b = db.batch();
        b.set(db.collection('taskArchive').doc(item.data.TaskID), Object.assign({}, item.data, { ArchivedAt: now }));
        b.delete(item.ref);
        const cSnap = await db.collection('checklist').where('TaskID', '==', item.data.TaskID).get();
        cSnap.forEach(c => {
          b.set(db.collection('checklistArchive').doc(c.id), Object.assign({}, c.data(), { ArchivedAt: now }));
          b.delete(c.ref);
          checksCount++;
        });
        await b.commit();
      }

      await db.collection('config').doc('app_config').set({ ARCHIVE_AT: now.toISOString() }, { merge: true });
      memoClear();
      await tmAudit_(user.EmpCode, 'TASKS_ARCHIVED', 'taskArchive', { count: toArchive.length, checklistCount: checksCount, days });
      return { ok: true, archived: toArchive.length, message: `Archived ${toArchive.length} completed task(s) and ${checksCount} checklist item(s) older than ${days} days.` };
    },

    apiRunBackupNow: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');

      const cols = ['config', 'roles', 'regions', 'employees', 'tasks', 'checklist', 'taskTemplates', 'reminderSchedule'];
      const payload = { exportedAt: new Date().toISOString(), projectId: window.FIREBASE_CONFIG.projectId, collections: {} };

      for (const c of cols) {
        const snap = await db.collection(c).get();
        payload.collections[c] = {};
        snap.forEach(d => { payload.collections[c][d.id] = d.data(); });
      }

      const now = new Date();
      const stamp = tmStamp_(now);
      const name = 'TM_Firebase_Backup_' + tmDayKey_(now);
      await db.collection('systemBackups').doc(tmId_('BKP')).set({
        Name: name,
        CreatedBy: user.EmpCode,
        CreatedAt: now,
        TaskCount: Object.keys(payload.collections.tasks || {}).length,
        EmployeeCount: Object.keys(payload.collections.employees || {}).length
      }).catch(() => {});

      await db.collection('config').doc('app_config').set({ LAST_BACKUP: stamp }, { merge: true });
      memoClear();
      await tmAudit_(user.EmpCode, 'BACKUP_CREATED', name, { tasks: Object.keys(payload.collections.tasks || {}).length });
      return { ok: true, name, timestamp: stamp, backup: payload };
    },

    apiRefreshDashboard: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      memoClear();
      const snap = await db.collection('tasks').get();
      return { ok: true, rows: snap.size };
    },

    apiInstallTriggers: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');
      return { ok: true };
    },

    apiRepair: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');

      const repaired = [];
      const stdRoles = tmStandardRolesMap_();
      const roleSnap = await db.collection('roles').get();
      const existingRoles = new Set();
      roleSnap.forEach(d => existingRoles.add(d.id));
      const b = db.batch();
      let addedRoles = 0;
      Object.values(stdRoles).forEach(r => {
        if (!existingRoles.has(r.Role)) {
          b.set(db.collection('roles').doc(r.Role), r);
          addedRoles++;
        }
      });
      if (addedRoles) {
        await b.commit();
        repaired.push(`Added ${addedRoles} standard company role(s)`);
      }

      const regSnap = await db.collection('regions').get();
      if (regSnap.empty) {
        const rb = db.batch();
        TM_REGIONS.forEach(r => rb.set(db.collection('regions').doc(r), { Region: r, Active: true }));
        await rb.commit();
        repaired.push('Seeded default regions');
      }

      const cfgRef = db.collection('config').doc('app_config');
      const cfgSnap = await cfgRef.get();
      if (!cfgSnap.exists) {
        await cfgRef.set(TM_DEFAULTS);
        repaired.push('Initialized app_config defaults');
      }

      // Repair missing WatcherCodes on tasks
      const hier = await tmHierarchy_();
      const tSnap = await db.collection('tasks').get();
      let fixedTasks = 0;
      const tb = db.batch();
      tSnap.forEach(d => {
        const t = d.data();
        if (!Array.isArray(t.WatcherCodes) || !t.WatcherCodes.length) {
          tb.update(d.ref, { WatcherCodes: getWatcherCodes_(t.AssignedTo, t.AssignedBy, hier) });
          fixedTasks++;
        }
      });
      if (fixedTasks) {
        await tb.commit();
        repaired.push(`Updated WatcherCodes on ${fixedTasks} task(s)`);
      }

      memoClear();
      return { ok: true, repaired };
    },

    apiRunSelfTest: async function (token, includeLive) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');

      const started = Date.now();
      const items = [];
      const check = async (group, name, fn) => {
        try {
          const r = await fn();
          if (r && r.warn) items.push({ group, name, status: 'WARN', detail: String(r.warn) });
          else if (r === false) items.push({ group, name, status: 'FAIL', detail: 'Check returned false.' });
          else items.push({ group, name, status: 'PASS', detail: typeof r === 'string' ? r : '' });
        } catch (e) {
          items.push({ group, name, status: 'FAIL', detail: String((e && e.message) || e) });
        }
      };

      // 1. Logic Checks
      await check('Logic', 'Nazim vs Employee permissions', () => {
        const lead = { code: 'L', admin: false, headOffice: false, sub: new Set(['M']) };
        const member = { code: 'M', admin: false, headOffice: false, sub: new Set() };
        const outsider = { code: 'O', admin: false, headOffice: false, sub: new Set() };
        const task = { AssignedTo: 'M', AssignedBy: 'L', Status: 'Pending' };
        if (!tmCanSee_(member, task) || !tmCanUpdate_(member, task) || tmCanManage_(member, task)) throw new Error('Member permissions wrong');
        if (!tmCanManage_(lead, task) || !tmCanDelete_(lead, task)) throw new Error('Nazim permissions wrong');
        if (tmCanManage_(lead, { AssignedTo: 'L', AssignedBy: 'L', Status: 'Pending' })) throw new Error('Nazim self-edit should be false');
        if (tmCanSee_(outsider, task)) throw new Error('Outsider visibility should be false');
        return 'All permission checks passed';
      });

      await check('Logic', 'Circular manager loop detection', () => {
        const cycle = tmFindCycle_({ A: 'B', B: 'C', C: 'A' });
        if (!cycle || cycle.length !== 3) throw new Error('Cycle detection failed');
        if (tmFindCycle_({ A: '', B: 'A', C: 'B' }) !== null) throw new Error('Valid tree flagged as cycle');
        return 'Cycle detection accurate';
      });

      await check('Logic', 'WebCrypto AES-256-GCM encryption vault', async () => {
        if (!window.crypto || !window.crypto.subtle) return { warn: 'WebCrypto unavailable (requires HTTPS or localhost).' };
        if (!window.CryptoVault || !window.CryptoVault.isUnlocked(user.EmpCode)) return { warn: 'Vault locked in current tab; re-login or unlock to use confidential mode.' };
        const dek = await window.CryptoVault.generateDek();
        const enc = await window.CryptoVault.encryptText(dek, 'SelfTest-Secret');
        const dec = await window.CryptoVault.decryptText(dek, enc);
        if (dec !== 'SelfTest-Secret') throw new Error('Decrypt mismatch');
        return 'AES-256-GCM active & unlocked';
      });

      // 2. Setup Checks
      await check('Setup', 'Directory, roles & regions integrity', async () => {
        const h = await tmHierarchy_();
        const roles = await tmRoles_();
        const regs = await tmRegions_();
        const admins = Object.values(h.byCode).filter(e => e.Active === 'Y' && (e.Role === 'Admin' || e.Role === 'System Admin'));
        if (!roles.length || !regs.length) throw new Error('Missing roles or regions. Click Repair setup.');
        if (!admins.length) return { warn: 'No active Admin role user found.' };
        return `${Object.keys(h.byCode).length} employees, ${roles.length} roles, ${regs.length} regions`;
      });

      await check('Setup', 'Email relay configuration', () => {
        const cfg = window.EMAIL_CONFIG || {};
        if (!cfg.appsScriptRelayUrl) return { warn: 'Apps Script Email Relay URL is not configured in firebase-config.js.' };
        return 'Relay URL configured';
      });

      // 3. Live Firestore Check
      if (includeLive) {
        await check('Live', 'Create, update, and clean up test task', async () => {
          const r = await Backend.apiCreateTask(token, { title: 'TEST-SelfCheck', dueDate: tmDayKey_(new Date()), assignedTo: [user.EmpCode], description: 'Automated check' });
          if (!r.ok || !r.taskId) throw new Error('Create failed');
          await Backend.apiUpdateTask(token, r.taskId, { status: 'Completed' });
          await db.collection('tasks').doc(r.taskId).delete();
          return 'Round-trip Firestore write/update/cleanup OK';
        });
      }

      const summary = { pass: 0, warn: 0, fail: 0, total: items.length, seconds: Math.round((Date.now() - started) / 100) / 10 };
      items.forEach(x => { summary[x.status.toLowerCase()]++; });
      return { ok: true, summary, items };
    },

    apiDemoData: async function (token, action) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Administrator access is required.');

      // Helper to purge DEMO- records
      const purgeDemo = async () => {
        let pCount = 0, tCount = 0;
        const empSnap = await db.collection('employees').get();
        const batch = db.batch();
        empSnap.forEach(d => {
          if (d.id.indexOf('DEMO-') === 0) {
            batch.delete(d.ref);
            batch.delete(db.collection('authLookup').doc(d.id));
            pCount++;
          }
        });
        const tSnap = await db.collection('tasks').get();
        const goneIds = [];
        tSnap.forEach(d => {
          const t = d.data();
          if (d.id.indexOf('TSK-DEMO-') === 0 || String(t.AssignedTo).indexOf('DEMO-') === 0) {
            batch.delete(d.ref);
            goneIds.push(d.id);
            tCount++;
          }
        });
        await batch.commit();
        for (const tid of goneIds) {
          const cs = await db.collection('checklist').where('TaskID', '==', tid).get();
          const cb = db.batch();
          cs.forEach(c => cb.delete(c.ref));
          if (!cs.empty) await cb.commit();
        }
        memoClear();
        return { people: pCount, tasks: tCount };
      };

      if (action === 'remove') {
        const res = await purgeDemo();
        return Object.assign({ ok: true }, res);
      }

      await purgeDemo();
      const regs = (await tmRegions_()).filter(r => r.Active).map(r => r.Region);
      const region = regs[0] || 'Mumbai';
      const now = new Date();
      const demoPeople = [
        { EmpCode: 'DEMO-RAS', EmpName: 'Demo Region Supervisor', Nazim: '', Role: 'Region Accountant Supervisor' },
        { EmpCode: 'DEMO-AS', EmpName: 'Demo Accountant Supervisor', Nazim: 'DEMO-RAS', Role: 'Accountant Supervisor' },
        { EmpCode: 'DEMO-AC1', EmpName: 'Demo Accountant One', Nazim: 'DEMO-AS', Role: 'Accountant' },
        { EmpCode: 'DEMO-AC2', EmpName: 'Demo Accountant Two', Nazim: 'DEMO-AS', Role: 'Accountant' }
      ];
      const batch = db.batch();
      demoPeople.forEach(p => {
        batch.set(db.collection('employees').doc(p.EmpCode), {
          EmpCode: p.EmpCode, EmpName: p.EmpName, Nazim: p.Nazim, Division: 'Demo', Region: region,
          Role: p.Role, Email: `${p.EmpCode.toLowerCase()}@example.invalid`, Active: 'Y', SessionVersion: '1', CreatedAt: now
        });
      });
      await batch.commit();
      memoClear();
      const hier = await tmHierarchy_();

      const dayOffset = d => new Date(Date.now() + d * 86400000);
      const specs = [
        ['Prepare salary register', 'Prepare the monthly salary register.', 'DEMO-AC1', 'DEMO-AS', 3, 'In Progress', ['Collect attendance', 'Cross-check totals']],
        ['Upload donor list', 'Update donor list in the system.', 'DEMO-AC1', 'DEMO-AS', -2, 'Pending', ['Export from software', 'Remove duplicates']],
        ['Bank reconciliation', 'Match bank statement with ERP entries.', 'DEMO-AC2', 'DEMO-AS', 0, 'Pending', []],
        ['File TDS return', 'Prepare and review quarterly TDS return.', 'DEMO-AC2', 'DEMO-AS', -5, 'In Progress', ['Verify challans', 'Prepare file']],
        ['Month-end closing checklist', 'Close the books for the month.', 'DEMO-AC2', 'DEMO-AS', -1, 'Completed', ['Post journals', 'Lock period']]
      ];
      const tb = db.batch();
      specs.forEach((s, i) => {
        const id = 'TSK-DEMO-' + (1000 + i);
        tb.set(db.collection('tasks').doc(id), {
          TaskID: id, Title: s[0], Description: s[1], AssignedBy: s[3], AssignedTo: s[2],
          Region: region, Division: 'Demo', DueDate: dayOffset(s[4]), Status: s[5],
          IsConfidential: false, FileCount: 0, WatcherCodes: getWatcherCodes_(s[2], s[3], hier),
          CreatedAt: now, UpdatedAt: now, CompletedAt: s[5] === 'Completed' ? now : null, LastReminderAt: null, ReminderCount: 0
        });
        s[6].forEach((text, j) => {
          const itemId = tmId_('ITM');
          tb.set(db.collection('checklist').doc(itemId), {
            ItemID: itemId, TaskID: id, Text: text,
            IsDone: s[5] === 'Completed' || (s[5] === 'In Progress' && j === 0) ? 'Y' : 'N',
            DoneAt: null, SortOrder: j + 1, WatcherCodes: getWatcherCodes_(s[2], s[3], hier)
          });
        });
      });
      await tb.commit();
      memoClear();
      return { ok: true, password: 'Demo accounts (display/analytics only)', people: demoPeople.length, tasks: specs.length };
    },

    // Legacy Google-Sheet-only import buttons: give clear Firebase guidance
    apiImportEmployees: async function () {
      return {
        ok: false,
        errors: ['Bulk spreadsheet import is for the Google Sheets edition. Use "+ Add person" above to create Firebase Auth accounts directly, or run AppsScript_Data_Migrator.gs for initial migration.']
      };
    },
    apiClearEmployeesImport: async function () { return { ok: true, message: 'No import sheet needed in Firebase Edition.' }; },
    apiCredentialRecipients: async function () { return { ok: true, recipients: [] }; },
    apiSendImportedCredentials: async function () { throw new Error('Passwords are stored securely in Firebase Authentication. Use "Send Reset Email" inside a person\'s profile.'); }
  };

  window.FirebaseBackend = Backend;
  window.initFirebaseBackend = initFirebase;
})();
