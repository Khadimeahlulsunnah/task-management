// =============================================================================
// FIREBASE BACKEND ADAPTER (V17.1 - Hardened Auth + End-to-End Encryption)
// =============================================================================
// Phase 1 Security Upgrade:
//   - Real Firebase Email/Password Authentication (no anonymous bypass)
//   - Server-verified UID -> /users/{uid} identity & role mapping
//   - Secondary Firebase App worker so Admins can create users without logging out
//   - One-time seamless migration for legacy V17 accounts (wipes old hashes/passwords)
//   - End-to-End Encryption (AES-256-GCM + RSA-OAEP) for confidential tasks & files
// =============================================================================

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
  const MAX_FILES_PER_TASK = 5;

  let fbApp = null;
  let db = null;
  let fbAuth = null;
  let isConfigured = false;
  let authReadyPromise = null;

  let _MEMO = {};
  function memoGet(key, fn) {
    if (!Object.prototype.hasOwnProperty.call(_MEMO, key)) _MEMO[key] = fn();
    return _MEMO[key];
  }
  function memoClear() { _MEMO = {}; }

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

  // Cryptographic Helpers (only used for one-time legacy account migration)
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

  function mapAuthError_(err) {
    const code = err && err.code ? err.code : '';
    if (code === 'auth/too-many-requests') {
      return 'Too many failed login attempts. Please wait a few minutes and try again.';
    }
    if (code === 'auth/wrong-password' || code === 'auth/invalid-credential' || code === 'auth/user-not-found') {
      return 'Invalid Employee Code / Email or password.';
    }
    if (code === 'auth/user-disabled') {
      return 'This account has been disabled. Contact your administrator.';
    }
    if (code === 'auth/weak-password') {
      return 'Password must be at least 6 characters (8+ recommended).';
    }
    if (code === 'auth/email-already-in-use') {
      return 'An account with this email already exists.';
    }
    if (code === 'auth/operation-not-allowed') {
      return 'Email/Password sign-in is not enabled in Firebase Console -> Authentication -> Sign-in method.';
    }
    if (code === 'auth/operation-not-supported-in-this-environment') {
      return 'Firebase Auth cannot run from a local file:// URL. Open your GitHub Pages link or run a local web server (e.g. npx serve).';
    }
    return err && err.message ? err.message : 'Authentication failed.';
  }

  // Verify real Firebase Auth user + /users/{uid} profile + active employee status
  async function tmAuth_() {
    const fbUser = await waitForFirebaseUser_();
    if (!fbUser) throw new Error('Please sign in again.');

    const userSnap = await db.collection('users').doc(fbUser.uid).get();
    if (!userSnap.exists) {
      throw new Error('Your account profile is missing. Please sign in again.');
    }
    const profile = userSnap.data();
    if (profile.Active !== 'Y') {
      throw new Error('This account is not active. Please contact your administrator.');
    }

    const hier = await tmHierarchy_();
    const emp = hier.byCode[String(profile.EmpCode)];
    if (!emp || emp.Active !== 'Y') {
      throw new Error('This account is not active. Please contact your administrator.');
    }
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

  function tmYes_(v) { return v === true || String(v).toUpperCase() === 'Y'; }
  function tmYN_(v) { return tmYes_(v) ? 'Y' : 'N'; }
  function tmId_(prefix) { return prefix + '-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7); }
  function tmClip_(s, n) { return String(s == null ? '' : s).trim().slice(0, n); }

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

  function authEmailFor_(empCode, email) {
    const clean = String(email || '').trim().toLowerCase();
    return clean || (String(empCode).toLowerCase() + '@tm.internal');
  }

  // ================= Seed / Bootstrap Helpers =================
  async function tmEnsureSeedLists_() {
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

    const regSnap = await db.collection('regions').get();
    if (regSnap.empty) {
      const b = db.batch();
      TM_REGIONS.forEach(r => b.set(db.collection('regions').doc(r), { Region: r, Active: true }));
      await b.commit();
    }
  }

  async function syncUserMapping_(uid, empData, roles) {
    const roleObj = (roles || []).find(x => x.Role === empData.Role && x.Active) || {};
    const isAdmin = empData.Role === 'Admin' || !!roleObj.IsAdmin;
    const isHeadOffice = !!roleObj.IsHeadOffice;
    const email = authEmailFor_(empData.EmpCode, empData.Email);

    const batch = db.batch();
    batch.set(db.collection('users').doc(uid), {
      uid,
      EmpCode: empData.EmpCode,
      Email: email,
      Role: empData.Role || 'Employee',
      Nazim: empData.Nazim || '',
      Region: empData.Region || '',
      Division: empData.Division || '',
      Active: empData.Active === 'Y' ? 'Y' : 'N',
      IsAdmin: isAdmin,
      IsHeadOffice: isHeadOffice,
      SessionVersion: String(empData.SessionVersion || '1'),
      UpdatedAt: new Date()
    }, { merge: true });

    batch.set(db.collection('authLookup').doc(empData.EmpCode), {
      email,
      migrated: true
    });
    await batch.commit();
  }

  // Create a Firebase Auth user using a secondary app instance so Admin stays signed in
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

  // ================= Roles & Hierarchy =================
  async function tmRoles_() {
    return memoGet('roles', async () => {
      if (!initFirebase()) return [];
      const snap = await db.collection('roles').get();
      const roles = [];
      snap.forEach(d => roles.push(d.data()));
      return roles;
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
          AuthUid: String(e.AuthUid || '').trim(),
          MustChangePassword: tmYN_(e.MustChangePassword),
          Active: tmYN_(e.Active),
          SessionVersion: String(e.SessionVersion || '1')
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
    const admin = user.Role === 'Admin' || !!r.IsAdmin;
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
    Object.keys(hier.byCode).forEach(c => {
      const e = hier.byCode[c];
      if (e.Active === 'Y' && privilegedRoles.has(e.Role)) {
        codes.add(c);
      }
    });
    return Array.from(codes);
  }

  async function fetchPublicKeys_(codes) {
    const map = {};
    await Promise.all(codes.map(async c => {
      try {
        const snap = await db.collection('userKeys').doc(String(c)).get();
        if (snap.exists && snap.data().publicKeyJwk) {
          map[String(c)] = snap.data().publicKeyJwk;
        }
      } catch (e) { /* Ignore missing keys for users who haven't logged in yet */ }
    }));
    return map;
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

  // ================= Checklists & Decryption =================
  async function tmChecklistFor_(taskIds, taskMap, viewerCode) {
    if (!taskIds.length) return {};
    const map = {};
    taskIds.forEach(id => { map[String(id)] = []; });

    const chunks = [];
    for (let i = 0; i < taskIds.length; i += 30) {
      chunks.push(taskIds.slice(i, i + 30));
    }

    const dekCache = {};
    for (const chunk of chunks) {
      const snap = await db.collection('checklist').where('TaskID', 'in', chunk).get();
      for (const d of snap.docs) {
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
              if (dekCache[tid]) {
                text = await window.CryptoVault.decryptText(dekCache[tid], x.TextEnc);
              }
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

  // ================= Secure Email Dispatch =================
  async function tmSendEmail_(to, subject, htmlBody, textBody) {
    const cfg = window.EMAIL_CONFIG || {};
    if (cfg.appsScriptRelayUrl && fbAuth && fbAuth.currentUser) {
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
      } catch (e) { console.warn('Apps Script mail relay error:', e); }
    }
    return { ok: false, error: 'Email relay not configured or user not signed in' };
  }

  // ================= Public API Implementation =================
  const Backend = {
    // 1. Real Firebase Authentication Login (+ seamless first-time setup / legacy migration)
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
        } catch (e) { /* Ignore lookup miss */ }
      }

      let fbUser = null;

      // Path A: Try real Firebase Auth sign-in directly
      if (email) {
        try {
          const cred = await fbAuth.signInWithEmailAndPassword(email, pw);
          fbUser = cred.user;
        } catch (err) {
          if (err && (err.code === 'auth/operation-not-allowed' || err.code === 'auth/operation-not-supported-in-this-environment' || err.code === 'auth/too-many-requests')) {
            return { ok: false, error: mapAuthError_(err) };
          }
          if (migrated) {
            return { ok: false, error: mapAuthError_(err) };
          }
          // Fall through only if not marked migrated yet
        }
      }

      // Path B: Brand-new DB bootstrap OR one-time legacy account migration
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

          if (!legacyMatch) {
            return { ok: false, error: 'Invalid Employee Code / Email or password.' };
          }

          const targetEmail = authEmailFor_(legacyDoc.EmpCode, legacyDoc.Email);
          try {
            const cred = await fbAuth.createUserWithEmailAndPassword(targetEmail, pw);
            fbUser = cred.user;
          } catch (createErr) {
            if (createErr && createErr.code === 'auth/email-already-in-use') {
              try {
                const cred2 = await fbAuth.signInWithEmailAndPassword(targetEmail, pw);
                fbUser = cred2.user;
              } catch (e2) {
                return { ok: false, error: mapAuthError_(e2) };
              }
            } else {
              return { ok: false, error: mapAuthError_(createErr) };
            }
          }

          // IMPORTANT: Write /users/{uid} and /employees/{EmpCode}.AuthUid BEFORE reading /roles
          // because Firestore rules require /users/{uid} to exist for isActiveUser()!
          const seedRole = [{
            Role: legacyDoc.Role || 'Employee',
            IsAdmin: legacyDoc.Role === 'Admin',
            IsHeadOffice: legacyDoc.Role === 'Admin',
            Active: true
          }];
          await syncUserMapping_(fbUser.uid, Object.assign({}, legacyDoc, { Active: tmYN_(legacyDoc.Active) }), seedRole);
          await db.collection('employees').doc(legacyDoc.EmpCode).update({
            AuthUid: fbUser.uid,
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
            await syncUserMapping_(fbUser.uid, Object.assign({}, legacyDoc, { Active: tmYN_(legacyDoc.Active) }), roles).catch(() => {});
          }
        } else if ((upperCode === 'ADMIN' || email === 'admin@taskmanagement.local') && pw === 'admin123') {
          // Brand-new database first-time ADMIN setup
          let adminExists = false;
          try {
            const checkAdmin = await db.collection('employees').doc('ADMIN').get();
            adminExists = checkAdmin.exists;
          } catch (e) {
            adminExists = true; // Rule blocked unauthenticated read => ADMIN already exists & is migrated
          }
          if (adminExists) {
            return { ok: false, error: 'Invalid Employee Code / Email or password.' };
          }
          try {
            const cred = await fbAuth.createUserWithEmailAndPassword('admin@taskmanagement.local', pw);
            fbUser = cred.user;
          } catch (createErr) {
            if (createErr && createErr.code === 'auth/email-already-in-use') {
              try {
                const cred2 = await fbAuth.signInWithEmailAndPassword('admin@taskmanagement.local', pw);
                fbUser = cred2.user;
              } catch (e2) {
                return { ok: false, error: mapAuthError_(e2) };
              }
            } else {
              return { ok: false, error: mapAuthError_(createErr) };
            }
          }
          const adminRecord = {
            EmpCode: 'ADMIN',
            EmpName: 'Administrator',
            Nazim: '',
            Division: 'Head Office',
            Region: 'Mumbai',
            Role: 'Admin',
            Email: 'admin@taskmanagement.local',
            AuthUid: fbUser.uid,
            MustChangePassword: 'N',
            Active: 'Y',
            SessionVersion: '1',
            CreatedAt: new Date()
          };
          await db.collection('employees').doc('ADMIN').set(adminRecord);
          await syncUserMapping_(fbUser.uid, adminRecord, [{ Role: 'Admin', IsAdmin: true, IsHeadOffice: true, Active: true }]);
          await tmEnsureSeedLists_();
        } else if (isEmailLogin) {
          return { ok: false, error: 'Invalid credentials, or if this is your first login after the security update, sign in once with your Employee Code (e.g. ADMIN).' };
        } else {
          return { ok: false, error: 'Invalid Employee Code / Email or password.' };
        }
      }

      // Ensure user mapping exists and account is active
      const userSnap = await db.collection('users').doc(fbUser.uid).get();
      if (!userSnap.exists || userSnap.data().Active !== 'Y') {
        await fbAuth.signOut().catch(() => {});
        return { ok: false, error: 'This account is not active. Please contact your administrator.' };
      }

      const empCode = userSnap.data().EmpCode;
      if (window.CryptoVault) {
        try {
          await window.CryptoVault.initForUser(db, empCode, pw);
        } catch (vaultErr) {
          console.warn('CryptoVault init warning:', vaultErr);
        }
      }

      await db.collection('employees').doc(empCode).update({ LastLogin: new Date() }).catch(() => {});
      memoClear();
      const token = 'fb:' + fbUser.uid;
      const boot = await Backend.apiBootstrap(token);
      return Object.assign({ ok: true, token }, boot);
    },

    // 2. Bootstrap
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
        app: { name: 'Task Management', version: '17.1.0 (Secured + Encrypted)', sessionDays: 30 },
        user: {
          EmpCode: me.EmpCode,
          EmpName: me.EmpName,
          Role: me.Role,
          Region: me.Region,
          Division: me.Division,
          Email: me.Email,
          Nazim: me.Nazim,
          NazimName: boss ? boss.EmpName : '',
          isAdmin: me.Role === 'Admin' || !!r.IsAdmin,
          isHeadOffice: !!r.IsHeadOffice,
          isNazim: (hier.children[me.EmpCode] || []).length > 0,
          hasTeam: (me.Role === 'Admin' || !!r.IsAdmin) || (hier.children[me.EmpCode] || []).length > 0,
          vaultUnlocked: window.CryptoVault ? window.CryptoVault.isUnlocked(me.EmpCode) : false
        },
        mustChangePassword: false
      };

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

      const regSnap = await db.collection('regions').where('Active', '==', true).get();
      const regList = [];
      regSnap.forEach(d => regList.push(d.data().Region));

      out.lists = {
        regions: regList.length ? regList : TM_REGIONS,
        divisions: Object.keys(divisions).sort(),
        roles: roles.filter(x => x.Active).map(x => x.Role),
        statuses: TM_STATUSES
      };

      out.mine = await Backend.apiListTasks(token, { scope: 'mine' });
      out.team = null;
      return out;
    },

    // Unlock CryptoVault if page was reopened in a new browser tab while Firebase Auth persisted
    apiUnlockVault: async function (token, password) {
      const { user, fbUser } = await tmAuth_(token);
      if (!password) throw new Error('Enter your password to unlock encrypted items.');
      const cred = firebase.auth.EmailAuthProvider.credential(fbUser.email, password);
      try {
        await fbUser.reauthenticateWithCredential(cred);
      } catch (e) {
        throw new Error('Incorrect password.');
      }
      if (window.CryptoVault) {
        await window.CryptoVault.initForUser(db, user.EmpCode, password);
      }
      return { ok: true, unlocked: true };
    },

    // 3. List Tasks (Rule-compliant queries for Admin, Nazim, and Employee)
    apiListTasks: async function (token, filters) {
      const { user } = await tmAuth_(token);
      filters = filters || {};
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();
      const byCode = hier.byCode;
      const scope = filters.scope === 'team' ? 'team' : 'mine';

      const taskMap = {};
      if (scope === 'mine') {
        const snap = await db.collection('tasks').where('AssignedTo', '==', access.code).get();
        snap.forEach(d => { taskMap[d.id] = Object.assign({ id: d.id }, d.data()); });
      } else {
        if (!access.admin && !access.headOffice && (hier.children[user.EmpCode] || []).length === 0) {
          throw new Error('Team task access is limited to Nazim users.');
        }
        if (access.admin || access.headOffice) {
          const snap = await db.collection('tasks').get();
          snap.forEach(d => { taskMap[d.id] = Object.assign({ id: d.id }, d.data()); });
        } else {
          // Query via WatcherCodes AND direct/subordinate AssignedTo batches (supports legacy docs too)
          const queries = [
            db.collection('tasks').where('WatcherCodes', 'array-contains', access.code).get(),
            db.collection('tasks').where('AssignedBy', '==', access.code).get()
          ];
          const subList = Array.from(access.sub);
          for (let i = 0; i < subList.length; i += 30) {
            queries.push(db.collection('tasks').where('AssignedTo', 'in', subList.slice(i, i + 30)).get());
          }
          const snaps = await Promise.all(queries);
          snaps.forEach(s => s.forEach(d => { taskMap[d.id] = Object.assign({ id: d.id }, d.data()); }));
        }
      }

      const allTasks = Object.values(taskMap);
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
      const checklist = await tmChecklistFor_(page.map(t => t.TaskID), pageMap, access.code);
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

    // 4. Create Task (Supports End-to-End Encrypted Confidential Tasks)
    apiCreateTask: async function (token, data) {
      const { user } = await tmAuth_(token);
      data = data || {};
      const hier = await tmHierarchy_();
      const directory = hier.byCode;
      const now = new Date();
      const isConfidential = !!data.confidential;

      if (isConfidential && (!window.CryptoVault || !window.CryptoVault.isUnlocked(user.EmpCode))) {
        throw new Error('Encryption vault is locked. Please unlock or sign in again to create confidential tasks.');
      }

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
      const taskRecords = [];

      for (const target of targets) {
        const emp = directory[target] || {};
        const watcherCodes = getWatcherCodes_(target, user.EmpCode, hier);

        let allowedCodes = watcherCodes;
        let recipientJwks = null;
        if (isConfidential) {
          allowedCodes = await getAllowedKeyCodes_(target, user.EmpCode, hier);
          recipientJwks = await fetchPublicKeys_(allowedCodes);
        }

        for (const pt of parsedTasks) {
          const taskId = 'TSK-' + tmDayKey_(now).replace(/-/g, '') + '-' + Math.random().toString(36).slice(2, 8).toUpperCase();
          taskIds.push(taskId);

          let taskData;
          let dek = null;
          if (isConfidential) {
            dek = await window.CryptoVault.generateDek();
            const keyEnvelopes = await window.CryptoVault.wrapDekForRecipients(dek, recipientJwks);
            const titleEnc = await window.CryptoVault.encryptText(dek, pt.title);
            const descEnc = pt.description ? await window.CryptoVault.encryptText(dek, pt.description) : null;

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
              AssignedTo: target,
              Region: emp.Region || '',
              Division: emp.Division || '',
              DueDate: pt.due,
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
              Title: pt.title,
              Description: pt.description,
              IsConfidential: false,
              WatcherCodes: watcherCodes,
              AssignedBy: user.EmpCode,
              AssignedTo: target,
              Region: emp.Region || '',
              Division: emp.Division || '',
              DueDate: pt.due,
              Status: 'Pending',
              FileCount: 0,
              CreatedAt: now,
              UpdatedAt: now,
              CompletedAt: null,
              LastReminderAt: null,
              ReminderCount: 0
            };
          }

          batch.set(db.collection('tasks').doc(taskId), taskData);
          taskRecords.push({ taskId, target, watcherCodes });

          for (let idx = 0; idx < pt.steps.length; idx++) {
            const step = pt.steps[idx];
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
            if (isConfidential && dek) {
              itemDoc.TextEnc = await window.CryptoVault.encryptText(dek, step);
            }
            batch.set(db.collection('checklist').doc(itemId), itemDoc);
          }

          batch.set(db.collection('taskHistory').doc(), {
            Timestamp: now,
            TaskID: taskId,
            ActorEmpCode: user.EmpCode,
            ActorName: user.EmpName,
            Action: 'TASK_CREATED',
            Details: JSON.stringify({ assignedTo: target, confidential: isConfidential }),
            WatcherCodes: watcherCodes
          });
        }
      }

      await batch.commit();

      if (data.notify) {
        targets.forEach(async target => {
          if (target === user.EmpCode) return;
          const person = directory[target];
          if (person && person.Email) {
            const count = parsedTasks.length;
            const sub = isConfidential
              ? `New Confidential Task Assigned (${count})`
              : (count === 1 ? `New Task Assigned: ${parsedTasks[0].title}` : `${count} New Tasks Assigned`);
            const html = `<p>Salam ${person.EmpName},</p><p>You have been assigned ${count} new ${isConfidential ? 'confidential ' : ''}task(s) by ${user.EmpName}.</p>`;
            await tmSendEmail_(person.Email, sub, html, html);
          }
        });
      }

      return { ok: true, taskId: taskIds[0], taskIds, count: taskIds.length, recipients: targets.length };
    },

    // 5. Update Task (Handles status, details, checklist toggle, and confidential encryption)
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

      // Checklist item toggles
      if (Array.isArray(changes.checklist)) {
        if (!tmCanUpdate_(access, task)) throw new Error('You cannot update this task.');
        changes.checklist.forEach(c => {
          if (!c || !c.id) return;
          batch.update(db.collection('checklist').doc(String(c.id)), {
            IsDone: c.done ? 'Y' : 'N',
            DoneAt: c.done ? now : null
          });
        });
      }

      const nextStatus = changes.status || changes.Status;
      if (nextStatus && nextStatus !== task.Status) {
        if (!tmCanUpdate_(access, task)) throw new Error('You cannot change the status of this task.');
        const isReopen = task.Status === 'Completed' && nextStatus !== 'Completed';
        updates.Status = nextStatus;
        if (nextStatus === 'Completed') {
          updates.CompletedAt = now;
          const checks = await db.collection('checklist').where('TaskID', '==', id).get();
          checks.forEach(c => batch.update(c.ref, { IsDone: 'Y', DoneAt: now }));
        } else {
          updates.CompletedAt = null;
        }
        batch.set(db.collection('taskHistory').doc(), {
          Timestamp: now,
          TaskID: id,
          ActorEmpCode: user.EmpCode,
          ActorName: user.EmpName,
          Action: isReopen ? 'TASK_REOPENED' : 'TASK_STATUS_CHANGED',
          Details: JSON.stringify({ from: task.Status, status: nextStatus, remark: changes.remark || '' }),
          WatcherCodes: watcherCodes
        });
      }

      const nextTitle = changes.title !== undefined ? changes.title : changes.Title;
      const nextDesc = changes.description !== undefined ? changes.description : changes.Description;
      const nextDue = changes.dueDate !== undefined ? changes.dueDate : changes.DueDate;
      const nextAssigned = changes.assignedTo !== undefined ? changes.assignedTo : changes.AssignedTo;

      if (nextTitle !== undefined || nextDesc !== undefined || nextDue !== undefined || nextAssigned !== undefined) {
        if (!tmCanManage_(access, task)) throw new Error('You do not have permission to edit this task.');
        if (task.IsConfidential) {
          if (!window.CryptoVault || !window.CryptoVault.isUnlocked(user.EmpCode)) {
            throw new Error('Unlock your encryption vault before editing a confidential task.');
          }
          const dek = await window.CryptoVault.unwrapDekFromEnvelopes(task.KeyEnvelopes, user.EmpCode);
          if (!dek) throw new Error('Missing encryption key for this confidential task.');
          if (nextTitle !== undefined) updates.TitleEnc = await window.CryptoVault.encryptText(dek, tmClip_(nextTitle, 200));
          if (nextDesc !== undefined) updates.DescriptionEnc = await window.CryptoVault.encryptText(dek, tmClip_(nextDesc, 2000));
        } else {
          if (nextTitle !== undefined) updates.Title = tmClip_(nextTitle, 200);
          if (nextDesc !== undefined) updates.Description = tmClip_(nextDesc, 2000);
        }
        if (nextDue !== undefined) updates.DueDate = nextDue ? new Date(nextDue) : null;
        if (nextAssigned !== undefined) {
          const target = String(nextAssigned);
          if (!(await tmCanAssign_(user, target))) throw new Error(`You cannot assign a task to ${target}.`);
          updates.AssignedTo = target;
          updates.WatcherCodes = getWatcherCodes_(target, task.AssignedBy, hier);
        }
      }

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
      let updated = 0;
      const failed = [];

      for (const id of ids) {
        const docRef = db.collection('tasks').doc(id);
        const snap = await docRef.get();
        if (!snap.exists) { failed.push({ id, reason: 'Not found' }); continue; }
        const t = snap.data();
        if (!tmCanUpdate_(access, t)) { failed.push({ id, reason: 'Permission denied' }); continue; }
        const updates = { Status: status, UpdatedAt: now };
        updates.CompletedAt = status === 'Completed' ? now : null;
        batch.update(docRef, updates);
        batch.set(db.collection('taskHistory').doc(), {
          Timestamp: now,
          TaskID: id,
          ActorEmpCode: user.EmpCode,
          ActorName: user.EmpName,
          Action: 'TASK_STATUS_CHANGED',
          Details: JSON.stringify({ status, remark: remark || '' }),
          WatcherCodes: t.WatcherCodes || [t.AssignedTo, t.AssignedBy]
        });
        updated++;
      }
      await batch.commit();
      return { ok: true, count: updated, updated, failed };
    },

    // 7. Delete Task (+ its encrypted attachments)
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
      const checks = await db.collection('checklist').where('TaskID', '==', id).get();
      checks.forEach(c => batch.delete(c.ref));

      const filesSnap = await db.collection('taskFiles').where('TaskID', '==', id).get();
      for (const fDoc of filesSnap.docs) {
        const chunksSnap = await fDoc.ref.collection('chunks').get();
        chunksSnap.forEach(ch => batch.delete(ch.ref));
        batch.delete(fDoc.ref);
      }

      await batch.commit();
      return { ok: true };
    },

    // 8. Checklist Management
    apiAddChecklistItem: async function (token, taskId, text) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const taskSnap = await db.collection('tasks').doc(taskId).get();
      if (!taskSnap.exists) throw new Error('Task no longer exists.');
      const task = taskSnap.data();
      if (!tmCanManage_(access, task)) throw new Error('You cannot edit this task.');

      const cleanText = tmClip_(text, 200);
      const itemId = tmId_('ITM');
      const item = {
        ItemID: itemId,
        TaskID: taskId,
        Text: task.IsConfidential ? '[Confidential Step]' : cleanText,
        IsConfidential: !!task.IsConfidential,
        IsDone: 'N',
        DoneAt: null,
        SortOrder: Date.now(),
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
      return { ok: true, item: { id: itemId, text: cleanText, done: false, order: item.SortOrder } };
    },

    apiRemoveChecklistItem: async function (token, taskId, itemId) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const taskSnap = await db.collection('tasks').doc(taskId).get();
      if (taskSnap.exists && !tmCanManage_(access, taskSnap.data())) {
        throw new Error('You cannot edit this task.');
      }
      await db.collection('checklist').doc(itemId).delete();
      return { ok: true };
    },

    // 9. Confidential Encrypted File Attachments (End-to-End AES-256-GCM)
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

      const existing = await db.collection('taskFiles').where('TaskID', '==', taskId).get();
      if (existing.size >= MAX_FILES_PER_TASK) {
        throw new Error(`Maximum ${MAX_FILES_PER_TASK} encrypted files allowed per task.`);
      }

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
          idx: i,
          iv: enc.chunks[i].iv,
          ct: enc.chunks[i].ct,
          AllowedCodes: allowedCodes
        });
      }

      await db.collection('tasks').doc(taskId).update({
        FileCount: existing.size + 1,
        UpdatedAt: now
      });

      return {
        ok: true,
        file: {
          FileID: fileId,
          name: file.name,
          sizeBytes: file.size,
          uploadedBy: user.EmpName,
          created: tmStamp_(now)
        }
      };
    },

    apiListTaskFiles: async function (token, taskId) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const taskSnap = await db.collection('tasks').doc(taskId).get();
      if (!taskSnap.exists) throw new Error('Task no longer exists.');
      if (!tmCanSee_(access, taskSnap.data())) throw new Error('Access denied.');

      const snap = await db.collection('taskFiles').where('TaskID', '==', taskId).get();
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
      if (taskSnap.exists && !tmCanSee_(access, taskSnap.data())) {
        throw new Error('You do not have access to this file.');
      }

      const chunksSnap = await fileRef.collection('chunks').orderBy('idx', 'asc').get();
      const chunkPayloads = [];
      chunksSnap.forEach(c => chunkPayloads.push(c.data()));

      const decrypted = await window.CryptoVault.decryptFileRecord(meta, chunkPayloads, access.code);
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
      const chunksSnap = await fileRef.collection('chunks').get();
      chunksSnap.forEach(c => batch.delete(c.ref));
      batch.delete(fileRef);
      await batch.commit();

      if (taskSnap.exists) {
        const rem = await db.collection('taskFiles').where('TaskID', '==', meta.TaskID).get();
        await db.collection('tasks').doc(meta.TaskID).update({ FileCount: rem.size });
      }
      return { ok: true };
    },

    // 10. Task History & Notifications
    apiTaskHistory: async function (token, taskId) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const taskSnap = await db.collection('tasks').doc(taskId).get();
      if (!taskSnap.exists) throw new Error('Task no longer exists.');
      if (!tmCanSee_(access, taskSnap.data())) throw new Error('Access denied.');

      const snap = await db.collection('taskHistory')
        .where('TaskID', '==', taskId)
        .orderBy('Timestamp', 'desc')
        .limit(50)
        .get();
      const events = [];
      snap.forEach(d => {
        const ev = d.data();
        events.push({
          actor: ev.ActorName || ev.ActorEmpCode,
          action: ev.Action,
          details: ev.Details || '{}',
          time: tmStamp_(ev.Timestamp)
        });
      });
      return { ok: true, events };
    },

    apiGetNotifications: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const q = (access.admin || access.headOffice)
        ? db.collection('taskHistory').orderBy('Timestamp', 'desc').limit(50)
        : db.collection('taskHistory').where('WatcherCodes', 'array-contains', access.code).orderBy('Timestamp', 'desc').limit(50);

      const snap = await q.get();
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

    // 11. Dashboard Analytics
    apiDashboardData: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      const hier = await tmHierarchy_();

      const taskMap = {};
      if (access.admin || access.headOffice) {
        const snap = await db.collection('tasks').get();
        snap.forEach(d => { taskMap[d.id] = d.data(); });
      } else {
        const queries = [
          db.collection('tasks').where('WatcherCodes', 'array-contains', access.code).get(),
          db.collection('tasks').where('AssignedTo', '==', access.code).get(),
          db.collection('tasks').where('AssignedBy', '==', access.code).get()
        ];
        const snaps = await Promise.all(queries);
        snaps.forEach(s => s.forEach(d => { taskMap[d.id] = d.data(); }));
      }

      const visible = [];
      Object.values(taskMap).forEach(t => {
        if (tmCanSee_(access, t)) {
          const emp = hier.byCode[String(t.AssignedTo)] || {};
          visible.push({ task: t, employee: emp, overdue: tmOverdue_(t.DueDate, t.Status) });
        }
      });

      const counts = { Pending: 0, 'In Progress': 0, Completed: 0, Overdue: 0, Total: visible.length };
      const byRegion = {}, byLocation = {}, byRole = {};

      visible.forEach(x => {
        const t = x.task, e = x.employee;
        counts[t.Status] = (counts[t.Status] || 0) + 1;
        if (x.overdue) counts.Overdue++;

        const reg = String(e.Region || 'Unassigned');
        byRegion[reg] = byRegion[reg] || { label: reg, total: 0, open: 0, completed: 0 };
        byRegion[reg].total++;
        if (t.Status === 'Completed') byRegion[reg].completed++; else byRegion[reg].open++;

        const div = String(e.Division || 'Unassigned');
        byLocation[div] = byLocation[div] || { label: div, total: 0, open: 0, completed: 0 };
        byLocation[div].total++;
        if (t.Status === 'Completed') byLocation[div].completed++; else byLocation[div].open++;

        const role = String(e.Role || 'Unassigned');
        byRole[role] = byRole[role] || { label: role, total: 0, open: 0, completed: 0 };
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

    // 12. Admin Management
    apiAdminOverview: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Admin access required.');
      const empSnap = await db.collection('employees').get();
      const taskSnap = await db.collection('tasks').get();
      return { ok: true, stats: { people: empSnap.size, tasks: taskSnap.size } };
    },

    apiAdminPeople: async function (token) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Admin access required.');
      const snap = await db.collection('employees').get();
      const people = [];
      snap.forEach(d => people.push(d.data()));
      people.sort((a, b) => String(a.EmpName || '').localeCompare(String(b.EmpName || '')));
      const roles = await tmRoles_();
      const regSnap = await db.collection('regions').where('Active', '==', true).get();
      const regions = [];
      regSnap.forEach(d => regions.push(d.data().Region));
      return {
        ok: true,
        people,
        roles: roles.filter(x => x.Active).map(x => x.Role),
        regions: regions.length ? regions : TM_REGIONS
      };
    },

    apiSavePerson: async function (token, input) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Admin access required.');
      const code = String(input.EmpCode || '').trim().toUpperCase();
      if (!code) throw new Error('Employee Code is required.');

      const existingSnap = await db.collection('employees').doc(code).get();
      const existing = existingSnap.exists ? existingSnap.data() : null;
      const isNew = !existing;
      const email = authEmailFor_(code, input.Email);

      const data = {
        EmpCode: code,
        EmpName: tmClip_(input.EmpName, 100),
        Nazim: String(input.Nazim || '').trim().toUpperCase(),
        Division: tmClip_(input.Division, 100),
        Region: tmClip_(input.Region, 100),
        Role: tmClip_(input.Role, 50) || 'Employee',
        Email: tmClip_(input.Email, 200),
        Active: isNew ? 'Y' : (input.Active === 'Y' || input.Active === true ? 'Y' : 'N'),
        SessionVersion: existing ? String(existing.SessionVersion || '1') : '1'
      };

      if (isNew || !existing.AuthUid) {
        if (!input.Password || String(input.Password).length < 6) {
          throw new Error('Please enter an initial password of at least 6 characters.');
        }
        try {
          data.AuthUid = await createAuthUserAsAdmin_(email, String(input.Password));
        } catch (err) {
          throw new Error(mapAuthError_(err));
        }
        data.CreatedAt = existing ? existing.CreatedAt : new Date();
      } else {
        data.AuthUid = existing.AuthUid;
        if (input.Password) {
          if (code === user.EmpCode) {
            await fbAuth.currentUser.updatePassword(String(input.Password));
            if (window.CryptoVault) await window.CryptoVault.rewrapOnPasswordChange(db, code, String(input.Password));
          } else {
            await fbAuth.sendPasswordResetEmail(email).catch(() => {});
            throw new Error('For security, existing users cannot have passwords overwritten from the browser. A Firebase password-reset email was sent to ' + email + '.');
          }
        }
      }

      await db.collection('employees').doc(code).set(data, { merge: true });
      const roles = await tmRoles_();
      if (data.AuthUid) {
        await syncUserMapping_(data.AuthUid, data, roles);
      }
      memoClear();
      return { ok: true };
    },

    apiSendPasswordReset: async function (token, empCode) {
      const { user } = await tmAuth_(token);
      const access = await tmAccess_(user);
      if (!access.admin) throw new Error('Admin access required.');
      const snap = await db.collection('employees').doc(String(empCode).toUpperCase()).get();
      if (!snap.exists) throw new Error('Employee not found.');
      const email = snap.data().Email;
      if (!email) throw new Error('This employee does not have a valid email address.');
      await fbAuth.sendPasswordResetEmail(email);
      return { ok: true, message: 'Password reset link sent to ' + email };
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

    // 13. Password & Session
    apiChangePassword: async function (token, currentPw, newPw) {
      const { user, fbUser } = await tmAuth_(token);
      if (!newPw || String(newPw).length < 8) {
        throw new Error('New password must be at least 8 characters.');
      }
      const cred = firebase.auth.EmailAuthProvider.credential(fbUser.email, currentPw);
      try {
        await fbUser.reauthenticateWithCredential(cred);
        await fbUser.updatePassword(newPw);
      } catch (err) {
        throw new Error(mapAuthError_(err));
      }

      if (window.CryptoVault) {
        await window.CryptoVault.rewrapOnPasswordChange(db, user.EmpCode, newPw);
      }

      const nextVer = tmId_('v');
      await db.collection('employees').doc(user.EmpCode).update({
        SessionVersion: nextVer,
        MustChangePassword: 'N'
      });
      await db.collection('users').doc(fbUser.uid).update({ SessionVersion: nextVer });
      memoClear();
      return { ok: true };
    },

    apiSignOut: async function () {
      if (window.CryptoVault) window.CryptoVault.clearSession();
      if (initFirebase() && fbAuth) {
        await fbAuth.signOut().catch(() => {});
      }
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

    // 14. Stubs for Phase 2 features
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
    apiRunMailNow: async function () { return { ok: true, sent: 0, newDigests: 0 }; },
    apiSendTestMail: async function () { return { ok: true, message: 'Test email function ready' }; }
  };

  window.FirebaseBackend = Backend;
  window.initFirebaseBackend = initFirebase;
})();
