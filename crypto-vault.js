// =============================================================================
// CRYPTO VAULT (Phase 1: End-to-End Encryption using Browser WebCrypto API)
// =============================================================================
// Provides:
//   - Per-user RSA-OAEP (2048-bit, SHA-256) keypairs
//   - Password-protected Private Key wrapping via PBKDF2 (100k iter) + AES-256-GCM
//   - AES-256-GCM encryption/decryption for confidential task fields
//   - AES-256-GCM chunked encryption/decryption for confidential file attachments
// =============================================================================

(function () {
  'use strict';

  const SESSION_PRIV_KEY = 'tm.vault.priv';
  const SESSION_CODE_KEY = 'tm.vault.code';
  const PBKDF2_ITERATIONS = 100000;
  const CHUNK_RAW_BYTES = 340 * 1024; // ~340 KB raw -> ~465 KB base64 (safe < 1 MB Firestore doc limit)
  const MAX_FILE_BYTES = 5 * 1024 * 1024; // 5 MB max per encrypted attachment (Spark-friendly)

  let _privKey = null;
  let _pubKey = null;
  let _empCode = '';

  function ensureWebCrypto() {
    if (!window.crypto || !window.crypto.subtle) {
      throw new Error('Secure encryption requires HTTPS (or localhost) in a modern browser.');
    }
    return window.crypto.subtle;
  }

  function bytesToB64(bytes) {
    const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const step = 0x8000;
    let bin = '';
    for (let i = 0; i < arr.length; i += step) {
      bin += String.fromCharCode.apply(null, arr.subarray(i, i + step));
    }
    return btoa(bin);
  }

  function b64ToBytes(b64) {
    const bin = atob(String(b64 || ''));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function utf8Encode(str) {
    return new TextEncoder().encode(String(str == null ? '' : str));
  }

  function utf8Decode(bytes) {
    return new TextDecoder().decode(bytes);
  }

  async function deriveWrappingKey(password, saltBytes) {
    const subtle = ensureWebCrypto();
    const baseKey = await subtle.importKey(
      'raw',
      utf8Encode(password),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: saltBytes,
        iterations: PBKDF2_ITERATIONS,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function generateUserKeypair() {
    const subtle = ensureWebCrypto();
    const pair = await subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      },
      true,
      ['wrapKey', 'unwrapKey']
    );
    return pair;
  }

  async function wrapPrivateKeyWithPassword(privateKey, password) {
    const subtle = ensureWebCrypto();
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const wrapKey = await deriveWrappingKey(password, salt);
    const jwkBytes = utf8Encode(JSON.stringify(await subtle.exportKey('jwk', privateKey)));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, jwkBytes);
    return {
      salt: bytesToB64(salt),
      iv: bytesToB64(iv),
      ct: bytesToB64(new Uint8Array(ct)),
      iter: PBKDF2_ITERATIONS
    };
  }

  async function unwrapPrivateKeyWithPassword(wrapped, password) {
    const subtle = ensureWebCrypto();
    const salt = b64ToBytes(wrapped.salt);
    const iv = b64ToBytes(wrapped.iv);
    const ct = b64ToBytes(wrapped.ct);
    const wrapKey = await deriveWrappingKey(password, salt);
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv }, wrapKey, ct);
    const jwk = JSON.parse(utf8Decode(plain));
    return subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['unwrapKey']
    );
  }

  async function importPublicKey(jwk) {
    const subtle = ensureWebCrypto();
    return subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['wrapKey']
    );
  }

  async function saveSessionKeys(empCode, privateKey, publicJwk) {
    const subtle = ensureWebCrypto();
    const privJwk = await subtle.exportKey('jwk', privateKey);
    _privKey = privateKey;
    _pubKey = await importPublicKey(publicJwk);
    _empCode = empCode;
    try {
      sessionStorage.setItem(SESSION_CODE_KEY, empCode);
      sessionStorage.setItem(SESSION_PRIV_KEY, JSON.stringify({ priv: privJwk, pub: publicJwk }));
    } catch (e) { /* Ignore storage quota issues */ }
  }

  async function restoreSession(empCode) {
    if (_privKey && _empCode === empCode) return true;
    try {
      const savedCode = sessionStorage.getItem(SESSION_CODE_KEY);
      const raw = sessionStorage.getItem(SESSION_PRIV_KEY);
      if (!savedCode || savedCode !== empCode || !raw) return false;
      const parsed = JSON.parse(raw);
      const subtle = ensureWebCrypto();
      _privKey = await subtle.importKey(
        'jwk',
        parsed.priv,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['unwrapKey']
      );
      _pubKey = await importPublicKey(parsed.pub);
      _empCode = empCode;
      return true;
    } catch (e) {
      clearSession();
      return false;
    }
  }

  function clearSession() {
    _privKey = null;
    _pubKey = null;
    _empCode = '';
    try {
      sessionStorage.removeItem(SESSION_CODE_KEY);
      sessionStorage.removeItem(SESSION_PRIV_KEY);
    } catch (e) { /* Ignore */ }
  }

  function isUnlocked(empCode) {
    return !!(_privKey && (!empCode || _empCode === empCode));
  }

  // Ensure the signed-in user has a keypair in Firestore and unlocked in memory.
  async function initForUser(db, empCode, password) {
    ensureWebCrypto();
    const docRef = db.collection('userKeys').doc(empCode);
    const snap = await docRef.get();

    if (snap.exists) {
      const data = snap.data();
      if (password && data.wrappedPrivateKey) {
        try {
          const priv = await unwrapPrivateKeyWithPassword(data.wrappedPrivateKey, password);
          await saveSessionKeys(empCode, priv, data.publicKeyJwk);
          return { ok: true, created: false };
        } catch (err) {
          // Password may have been reset by an admin; generate a fresh keypair so user isn't locked out.
          console.warn('Could not unwrap existing vault key (likely password reset); rotating keypair.');
        }
      } else if (await restoreSession(empCode)) {
        return { ok: true, created: false };
      } else {
        return { ok: false, locked: true };
      }
    }

    if (!password) {
      return { ok: false, locked: true };
    }

    const pair = await generateUserKeypair();
    const subtle = ensureWebCrypto();
    const publicKeyJwk = await subtle.exportKey('jwk', pair.publicKey);
    const wrappedPrivateKey = await wrapPrivateKeyWithPassword(pair.privateKey, password);

    await docRef.set({
      EmpCode: empCode,
      publicKeyJwk,
      wrappedPrivateKey,
      keyVersion: 1,
      updatedAt: new Date()
    });

    await saveSessionKeys(empCode, pair.privateKey, publicKeyJwk);
    return { ok: true, created: true };
  }

  async function rewrapOnPasswordChange(db, empCode, newPassword) {
    if (!_privKey || _empCode !== empCode) return false;
    const wrappedPrivateKey = await wrapPrivateKeyWithPassword(_privKey, newPassword);
    await db.collection('userKeys').doc(empCode).update({
      wrappedPrivateKey,
      updatedAt: new Date()
    });
    return true;
  }

  // Generate a random AES-256-GCM Data Encryption Key (DEK)
  async function generateDek() {
    const subtle = ensureWebCrypto();
    return subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  // Wrap a DEK for a map of { empCode: publicKeyJwk }
  async function wrapDekForRecipients(dek, recipientPublicJwks) {
    const subtle = ensureWebCrypto();
    const envelopes = {};
    const codes = Object.keys(recipientPublicJwks || {});
    for (const code of codes) {
      const jwk = recipientPublicJwks[code];
      if (!jwk) continue;
      try {
        const pub = await importPublicKey(jwk);
        const wrapped = await subtle.wrapKey('raw', dek, pub, { name: 'RSA-OAEP' });
        envelopes[code] = bytesToB64(new Uint8Array(wrapped));
      } catch (e) {
        console.warn('Key wrap skipped for', code, e);
      }
    }
    return envelopes;
  }

  async function unwrapDekFromEnvelopes(envelopes, empCode) {
    if (!_privKey || !envelopes || !envelopes[empCode]) return null;
    const subtle = ensureWebCrypto();
    const wrappedBytes = b64ToBytes(envelopes[empCode]);
    return subtle.unwrapKey(
      'raw',
      wrappedBytes,
      _privKey,
      { name: 'RSA-OAEP' },
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptText(dek, plainText) {
    const subtle = ensureWebCrypto();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, dek, utf8Encode(plainText));
    return { iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ct)) };
  }

  async function decryptText(dek, payload) {
    if (!payload || !payload.iv || !payload.ct) return '';
    const subtle = ensureWebCrypto();
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(payload.iv) },
      dek,
      b64ToBytes(payload.ct)
    );
    return utf8Decode(plain);
  }

  async function encryptBytes(dek, uint8Data) {
    const subtle = ensureWebCrypto();
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv }, dek, uint8Data);
    return { iv: bytesToB64(iv), ct: bytesToB64(new Uint8Array(ct)) };
  }

  async function decryptBytes(dek, payload) {
    const subtle = ensureWebCrypto();
    const plain = await subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(payload.iv) },
      dek,
      b64ToBytes(payload.ct)
    );
    return new Uint8Array(plain);
  }

  // Encrypt a File object into metadata + array of encrypted chunk payloads
  async function encryptFileForRecipients(file, recipientPublicJwks) {
    if (!file) throw new Error('No file selected.');
    if (file.size > MAX_FILE_BYTES) {
      throw new Error('File "' + file.name + '" exceeds the 5 MB limit for encrypted attachments.');
    }

    const dek = await generateDek();
    const envelopes = await wrapDekForRecipients(dek, recipientPublicJwks);
    const nameEnc = await encryptText(dek, file.name);
    const mimeEnc = await encryptText(dek, file.type || 'application/octet-stream');

    const buffer = new Uint8Array(await file.arrayBuffer());
    const chunks = [];
    if (buffer.length === 0) {
      chunks.push(await encryptBytes(dek, new Uint8Array(0)));
    } else {
      for (let offset = 0; offset < buffer.length; offset += CHUNK_RAW_BYTES) {
        const slice = buffer.subarray(offset, offset + CHUNK_RAW_BYTES);
        chunks.push(await encryptBytes(dek, slice));
      }
    }

    return {
      envelopes,
      nameEnc,
      mimeEnc,
      sizeBytes: file.size,
      chunkCount: chunks.length,
      chunks
    };
  }

  async function decryptFileRecord(meta, chunkPayloads, empCode) {
    const dek = await unwrapDekFromEnvelopes(meta.KeyEnvelopes, empCode);
    if (!dek) {
      throw new Error('You do not have a decryption key for this confidential file.');
    }
    const fileName = await decryptText(dek, meta.NameEnc);
    const mimeType = await decryptText(dek, meta.MimeEnc) || 'application/octet-stream';

    const parts = [];
    for (const chunk of chunkPayloads) {
      parts.push(await decryptBytes(dek, chunk));
    }
    const blob = new Blob(parts, { type: mimeType });
    return { fileName, mimeType, blob };
  }

  window.CryptoVault = {
    MAX_FILE_BYTES,
    initForUser,
    restoreSession,
    clearSession,
    isUnlocked,
    rewrapOnPasswordChange,
    generateDek,
    wrapDekForRecipients,
    unwrapDekFromEnvelopes,
    encryptText,
    decryptText,
    encryptFileForRecipients,
    decryptFileRecord
  };
})();
