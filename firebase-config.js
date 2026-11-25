// =============================================================================
// FIREBASE CONFIGURATION (V17.1 - Hardened Auth + Encrypted Vault Edition)
// =============================================================================

const firebaseConfig = {
  apiKey: "AIzaSyDr1eVnzyLqVRuz4_VqIGxk54w9tv4enIw",
  authDomain: "my-task-manager-586243.firebaseapp.com",
  projectId: "my-task-manager-586243",
  storageBucket: "my-task-manager-586243.firebasestorage.app",
  messagingSenderId: "246631069985",
  appId: "1:246631069985:web:a8edb5f48fd56e0b29a660"
};

// Optional: Email Relay Configuration (for task alerts & reminder emails)
// NOTE: Do NOT store secret passcodes or private API keys in this public file.
// The Apps Script relay verifies the logged-in user's Firebase ID token on Google's servers.
const emailConfig = {
  appsScriptRelayUrl: "https://script.google.com/macros/s/AKfycbwXFC1DA_YxoX9Q-6CHa_68XotmTEPlIRxxjIrM9A5XmSEuyt4zRVjKcuztHOan0IERHg/exec",
  senderName: "Task Management"
};

if (typeof window !== 'undefined') {
  window.FIREBASE_CONFIG = firebaseConfig;
  window.EMAIL_CONFIG = emailConfig;
}
