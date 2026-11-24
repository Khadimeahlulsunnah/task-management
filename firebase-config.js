// =============================================================================
// FIREBASE CONFIGURATION (V17 - Firebase Edition)
// =============================================================================

const firebaseConfig = {
  apiKey: "AIzaSyDr1eVnzyLqVRuz4_VqIGxk54w9tv4enIw",
  authDomain: "my-task-manager-586243.firebaseapp.com",
  projectId: "my-task-manager-586243",
  storageBucket: "my-task-manager-586243.firebasestorage.app",
  messagingSenderId: "246631069985",
  appId: "1:246631069985:web:a8edb5f48fd56e0b29a660"
};

// Optional: Free Email Relay Configuration (for task alerts & reminder emails)
const emailConfig = {
  // Option A: Free Brevo API Key (300 emails/day free)
  brevoApiKey: "",
  senderEmail: "",
  senderName: "Task Management",

  // Option B: Free Google Apps Script Email Relay Webhook URL
  appsScriptRelayUrl: "https://script.google.com/macros/s/AKfycbwXFC1DA_YxoX9Q-6CHa_68XotmTEPlIRxxjIrM9A5XmSEuyt4zRVjKcuztHOan0IERHg/exec",

  // Secret passcode to protect your Google account from spam abuse
  // (Must match RELAY_SECRET in AppsScript_Email_Relay.gs)
  relaySecret: "TM_SECURE_RELAY_KEY_2026"
};

if (typeof window !== 'undefined') {
  window.FIREBASE_CONFIG = firebaseConfig;
  window.EMAIL_CONFIG = emailConfig;
}
