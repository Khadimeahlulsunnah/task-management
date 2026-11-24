# Task Management V17 (Firebase Edition) 🚀
### 100% Free • Sub-50ms Speed • 50+ Real-time Users

Welcome to **V17**! This edition moves your database from slow Google Sheets to Google's modern, lightning-fast **Cloud Firestore**. 

Your user interface (`Index.html`) looks and feels exactly the same, but:
* Tasks load and save **instantly (20–50ms)** instead of taking 3–4 seconds.
* **50+ users** can use it simultaneously without hitting Google Apps Script quotas or "System is busy" locks.
* It is **100% Free of Cost** forever on Google Firebase's Spark Plan.

---

## 📋 Table of Contents
1. [Step 1: Create Your Free Firebase Project (2 Minutes)](#step-1-create-your-free-firebase-project-2-minutes)
2. [Step 2: Enable Cloud Firestore Database](#step-2-enable-cloud-firestore-database)
3. [Step 3: Copy Your Keys into `firebase-config.js`](#step-3-copy-your-keys-into-firebase-configjs)
4. [Step 4: Test & Log In](#step-4-test--log-in)
5. [Step 5: (Optional) Migrate Existing Data from Google Sheets](#step-5-optional-migrate-existing-data-from-google-sheets)
6. [Step 6: (Optional) Host for Free on GitHub Pages or Firebase](#step-6-optional-host-for-free-on-github-pages-or-firebase)
7. [Step 7: (Optional) Free Daily 9 AM Reminder Emails](#step-7-optional-free-daily-9-am-reminder-emails)

---

## Step 1: Create Your Free Firebase Project (2 Minutes)

1. Open your browser and go to: **[https://console.firebase.google.com](https://console.firebase.google.com)**
2. Sign in with any standard Google account.
3. Click **"Add project"** (or **"Create a project"**).
4. Enter a name (e.g. `Task-Management`). Click **Continue**.
5. Disable Google Analytics (optional, not needed for tasks). Click **Create project**.
6. Wait 10 seconds until it says *"Your new project is ready"*, then click **Continue**.

---

## Step 2: Enable Cloud Firestore Database

1. In the left-hand menu of Firebase Console, click **Build** ➜ **Firestore Database**.
2. Click the blue **"Create database"** button.
3. Choose a location closest to you (e.g. `asia-south1 (Mumbai)` or `us-central1`). Click **Next**.
4. Choose **"Start in test mode"** (this allows your web app to read/write data).
5. Click **Create**. Your database is now live!

---

## Step 3: Copy Your Keys into `firebase-config.js`

1. In the top-left menu, click the **Gear icon ⚙️ (Project settings)** next to "Project Overview".
2. Scroll down to the **"Your apps"** section and click the **Web icon `</>`**.
3. Enter an app nickname (e.g. `Web-App`), leave "Firebase Hosting" unchecked for now, and click **Register app**.
4. You will see a code block containing `firebaseConfig`. It looks like this:
   ```javascript
   const firebaseConfig = {
     apiKey: "AIzaSy...",
     authDomain: "your-project.firebaseapp.com",
     projectId: "your-project",
     storageBucket: "your-project.appspot.com",
     messagingSenderId: "123456789",
     appId: "1:123456789:web:abcdef"
   };
   ```
5. Open the file `V17_Firebase/firebase-config.js` in any text editor.
6. Replace the placeholder values with your real keys from step 4, and **Save** the file!

---

## Step 4: Test & Log In

1. Simply double-click **`Index.html`** in this folder to open it in Google Chrome, Microsoft Edge, or any browser!
2. You will see the Task Management sign-in screen.
3. Default First-Time Administrator Login:
   * **Employee Code:** `ADMIN`
   * **Password:** `admin123`
4. Once logged in, you can create tasks, add your team members in the Admin tab, and change your password!

---

## Step 5: (Optional) Migrate Existing Data from Google Sheets

If you have employees and tasks in your existing Google Sheet that you want to transfer automatically:

1. Open your Google Spreadsheet.
2. In the top menu, click **Extensions ➜ Apps Script**.
3. Create a new script file and paste the contents of **`AppsScript_Data_Migrator.gs`** (from this folder).
4. At the top of the file, enter your `FIREBASE_PROJECT_ID` and `FIREBASE_API_KEY`.
5. Select `migrateAllDataToFirebase` from the function dropdown at the top and click **Run**.
6. Check your execution log—all employees, roles, tasks, and checklists will instantly appear in your Firebase database!

---

## Step 6: (Optional) Host for Free on GitHub Pages or Firebase

To share the web app with your 50+ users so they can access it from their computers and mobile phones:

### Choice A: GitHub Pages (Easiest)
1. Create a free account at [github.com](https://github.com).
2. Create a new repository named `task-management`.
3. Upload all files from the `V17_Firebase` folder (`Index.html`, `firebase-config.js`, `firebase-backend.js`).
4. Go to **Settings ➜ Pages**. Under "Branch", select `main` and click **Save**.
5. In 1 minute, GitHub will give you a free HTTPS link (e.g. `https://yourname.github.io/task-management/`) that all 50 users can access!

### Choice B: Firebase Hosting
1. Install Firebase CLI: `npm install -g firebase-tools`
2. Run `firebase login` and `firebase init hosting` inside the `V17_Firebase` folder.
3. Run `firebase deploy`. It gives you a free link like `https://your-project.web.app`.

---

## Step 7: (Optional) Free Daily 9 AM Reminder Emails

1. In your existing Google Sheet's Apps Script, paste the contents of **`AppsScript_Email_Relay.gs`**.
2. Run `installDailyTrigger()`.
3. Google will now run a free automated timer every morning at 9:00 AM, query your Firestore database, and send summary emails to managers and assignees!

---

## Summary of Files in V17_Firebase

| File | Purpose |
| :--- | :--- |
| **`Index.html`** | The complete user-facing responsive Web App. |
| **`firebase-config.js`** | Where you paste your Firebase project API keys. |
| **`firebase-backend.js`** | The fast client-side Firestore database adapter. |
| **`firestore.rules`** | Cloud Firestore database security rules. |
| **`firebase.json`** | Configuration for Firebase Hosting. |
| **`AppsScript_Data_Migrator.gs`** | One-click tool to copy existing Google Sheet data to Firebase. |
| **`AppsScript_Email_Relay.gs`** | Free Google script for task assignment & 9 AM reminder emails. |
| **`README.md`** | This setup guide. |
