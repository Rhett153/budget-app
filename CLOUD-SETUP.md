# Optional passkey accounts and encrypted sync

Cloud sync is off until all setup below is complete and the user selects **Enable encrypted sync** in the app. This demo cannot provision a Supabase project automatically.

## 1. Create and configure Supabase

1. Create a Supabase project and confirm its Auth email flow works.
2. In the Supabase SQL Editor, run the contents of [`supabase-schema.sql`](supabase-schema.sql). It creates the encrypted vault table, owner-only read policy, and revision-checked write function.
3. In **Authentication → Sign In / Providers**, enable passkey authentication. Supabase currently marks its passkey feature as experimental.
4. In **Authentication → Passkeys**, enable passkeys. Use a display name such as `Budget App`, relying party ID `rhett153.github.io`, and allowed origin `https://rhett153.github.io` (an origin has no path). Keep the relying party ID stable after registering passkeys.
5. In **Authentication → URL Configuration**, set the Site URL to `https://rhett153.github.io/budget-app/` and add that exact URL to the Redirect URLs allow-list. The email sign-in link returns to the app. Do not add `localhost` to this production passkey configuration; local testing needs a separate matching RP setup.
6. Open the project's **Connect** dialog or **Settings → API Keys**. In `supabase-config.js`, set `url` to the Project URL and `publishableKey` to the project's publishable key (or legacy anon key).

Only a browser publishable/anon key belongs in this static site. It is designed for client use, but the public repository exposes it, so the table's owner-only RLS and write function must remain in place. Never put a `service_role`, secret key, database password, or other server credential in this repository. Commit and push `supabase-config.js` to publish the configuration.

## 2. First account and first device

1. Deploy the configured static site over HTTPS.
2. Create or unlock your local encrypted vault and make an encrypted backup.
3. Open **Privacy & backups**, enter your email, and select **Send sign-in link**. Open the email on the same device/browser and confirm the account.
4. Return to the app and select **Add a passkey on this device**. Follow the browser or password manager prompt. Register another passkey on any device you want to use if your passkey provider does not sync them.
5. Select **Enable encrypted sync** and accept the in-app disclosure. The app uploads the encrypted vault envelope to your Supabase project.

## 3. Another device

1. Open the same site and sign in with the same passkey account.
2. The app downloads only the encrypted vault envelope. Enter the existing vault passphrase once to unlock it. Choose **Remember this device** only on a browser profile you control.
3. Changes sync when saved. If another device made a newer change, the app reports a conflict instead of silently overwriting the cloud copy; use **Sync now** and resolve from the current cloud copy before continuing.

The passkey authenticates the account; it does not decrypt the vault. A passphrase is still needed on each new device. Remembered unlock uses a non-extractable browser key stored in that device's IndexedDB. Anyone who can use that browser profile can reopen its vault, and **Lock** removes the saved key.

## Data and limitations

Cloud storage contains the AES-GCM encrypted vault record, including encrypted original statement files. Supabase Auth receives the account email and passkey credential metadata. OCR and encryption happen in the browser. Cloud sync does not provide end-to-end recovery of a forgotten vault passphrase; keep the encrypted backup and passphrase safe.

Supabase's passkey APIs are experimental. Review their current provider documentation and test account recovery before using this with important financial records. PDF.js and Tesseract.js load from pinned-version jsDelivr URLs for in-browser PDF parsing/OCR.
