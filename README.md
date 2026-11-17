# Budget App

A local-first budgeting workspace published as a static site. It stores a private encrypted vault in the browser, imports CSV/PDF/image statements, creates a budget plan, and tracks savings goals.

See [SCHEMA.md](SCHEMA.md) for local storage and [CLOUD-SETUP.md](CLOUD-SETUP.md) for optional account and sync setup.

## What works

- Create and unlock an AES-GCM encrypted vault protected by a passphrase.
- Optionally remember the vault key in this browser profile for one-click reopening. Anyone with access to that profile can reopen it; using **Lock** removes the remembered key.
- Add, edit, filter, and delete income and expense transactions.
- Import CSV transactions. The importer also extracts text from PDFs and runs OCR on scanned PDF pages and PNG/JPEG files in the browser. It presents a transaction preview; verify all dates, descriptions, and amounts before importing. Previously saved PDFs/images can be reprocessed from the Statements page.
- Generate a budget from recent transaction history, edit category limits, and record savings goals.
- Export and restore an encrypted backup, change the passphrase, lock the vault, or delete the local vault.
- Optionally sign in with a passkey and sync the encrypted vault through a Supabase project. Passkey account login and the vault passphrase are separate: a new device needs the vault passphrase once to decrypt the downloaded vault.

## Privacy and limitations

Without cloud setup and explicit sync enablement, the app keeps data in this browser's IndexedDB. OCR and encryption run in the browser. When sync is enabled, the Supabase project receives the encrypted vault envelope; it does not receive the vault passphrase or readable transactions. The passkey signs into the account but does not decrypt the vault.

PDF/image recognition depends on statement layout and image quality. Review the preview; OCR can misread amounts and dates. PDF.js, Tesseract.js, and Supabase JS are loaded from pinned-version public CDNs. Browser access to these packages requires an internet connection.

The Supabase passkey API is currently experimental. Cross-device passkey availability depends on the passkey provider (for example, the same password manager/keychain or a separately registered passkey). See [CLOUD-SETUP.md](CLOUD-SETUP.md) before enabling it. Do not enter bank passwords. Keep an encrypted backup somewhere private. If you lose both the passphrase and a usable backup, the data cannot be recovered.

The budget plan is an estimate based on recent recorded transactions or an income amount you provide. Review and adjust it; it is not financial advice.

## Run locally

Open the hosted HTTPS site, or serve this directory with a static web server. Browser encryption, passkeys, and IndexedDB require a modern browser on HTTPS or localhost.

## Deploy

The repository is configured for GitHub Pages. Push updates to `main`; Pages publishes the static files from the repository. The public Pages URL is https://rhett153.github.io/budget-app/.
