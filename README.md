# Budget App

A local-first budgeting workspace published as a static site. It lets one person keep a private encrypted budget vault in a modern browser, enter transactions, import CSV statements, save PDFs, generate a monthly spending plan, and track savings goals.

## What works

- Create and unlock a passphrase-protected vault stored in this browser using IndexedDB, PBKDF2, and AES-GCM.
- Add, edit, filter, and delete income and expense transactions.
- Import CSV files with common date, amount, debit/credit, description, and category columns. Imports are previewed and likely duplicates are skipped.
- Save PDF statements encrypted in the vault and download them again later. PDF text extraction is not included.
- Generate a budget from up to three months of transaction history, edit category limits, and record savings goals.
- Export and restore an encrypted backup, change the vault passphrase, lock the vault, or delete it from this browser.

## Privacy and limitations

This is a single-device MVP. The static website code is public, but it does not send the passphrase or vault contents to a server. Financial records and uploaded PDFs are encrypted in the browser before being written to IndexedDB. This project has no account system, cloud backup, multi-device sync, bank connection, automatic bank feed, or PDF transaction extraction. Do not enter bank passwords. Backups are encrypted but should still be stored somewhere private. If you lose both the passphrase and a usable backup, the data cannot be recovered.

The budget plan is a simple estimate based on recent recorded transactions or an income amount you provide. Review and adjust the result; it is not financial advice.

## Run locally

No build step or external dependencies are required. Open the hosted HTTPS site, or serve this directory with a static web server. Browser encryption and IndexedDB work in modern browsers on secure origins (HTTPS or localhost).

## Deploy

The repository is configured for GitHub Pages. Push updates to `main`; Pages publishes the static files from the repository. The public Pages URL is https://rhett153.github.io/budget-app/.
