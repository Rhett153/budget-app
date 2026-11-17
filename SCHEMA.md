# Budget App storage schema

Budget App uses IndexedDB, a browser document store. Database `budget-app-private-vault` is version 2 and has two object stores: `vault` and `device`.

## Encrypted vault record

Object store `vault` has key path `id` and contains one record with key `primary`:

```ts
type VaultRecord = {
  id: "primary";
  version: 1;
  kdf: "PBKDF2-SHA-256";
  iterations: 310000;
  salt: string;       // Base64-encoded random salt
  iv: string;         // Base64-encoded AES-GCM nonce
  ciphertext: string; // Base64-encoded encrypted UTF-8 JSON payload
  updatedAt: string;  // ISO 8601 timestamp
};
```

The passphrase derives an AES-GCM key using PBKDF2-SHA-256. Only the encrypted payload is written to `vault`; the passphrase and cleartext payload are not stored there.

## Device records

Object store `device` has key path `id`. It may contain:

```ts
type RememberedKey = { id: "remembered-vault-key"; key: CryptoKey };
type CloudSyncState = {
  id: "cloud-sync-state";
  revision: number;
  lastSyncedUpdatedAt: string;
};
```

The remembered, non-extractable CryptoKey is browser-profile-specific. It allows reopening without the passphrase on that profile. Locking removes that key. Cloud sync metadata is local bookkeeping; it contains no transaction data.

## Encrypted payload

```ts
type VaultPayload = {
  transactions: Transaction[];
  statements: Statement[];
  goals: SavingsGoal[];
  plans: Record<MonthKey, BudgetPlan>;
  settings: {
    monthlyIncome: number;
    cloudSyncEnabled?: boolean;
  };
};

type MonthKey = `${number}-${string}`; // YYYY-MM

type Transaction = {
  id: string;
  date: string;       // YYYY-MM-DD
  merchant: string;
  amount: number;     // Positive = income; negative = expense
  category: string;
  account: string;    // User-entered label, not a bank credential
  notes: string;
  source: string;     // e.g. "manual" or imported filename
};

type Statement = {
  id: string;
  kind: "csv" | "pdf" | "image";
  name: string;
  mimeType?: string;
  size?: number;
  content?: string;        // Original file, Base64-encoded inside encrypted payload
  importedCount?: number;
  addedAt: string;
};
```

Transactions and statements are serialized together and encrypted as one vault payload. PDF text extraction and image OCR run in the browser; inspect the import preview before saving recognized transactions.

## Optional cloud record

After the user configures a Supabase project and explicitly enables sync, one row per authenticated account is stored in `public.encrypted_vaults`:

```ts
type EncryptedVaultRow = {
  user_id: string;       // Supabase Auth user UUID
  record: VaultRecord;   // AES-GCM encrypted; opaque to the database
  revision: number;      // Optimistic concurrency counter
  updated_at: string;
};
```

Row-level security restricts reads to the owner. Writes use the `save_my_encrypted_vault` function and expected revision, so stale devices get a conflict instead of overwriting a newer row. The SQL is in [supabase-schema.sql](supabase-schema.sql); provider configuration is in [CLOUD-SETUP.md](CLOUD-SETUP.md).
