# Budget App storage schema

Budget App uses the browser's IndexedDB API. It is a document-style store, not a SQL database with one table per record type. The current implementation creates database `budget-app-private-vault` (version 1) with one object store, `vault`, whose key path is `id`.

## IndexedDB record

The object store currently contains one record with key `primary`:

```ts
type VaultRecord = {
  id: "primary";
  version: 1;
  kdf: "PBKDF2-SHA-256";
  iterations: 310000;
  salt: string;       // Base64-encoded 16-byte random salt
  iv: string;         // Base64-encoded 12-byte AES-GCM nonce
  ciphertext: string; // Base64-encoded encrypted UTF-8 JSON payload
  updatedAt: string;  // ISO 8601 timestamp
};
```

The passphrase is used with PBKDF2-SHA-256 to derive an AES-GCM 256-bit key. The app serializes the complete payload below to JSON, encrypts it, and stores only the encrypted result in `ciphertext`. The passphrase and cleartext payload are not stored in IndexedDB.

## Encrypted payload

```ts
type VaultPayload = {
  transactions: Transaction[];
  statements: Statement[];
  goals: SavingsGoal[];
  plans: Record<MonthKey, BudgetPlan>;
  settings: {
    monthlyIncome: number;
  };
};

type MonthKey = `${number}-${string}`; // YYYY-MM

type Transaction = {
  id: string;
  date: string;       // YYYY-MM-DD
  merchant: string;
  amount: number;     // Positive = income; negative = expense
  category: string;
  account: string;    // User-entered account label, not a bank credential
  notes: string;
  source: string;     // e.g. "manual" or imported filename
};

type Statement = {
  id: string;
  kind: "csv" | "pdf";
  name: string;
  size?: number;           // Original file size in bytes
  content?: string;        // Original file, Base64-encoded inside encrypted payload
  importedCount?: number;  // CSV transactions added after duplicate filtering
  addedAt: string;         // ISO 8601 timestamp
};

type SavingsGoal = {
  id: string;
  name: string;
  target: number;
  saved: number;
  targetDate: string; // YYYY-MM-DD, or empty string
};

type BudgetPlan = {
  monthKey: MonthKey;
  income: number;
  categories: BudgetCategory[];
  assumptions: string;
  generatedAt: string; // ISO 8601 timestamp
};

type BudgetCategory = {
  key: string;
  name: string;
  average: number; // Recent average expense used to suggest a limit
  spent: number;   // Actual expense total for the plan month
  budget: number;  // Editable planned limit
};
```

`content` is optional to support older CSV imports created before source files were retained. Current CSV imports store the original CSV and parsed transaction rows together in the encrypted payload. PDF statements store the original PDF; PDF transaction extraction is not implemented.

## Storage layout

```text
IndexedDB: budget-app-private-vault (version 1)
└── Object store: vault (keyPath: id)
    └── key "primary": VaultRecord
        └── ciphertext → encrypted VaultPayload
            ├── transactions[]
            ├── statements[]
            ├── goals[]
            ├── plans[YYYY-MM]
            └── settings
```

The schema is implemented in [app.js](app.js), including IndexedDB setup, encryption, CSV parsing, and statement handling.
