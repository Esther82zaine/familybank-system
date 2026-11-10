-- Tables from Table 2.3.1 (data dictionary). Runs on SQLite; types map directly to PostgreSQL.
CREATE TABLE IF NOT EXISTS users (
  user_id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  phone TEXT UNIQUE NOT NULL,
  email TEXT,
  pin_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'CUSTOMER',      -- CUSTOMER | AGENT | ADMIN
  status TEXT NOT NULL DEFAULT 'ACTIVE',      -- ACTIVE | SUSPENDED
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS accounts (
  account_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(user_id),
  account_number TEXT UNIQUE NOT NULL,
  balance REAL NOT NULL DEFAULT 0 CHECK (balance >= 0),
  currency TEXT NOT NULL DEFAULT 'KES',
  status TEXT NOT NULL DEFAULT 'ACTIVE'
);
CREATE TABLE IF NOT EXISTS transactions (
  txn_id INTEGER PRIMARY KEY AUTOINCREMENT,
  from_account INTEGER REFERENCES accounts(account_id),
  to_account INTEGER REFERENCES accounts(account_id),
  amount REAL NOT NULL CHECK (amount > 0),
  type TEXT NOT NULL,                          -- TRANSFER | MPESA_DEPOSIT | BILL
  status TEXT NOT NULL DEFAULT 'PENDING',
  reference TEXT UNIQUE NOT NULL,              -- idempotency key / M-Pesa receipt
  description TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS otp_codes (
  otp_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(user_id),
  code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS notifications (
  notif_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(user_id),
  txn_id INTEGER, channel TEXT, message TEXT,
  sent_at TEXT DEFAULT CURRENT_TIMESTAMP, read_at TEXT
);
CREATE TABLE IF NOT EXISTS tickets (
  ticket_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(user_id),
  subject TEXT NOT NULL, description TEXT,
  status TEXT NOT NULL DEFAULT 'OPEN',         -- OPEN | IN_PROGRESS | RESOLVED
  assigned_to INTEGER, created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS feedback (
  feedback_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(user_id),
  txn_id INTEGER, rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5), comment TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_logs (       -- metadata only: never PINs, OTPs or message content
  log_id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER, action TEXT NOT NULL, ip_address TEXT, device_id TEXT, details TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS payments (          -- pending M-Pesa STK Push requests
  checkout_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, phone TEXT, amount REAL NOT NULL,
  status TEXT NOT NULL DEFAULT 'PENDING', receipt TEXT
);
