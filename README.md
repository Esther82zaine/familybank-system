# Real-Time Mobile Banking System (Family Bank Kenya case study)

Working prototype for the Zetech University diploma project. It runs on your own computer with a real back end, a real database, live WebSocket notifications, and a customer app plus an admin/agent console. It uses synthetic data only, and M-Pesa is a sandbox simulation.

## 1. Run it (2 minutes)

1. Install **Node.js 22.13 or newer** (the current LTS is fine) from nodejs.org. Check with `node -v`.
2. Open a terminal in this folder and run:

```
npm start
```

3. Open **http://localhost:3000** in your browser. On a phone on the same Wi-Fi, use `http://YOUR-LAPTOP-IP:3000`.

No `npm install` is needed. The project has no outside packages.

**With Docker instead:** `docker compose up --build`

## 2. Demo accounts (synthetic data)

| Role | Phone | PIN |
|---|---|---|
| Customer: Amina Wanjiru (acct 1234567890, KES 45,300) | 0712345678 | 1234 |
| Customer: John Mwangi (acct 1234567891) | 0722000111 | 1234 |
| Customer: Grace Achieng (acct 1234567892) | 0733000222 | 1234 |
| Administrator | 0700000001 | 9999 |
| Support agent | 0700000002 | 8888 |

After the PIN, the SMS code appears on the login screen (sandbox). Set `DEMO_MODE=false` to hide it; it is then only printed in the server console.

## 3. How to demo it (live part)

1. Open two browser windows: Amina in one, John in the other (or use a phone for one).
2. Amina: **Send Money** to account `1234567891`. Amina sees the receipt immediately, and **both** windows show a live alert and an updated balance with no refresh.
3. **M-Pesa:** enter an amount and tap Send STK Push. The balance rises about 3 seconds later when the simulated Safaricom callback arrives. Amount `99` simulates a cancelled prompt.
4. **Pay Bills**, then **History** (search works).
5. **Help:** log a complaint as Amina. Log in as the agent (0700000002) and press Start, then Resolve. Amina gets a live notification and can rate the service.
6. Log in as the administrator to see the dashboard tiles, latest transactions, users (suspend or activate), and the audit log. Transfers of KES 50,000 or more raise a **FRAUD_FLAG** alert.

## 4. Automated tests (Table 3.4.1)

```
npm test
```

This runs TC01 to TC12 against a temporary in-memory database and prints PASS or FAIL for each, including the measured alert time for TC04. Screenshot the output for **Figure 3.4.1** and copy the results into the "Actual result" and "Status" columns.

## 5. Where each part of the report is in the code

| Report section | File and function |
|---|---|
| 3.3.1 Secure channel | `server.js` security headers and rate limit. TLS is added by the reverse proxy in Listing 3.3.1 when deployed. |
| 3.3.2 Login, PIN, OTP, lock after 3 | `login()`, `verifyOtp()`, `sign()` and `verify()` (15-minute JWT) |
| 3.3.3 Atomic transfer, idempotency | `moveMoney()` (database transaction, duplicate reference rejected, daily limit, fraud flag) |
| 3.3.4 M-Pesa STK Push and callback | `stkPush()`, `mpesaCallback()` (credits once, receipt number unique) |
| 3.3.5 Live notifications | `bus` event `transaction.completed`, `notify()`, `lib/ws.js` WebSocket |
| 3.3.6 Audit logging | `audit()`, table `audit_logs` (metadata only) |
| 3.3.7 Database | `db/schema.sql` (CHECK constraints, UNIQUE references) |
| Support and feedback | `/api/tickets`, `/api/staff/tickets`, `/api/feedback` |
| Admin console | `/api/admin/*` and the staff view in `public/index.html` |

## 6. Differences from the report (write these honestly in Chapter 3)

- **Database:** this build uses **SQLite** (built into Node) so it runs with no setup. The schema in `db/schema.sql` follows Table 2.3.1 and moves to PostgreSQL with only small type changes (`SERIAL` for `INTEGER PRIMARY KEY AUTOINCREMENT`, `NUMERIC(15,2)` for `REAL`).
- **Message queue:** an in-process event bus plays the role of RabbitMQ. The publish-after-commit design is the same.
- **WebSocket:** a small built-in implementation in `lib/ws.js` replaces the `ws` library.
- **PIN hashing:** `scrypt` (built into Node) is used instead of bcrypt. Both are deliberately slow password hashes.
- **Not built:** registration and KYC screens, airtime tile, Kiswahili, report export, rule-based fraud beyond the high-value flag, Redis, FCM push. Mention these as future work in Chapter 4.
- **Mobile app:** this is a mobile-first web app, not a Flutter app. It can be added to a phone home screen from the browser.
- **Security note:** the M-Pesa callback is public by design. In production it must be restricted to Safaricom's addresses. Do not use real customer data or real money.

## 7. Put it online for your presentation

The server needs Node, so it cannot go on Netlify Drop. Free options: **Render.com** (New Web Service, connect your GitHub repo, build command empty, start command `npm start`, add environment variables `JWT_SECRET` and `DEMO_MODE=true`). Free instances sleep when idle and their database may reset, so open the link a few minutes before you present. Keep the local version as a backup.
