// Real-Time Mobile Banking System: gateway + services in one Node.js process (no npm packages needed).
// Sections follow the report: 3.3.1 secure channel, 3.3.2 login, 3.3.3 transfer, 3.3.4 M-Pesa,
// 3.3.5 live notifications, 3.3.6 audit log, 3.3.7 database.
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite');
const { EventEmitter } = require('events');
const ws = require('./lib/ws');

const PORT = +process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || crypto.randomBytes(32).toString('hex');
const DEMO = process.env.DEMO_MODE !== 'false';          // DEMO_MODE shows the SMS code on screen (sandbox only)
const RATE = +process.env.RATE_LIMIT || 120;             // requests per minute per IP
const OTP_TTL = +process.env.OTP_TTL || 300;             // seconds
const DAILY_LIMIT = 150000, FRAUD_FLAG = 50000;
const DBFILE = process.env.DB_FILE || path.join(__dirname, 'data', 'bank.db');
if (DBFILE !== ':memory:') fs.mkdirSync(path.dirname(DBFILE), { recursive: true });

// ---------- Database (3.3.7) ----------
const db = new DatabaseSync(DBFILE);
db.exec('PRAGMA foreign_keys = ON');
db.exec(fs.readFileSync(path.join(__dirname, 'db', 'schema.sql'), 'utf8'));
const one = (s, ...p) => db.prepare(s).get(...p);
const all = (s, ...p) => db.prepare(s).all(...p);
const run = (s, ...p) => db.prepare(s).run(...p);
const tx = fn => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
class E extends Error { constructor(s, m) { super(m); this.s = s; } }
const money = n => Math.round(n * 100) / 100;
const fmt = n => Number(n).toLocaleString('en-KE', { minimumFractionDigits: 2, maximumFractionDigits: 2 });

// ---------- Security helpers ----------
const hash = v => { const s = crypto.randomBytes(8).toString('hex'); return s + ':' + crypto.scryptSync(String(v), s, 32).toString('hex'); };
const check = (v, h) => { const [s, x] = h.split(':'); return crypto.timingSafeEqual(Buffer.from(x, 'hex'), crypto.scryptSync(String(v), s, 32)); };
const b64 = s => Buffer.from(s).toString('base64url');
const sig = d => crypto.createHmac('sha256', SECRET).update(d).digest('base64url');
const sign = u => { const d = b64('{"alg":"HS256","typ":"JWT"}') + '.' + b64(JSON.stringify({ sub: u.user_id, role: u.role, exp: Math.floor(Date.now() / 1000) + 900 })); return d + '.' + sig(d); };
const verify = t => { try { const [h, p, s] = String(t).split('.'), x = sig(h + '.' + p); if (s.length !== x.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(x))) return null; const d = JSON.parse(Buffer.from(p, 'base64url')); return d.exp > Date.now() / 1000 ? d : null; } catch { return null; } };
const audit = (uid, action, ip, details) => run('INSERT INTO audit_logs(user_id,action,ip_address,details) VALUES(?,?,?,?)', uid ?? null, action, ip || null, details || null);
const hits = new Map();
const limited = ip => { const n = Date.now(), h = hits.get(ip); if (!h || n - h.t > 60000) { hits.set(ip, { t: n, c: 1 }); return false; } return ++h.c > RATE; };

// ---------- Message queue stand-in + Notification service (3.3.5) ----------
const bus = new EventEmitter();
const sms = (phone, text) => console.log(`[SMS sandbox] to ${phone}: ${text}`);
function notify(userId, txnId, message, extra = {}) {
  const u = one('SELECT phone FROM users WHERE user_id=?', userId);
  run('INSERT INTO notifications(user_id,txn_id,channel,message) VALUES(?,?,?,?)', userId, txnId ?? null, 'WS+SMS', message);
  ws.push(userId, { type: 'NOTIF', message, ...extra });
  if (u) sms(u.phone, message);
}
bus.on('transaction.completed', evt => { for (const p of evt.parties) notify(p.userId, evt.txnId, p.message, { balance: p.balance, txnId: evt.txnId }); });

// ---------- Auth service (3.3.2) ----------
function login(phone, pin, ip) {
  const u = one('SELECT * FROM users WHERE phone=?', String(phone || ''));
  if (!u || u.status !== 'ACTIVE') { audit(u?.user_id, 'LOGIN_FAILED', ip); throw new E(401, 'Access denied'); }
  if (u.locked_until > Date.now()) throw new E(423, 'Account locked temporarily after 3 wrong PINs. Try again in 15 minutes.');
  if (!check(pin, u.pin_hash)) {
    const n = u.failed_count + 1;
    if (n >= 3) { run('UPDATE users SET failed_count=0, locked_until=? WHERE user_id=?', Date.now() + 15 * 60000, u.user_id); audit(u.user_id, 'ACCOUNT_LOCKED', ip); }
    else run('UPDATE users SET failed_count=? WHERE user_id=?', n, u.user_id);
    audit(u.user_id, 'LOGIN_FAILED', ip);
    throw new E(401, n >= 3 ? 'Account locked after 3 wrong PINs' : `Invalid credentials. ${3 - n} attempt(s) left.`);
  }
  run('UPDATE users SET failed_count=0 WHERE user_id=?', u.user_id);
  run('UPDATE otp_codes SET used=1 WHERE user_id=?', u.user_id);
  const otp = String(crypto.randomInt(100000, 999999));
  run('INSERT INTO otp_codes(user_id,code_hash,expires_at) VALUES(?,?,?)', u.user_id, hash(otp), Date.now() + OTP_TTL * 1000);
  sms(u.phone, `Your code is ${otp}`);
  audit(u.user_id, 'PIN_OK_OTP_SENT', ip);
  return { step: 'OTP_REQUIRED', demoOtp: DEMO ? otp : undefined };
}
function verifyOtp(phone, otp, ip) {
  const u = one('SELECT * FROM users WHERE phone=?', String(phone || ''));
  const o = u && one('SELECT * FROM otp_codes WHERE user_id=? AND used=0 ORDER BY otp_id DESC LIMIT 1', u.user_id);
  if (!o || o.expires_at < Date.now() || !check(otp, o.code_hash)) { audit(u?.user_id, 'OTP_FAILED', ip); throw new E(401, 'Code is wrong or expired. Log in again to get a new one.'); }
  run('UPDATE otp_codes SET used=1 WHERE otp_id=?', o.otp_id);
  audit(u.user_id, 'LOGIN_SUCCESS', ip);
  return { token: sign(u), user: { id: u.user_id, name: u.full_name, role: u.role, phone: u.phone } };
}
const pinOk = (u, pin, ip) => { if (!check(pin ?? '', u.pin_hash)) { audit(u.user_id, 'PIN_FAILED', ip); throw new E(403, 'Invalid PIN'); } };

// ---------- Transaction service (3.3.3): atomic, row-locked, idempotent ----------
function moveMoney({ user, toAcc, amount, reference, type, desc, ip }) {
  amount = money(Number(amount));
  if (!(amount > 0)) throw new E(400, 'Enter an amount above zero');
  if (!reference) throw new E(400, 'Missing reference');
  const res = tx(() => {
    if (one('SELECT 1 FROM transactions WHERE reference=?', reference)) throw new E(409, 'Duplicate transaction: this reference was already processed');
    const from = one('SELECT * FROM accounts WHERE user_id=?', user.user_id);
    if (!from) throw new E(400, 'No account');
    const to = toAcc ? one('SELECT a.*, u.full_name FROM accounts a JOIN users u USING(user_id) WHERE account_number=?', String(toAcc)) : null;
    if (toAcc && !to) throw new E(404, 'Recipient account not found');
    if (to && to.account_id === from.account_id) throw new E(400, 'You cannot send money to your own account');
    const today = one("SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE from_account=? AND status='SUCCESS' AND date(created_at)=date('now')", from.account_id).s;
    if (today + amount > DAILY_LIMIT) throw new E(422, `Daily limit of KES ${fmt(DAILY_LIMIT)} exceeded`);
    if (from.balance < amount) throw new E(422, `Insufficient funds. Available: KES ${fmt(from.balance)}`);
    run('UPDATE accounts SET balance = balance - ? WHERE account_id=?', amount, from.account_id);
    if (to) run('UPDATE accounts SET balance = balance + ? WHERE account_id=?', amount, to.account_id);
    const r = run("INSERT INTO transactions(from_account,to_account,amount,type,status,reference,description) VALUES(?,?,?,?, 'SUCCESS',?,?)", from.account_id, to?.account_id ?? null, amount, type, reference, desc);
    return { txnId: Number(r.lastInsertRowid), from, to };
  });
  // After COMMIT only: publish the event, then notifications follow without blocking the receipt.
  const balance = one('SELECT balance FROM accounts WHERE user_id=?', user.user_id).balance;
  const parties = [{ userId: user.user_id, balance, message: `KES ${fmt(amount)} ${res.to ? 'sent to ' + res.to.full_name : 'paid: ' + desc}. New balance KES ${fmt(balance)}.` }];
  if (res.to) parties.push({ userId: res.to.user_id, balance: res.to.balance + amount, message: `KES ${fmt(amount)} received from ${user.full_name}. New balance KES ${fmt(res.to.balance + amount)}.` });
  bus.emit('transaction.completed', { txnId: res.txnId, parties });
  audit(user.user_id, type + '_SUCCESS', ip, `txn ${res.txnId} amount ${amount}`);
  if (amount >= FRAUD_FLAG) audit(user.user_id, 'FRAUD_FLAG', ip, `High-value ${type} txn ${res.txnId} amount ${amount}`);
  return { status: 'SUCCESS', txnId: res.txnId, reference, balance };
}

// ---------- Payment service: M-Pesa STK Push (Daraja sandbox simulation) (3.3.4) ----------
function stkPush(user, phone, amount) {
  amount = money(Number(amount));
  if (!(amount >= 10)) throw new E(400, 'Minimum M-Pesa deposit is KES 10');
  const id = 'ws_CO_' + crypto.randomBytes(6).toString('hex');
  run('INSERT INTO payments(checkout_id,user_id,phone,amount) VALUES(?,?,?,?)', id, user.user_id, phone || user.phone, amount);
  // Simulate Safaricom: customer enters PIN, callback arrives 3 s later. Amount 99 simulates a cancelled prompt.
  setTimeout(() => {
    const ok = amount !== 99;
    mpesaCallback({ Body: { stkCallback: ok
      ? { CheckoutRequestID: id, ResultCode: 0, CallbackMetadata: { Item: [{ Name: 'Amount', Value: amount }, { Name: 'MpesaReceiptNumber', Value: 'S' + crypto.randomBytes(4).toString('hex').toUpperCase() }] } }
      : { CheckoutRequestID: id, ResultCode: 1032, ResultDesc: 'Request cancelled by user' } } });
  }, 3000).unref();
  return { checkoutId: id, status: 'PENDING', message: 'Prompt sent. Enter your M-Pesa PIN on the phone.' };
}
function mpesaCallback(body) {
  const cb = body?.Body?.stkCallback; if (!cb) throw new E(400, 'Bad callback');
  const p = one('SELECT * FROM payments WHERE checkout_id=?', cb.CheckoutRequestID);
  if (!p) throw new E(404, 'Unknown checkout request');
  if (p.status !== 'PENDING') return;                                  // repeated callback: ignore (no second credit)
  if (cb.ResultCode !== 0) { run("UPDATE payments SET status='FAILED' WHERE checkout_id=?", p.checkout_id); return notify(p.user_id, null, `M-Pesa deposit of KES ${fmt(p.amount)} failed: ${cb.ResultDesc || 'cancelled'}.`, { mpesa: 'FAILED' }); }
  const items = Object.fromEntries((cb.CallbackMetadata?.Item || []).map(i => [i.Name, i.Value]));
  if (Number(items.Amount) !== p.amount) { run("UPDATE payments SET status='FAILED' WHERE checkout_id=?", p.checkout_id); return; }
  const acc = one('SELECT * FROM accounts WHERE user_id=?', p.user_id);
  const txnId = tx(() => {
    if (one('SELECT 1 FROM transactions WHERE reference=?', items.MpesaReceiptNumber)) throw new E(409, 'Duplicate receipt');
    run('UPDATE accounts SET balance = balance + ? WHERE account_id=?', p.amount, acc.account_id);
    const r = run("INSERT INTO transactions(to_account,amount,type,status,reference,description) VALUES(?,?, 'MPESA_DEPOSIT','SUCCESS',?,?)", acc.account_id, p.amount, items.MpesaReceiptNumber, 'M-Pesa deposit');
    run("UPDATE payments SET status='SUCCESS', receipt=? WHERE checkout_id=?", items.MpesaReceiptNumber, p.checkout_id);
    return Number(r.lastInsertRowid);
  });
  const bal = one('SELECT balance FROM accounts WHERE account_id=?', acc.account_id).balance;
  bus.emit('transaction.completed', { txnId, parties: [{ userId: p.user_id, balance: bal, message: `M-Pesa deposit of KES ${fmt(p.amount)} received (${items.MpesaReceiptNumber}). New balance KES ${fmt(bal)}.` }] });
  audit(p.user_id, 'MPESA_DEPOSIT_SUCCESS', null, `txn ${txnId} amount ${p.amount}`);
}

// ---------- Gateway: routing, auth, rate limit, headers, request log ----------
const routes = [];
const route = (m, p, roles, fn) => routes.push({ m, re: new RegExp('^' + p.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$'), roles, fn });
const STAFF = ['ADMIN', 'AGENT'], ADMIN = ['ADMIN'];
const label = (r, mine) => r.type === 'TRANSFER' ? (r.from_account === mine ? 'Sent to ' + (r.to_name || '') : 'Received from ' + (r.from_name || '')) : r.description;
const ticketCode = id => 'TKT-' + String(id).padStart(4, '0');

route('GET', '/api/health', null, () => ({ ok: true }));
route('POST', '/api/auth/login', null, c => login(c.body.phone, c.body.pin, c.ip));
route('POST', '/api/auth/verify-otp', null, c => verifyOtp(c.body.phone, c.body.otp, c.ip));
route('POST', '/api/payments/mpesa/callback', null, c => { mpesaCallback(c.body); return { ResultCode: 0, ResultDesc: 'Accepted' }; });

route('GET', '/api/me', ['CUSTOMER', ...STAFF], c => ({ user: { id: c.user.user_id, name: c.user.full_name, role: c.user.role, phone: c.user.phone }, account: one('SELECT account_number, balance, currency FROM accounts WHERE user_id=?', c.user.user_id) || null,
  unread: one('SELECT COUNT(*) n FROM notifications WHERE user_id=? AND read_at IS NULL', c.user.user_id).n, dailyLimit: DAILY_LIMIT }));
route('GET', '/api/transactions', ['CUSTOMER'], c => {
  const a = one('SELECT account_id FROM accounts WHERE user_id=?', c.user.user_id), q = '%' + (c.q.get('q') || '') + '%';
  return all(`SELECT t.txn_id,t.amount,t.type,t.status,t.reference,t.description,t.created_at,t.from_account,fu.full_name from_name,tu.full_name to_name FROM transactions t
    LEFT JOIN accounts fa ON fa.account_id=t.from_account LEFT JOIN users fu ON fu.user_id=fa.user_id
    LEFT JOIN accounts ta ON ta.account_id=t.to_account LEFT JOIN users tu ON tu.user_id=ta.user_id
    WHERE (t.from_account=? OR t.to_account=?) AND (t.description LIKE ? OR t.reference LIKE ? OR fu.full_name LIKE ? OR tu.full_name LIKE ?) ORDER BY t.txn_id DESC LIMIT 100`, a.account_id, a.account_id, q, q, q, q)
    .map(r => ({ id: r.txn_id, title: label(r, a.account_id), amount: r.from_account === a.account_id ? -r.amount : r.amount, status: r.status, reference: r.reference, at: r.created_at, type: r.type }));
});
route('POST', '/api/transfer', ['CUSTOMER'], c => { pinOk(c.user, c.body.pin, c.ip); return moveMoney({ user: c.user, toAcc: c.body.toAccount, amount: c.body.amount, reference: c.body.reference, type: 'TRANSFER', desc: c.body.note || 'Transfer', ip: c.ip }); });
route('POST', '/api/bills', ['CUSTOMER'], c => { pinOk(c.user, c.body.pin, c.ip); if (!c.body.biller || !c.body.accountNo) throw new E(400, 'Choose a biller and enter the account or meter number'); return moveMoney({ user: c.user, amount: c.body.amount, reference: 'BILL' + crypto.randomBytes(5).toString('hex').toUpperCase(), type: 'BILL', desc: `${c.body.biller} ${c.body.accountNo}`, ip: c.ip }); });
route('POST', '/api/mpesa/stkpush', ['CUSTOMER'], c => stkPush(c.user, c.body.phone, c.body.amount));
route('GET', '/api/notifications', ['CUSTOMER'], c => { const r = all('SELECT notif_id id,message,sent_at at,read_at FROM notifications WHERE user_id=? ORDER BY notif_id DESC LIMIT 30', c.user.user_id); run('UPDATE notifications SET read_at=CURRENT_TIMESTAMP WHERE user_id=? AND read_at IS NULL', c.user.user_id); return r; });
route('GET', '/api/tickets', ['CUSTOMER'], c => all('SELECT ticket_id id,subject,status,created_at at FROM tickets WHERE user_id=? ORDER BY ticket_id DESC', c.user.user_id).map(t => ({ ...t, code: ticketCode(t.id) })));
route('POST', '/api/tickets', ['CUSTOMER'], c => {
  if (!c.body.subject?.trim()) throw new E(400, 'Describe the problem');
  const id = Number(run('INSERT INTO tickets(user_id,subject,description) VALUES(?,?,?)', c.user.user_id, c.body.subject.trim(), c.body.description || '').lastInsertRowid);
  audit(c.user.user_id, 'TICKET_CREATED', c.ip, ticketCode(id));
  for (const s of all("SELECT user_id FROM users WHERE role IN ('AGENT','ADMIN')")) ws.push(s.user_id, { type: 'TICKET', message: `New ticket ${ticketCode(id)} from ${c.user.full_name}` });
  return { id, code: ticketCode(id), status: 'OPEN' };
});
route('POST', '/api/feedback', ['CUSTOMER'], c => { const r = Number(c.body.rating); if (!(r >= 1 && r <= 5)) throw new E(400, 'Rating must be 1 to 5'); run('INSERT INTO feedback(user_id,txn_id,rating,comment) VALUES(?,?,?,?)', c.user.user_id, c.body.txnId ?? null, r, c.body.comment || ''); return { ok: true }; });

route('GET', '/api/staff/tickets', STAFF, () => all('SELECT t.ticket_id id,t.subject,t.description,t.status,t.created_at at,u.full_name customer FROM tickets t JOIN users u USING(user_id) ORDER BY t.ticket_id DESC').map(t => ({ ...t, code: ticketCode(t.id) })));
route('PATCH', '/api/staff/tickets/:id', STAFF, c => {
  if (!['IN_PROGRESS', 'RESOLVED'].includes(c.body.status)) throw new E(400, 'Bad status');
  const t = one('SELECT * FROM tickets WHERE ticket_id=?', c.params.id); if (!t) throw new E(404, 'Ticket not found');
  run('UPDATE tickets SET status=?, assigned_to=? WHERE ticket_id=?', c.body.status, c.user.user_id, t.ticket_id);
  audit(c.user.user_id, 'TICKET_' + c.body.status, c.ip, ticketCode(t.ticket_id));
  notify(t.user_id, null, `Your ticket ${ticketCode(t.ticket_id)} is now ${c.body.status.replace('_', ' ').toLowerCase()}.${c.body.status === 'RESOLVED' ? ' Please rate our service.' : ''}`, { ticket: c.body.status });
  return { ok: true };
});
route('GET', '/api/admin/summary', ADMIN, () => ({
  transactions: one('SELECT COUNT(*) n FROM transactions').n, failed: one("SELECT COUNT(*) n FROM transactions WHERE status='FAILED'").n,
  openTickets: one("SELECT COUNT(*) n FROM tickets WHERE status!='RESOLVED'").n, fraudAlerts: one("SELECT COUNT(*) n FROM audit_logs WHERE action='FRAUD_FLAG'").n,
  volumeToday: one("SELECT COALESCE(SUM(amount),0) s FROM transactions WHERE status='SUCCESS' AND date(created_at)=date('now')").s,
  avgRating: one('SELECT ROUND(AVG(rating),1) a FROM feedback').a }));
route('GET', '/api/admin/transactions', ADMIN, c => all(`SELECT t.txn_id id,t.type,t.amount,t.status,t.reference,t.created_at at,fu.full_name from_name,tu.full_name to_name FROM transactions t
  LEFT JOIN accounts fa ON fa.account_id=t.from_account LEFT JOIN users fu ON fu.user_id=fa.user_id LEFT JOIN accounts ta ON ta.account_id=t.to_account LEFT JOIN users tu ON tu.user_id=ta.user_id
  WHERE (?='' OR t.status=?) ORDER BY t.txn_id DESC LIMIT 50`, c.q.get('status') || '', c.q.get('status') || ''));
route('GET', '/api/admin/audit', ADMIN, c => all('SELECT l.log_id id,l.action,l.ip_address ip,l.details,l.created_at at,u.full_name user FROM audit_logs l LEFT JOIN users u USING(user_id) WHERE (?=\'\' OR l.action=?) ORDER BY l.log_id DESC LIMIT 60', c.q.get('action') || '', c.q.get('action') || ''));
route('GET', '/api/admin/users', ADMIN, () => all("SELECT user_id id,full_name name,phone,role,status FROM users ORDER BY user_id"));
route('POST', '/api/admin/users/:id/status', ADMIN, c => { if (!['ACTIVE', 'SUSPENDED'].includes(c.body.status)) throw new E(400, 'Bad status'); run('UPDATE users SET status=?, failed_count=0, locked_until=0 WHERE user_id=? AND role=\'CUSTOMER\'', c.body.status, c.params.id); audit(c.user.user_id, 'USER_' + c.body.status, c.ip, 'user ' + c.params.id); return { ok: true }; });

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
const server = http.createServer((req, res) => {
  const t0 = Date.now(), url = new URL(req.url, 'http://x'), ip = req.socket.remoteAddress;
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
  const send = (s, o) => { const b = JSON.stringify(o); res.writeHead(s, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(b); console.log(`${req.method} ${url.pathname} ${s} ${Date.now() - t0}ms`); };
  if (!url.pathname.startsWith('/api/')) {   // static front end
    const f = path.join(__dirname, 'public', url.pathname === '/' ? 'index.html' : path.normalize(url.pathname).replace(/^(\.\.[/\\])+/, ''));
    if (!f.startsWith(path.join(__dirname, 'public')) || !fs.existsSync(f) || fs.statSync(f).isDirectory()) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(f)] || 'application/octet-stream' }); return fs.createReadStream(f).pipe(res);
  }
  if (limited(ip)) return send(429, { error: 'Too many requests. Slow down.' });
  let raw = ''; req.on('data', d => { raw += d; if (raw.length > 1e5) req.destroy(); });
  req.on('end', () => {
    try {
      const r = routes.find(r => r.m === req.method && r.re.test(url.pathname));
      if (!r) return send(404, { error: 'Not found' });
      const c = { ip, q: url.searchParams, params: r.re.exec(url.pathname).groups || {}, body: {} };
      try { if (raw) c.body = JSON.parse(raw); } catch { return send(400, { error: 'Invalid JSON' }); }
      if (r.roles) {                                                    // gateway: token check + role check
        const d = verify((req.headers.authorization || '').replace('Bearer ', ''));
        const u = d && one('SELECT * FROM users WHERE user_id=?', d.sub);
        if (!u || u.status !== 'ACTIVE') return send(401, { error: 'Missing or invalid token' });
        if (!r.roles.includes(u.role)) return send(403, { error: 'Not allowed for your role' });
        c.user = u;
      }
      send(200, r.fn(c) ?? { ok: true });
    } catch (e) { if (!(e instanceof E)) console.error(e); send(e.s || 500, { error: e.s ? e.message : 'Server error' }); }
  });
});
server.on('upgrade', (req, socket) => {                                // WebSocket for live updates
  const d = verify(new URL(req.url, 'http://x').searchParams.get('token'));
  if (!d || !req.url.startsWith('/ws')) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return socket.destroy(); }
  ws.accept(req, socket, d.sub);
});

// ---------- Synthetic data only (1.7 Legal and ethical considerations) ----------
function seed() {
  if (one('SELECT COUNT(*) n FROM users').n) return;
  const u = (name, phone, pin, role) => Number(run('INSERT INTO users(full_name,phone,email,pin_hash,role) VALUES(?,?,?,?,?)', name, phone, name.split(' ')[0].toLowerCase() + '@example.test', hash(pin), role).lastInsertRowid);
  const a = (uid, no, bal) => Number(run('INSERT INTO accounts(user_id,account_number,balance) VALUES(?,?,?)', uid, no, bal).lastInsertRowid);
  const amina = a(u('Amina Wanjiru', '0712345678', '1234', 'CUSTOMER'), '1234567890', 45300);
  a(u('John Mwangi', '0722000111', '1234', 'CUSTOMER'), '1234567891', 12000);
  a(u('Grace Achieng', '0733000222', '1234', 'CUSTOMER'), '1234567892', 8500);
  u('Mercy Admin', '0700000001', '9999', 'ADMIN'); u('Peter Agent', '0700000002', '8888', 'AGENT');
  const t = (f, to, amt, type, desc, ref, ago) => run("INSERT INTO transactions(from_account,to_account,amount,type,status,reference,description,created_at) VALUES(?,?,?,?, 'SUCCESS',?,?,datetime('now',?))", f, to, amt, type, ref, desc, ago);
  t(null, amina, 38000, 'MPESA_DEPOSIT', 'Salary credit', 'SEED-1', '-30 hours'); t(amina, null, 850, 'BILL', 'Water 5521', 'SEED-2', '-28 hours'); t(amina, null, 100, 'BILL', 'Airtime 0712345678', 'SEED-3', '-27 hours');
  t(null, amina, 5000, 'MPESA_DEPOSIT', 'M-Pesa deposit', 'SEED-4', '-3 hours'); t(amina, null, 1200, 'BILL', 'KPLC token 4401', 'SEED-5', '-2 hours');
  run("INSERT INTO tickets(user_id,subject,description,status) VALUES(1,'Failed transfer','Transfer showed pending','IN_PROGRESS')");
}
seed();
if (require.main === module) server.listen(PORT, () => console.log(`Family Bank real-time banking prototype listening on http://localhost:${PORT}  (DEMO_MODE=${DEMO})`));
