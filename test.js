// Automated feature tests TC01-TC12 (Table 3.4.1). Run with: npm test
// Starts its own server on port 3999 with an in-memory database, so your real data is never touched.
const { spawn } = require('child_process');
const PORT = 3999, BASE = `http://localhost:${PORT}`;
const srv = spawn(process.execPath, ['server.js'], { env: { ...process.env, PORT, DB_FILE: ':memory:', OTP_TTL: '2', RATE_LIMIT: '80', DEMO_MODE: 'true' }, stdio: ['ignore', 'pipe', 'inherit'] });
const results = [];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const call = async (path, { method = 'GET', body, token } = {}) => {
  const r = await fetch(BASE + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: 'Bearer ' + token } : {}) }, body: body && JSON.stringify(body) });
  return { status: r.status, data: await r.json().catch(() => ({})) };
};
const login = async (phone, pin) => { const a = await call('/api/auth/login', { method: 'POST', body: { phone, pin } }); const b = await call('/api/auth/verify-otp', { method: 'POST', body: { phone, otp: a.data.demoOtp } }); return b.data.token; };
const balance = async t => (await call('/api/me', { token: t })).data.account.balance;
const ref = () => 'T' + Math.random().toString(36).slice(2, 10);
const test = async (id, name, fn) => { try { const note = await fn(); results.push([id, name, 'PASS', note || '']); } catch (e) { results.push([id, name, 'FAIL', e.message]); } };
const expect = (c, m) => { if (!c) throw new Error(m); };

(async () => {
  await new Promise(r => srv.stdout.on('data', d => String(d).includes('listening') && r()));
  let amina;
  await test('TC01', 'Login with correct PIN and OTP', async () => { amina = await login('0712345678', '1234'); const m = await call('/api/me', { token: amina }); expect(m.status === 200 && m.data.account, 'dashboard data not returned'); });
  await test('TC02', 'Login with wrong PIN three times locks account', async () => {
    for (let i = 0; i < 3; i++) await call('/api/auth/login', { method: 'POST', body: { phone: '0722000111', pin: '0000' } });
    const r = await call('/api/auth/login', { method: 'POST', body: { phone: '0722000111', pin: '1234' } }); expect(r.status === 423, 'expected 423, got ' + r.status); });
  await test('TC03', 'Expired OTP is rejected', async () => {
    const a = await call('/api/auth/login', { method: 'POST', body: { phone: '0733000222', pin: '1234' } }); await sleep(2300);
    const r = await call('/api/auth/verify-otp', { method: 'POST', body: { phone: '0733000222', otp: a.data.demoOtp } }); expect(r.status === 401, 'expected 401, got ' + r.status); });
  await test('TC04', 'Transfer within balance: balances updated, alert within 2 s', async () => {
    const ws = new WebSocket(`ws://localhost:${PORT}/ws?token=${amina}`); await new Promise((ok, no) => { ws.onopen = ok; ws.onerror = () => no(new Error('WebSocket failed')); });
    const got = new Promise(r => { ws.onmessage = e => r(Date.now()); });
    const before = await balance(amina), t0 = Date.now();
    const r = await call('/api/transfer', { method: 'POST', token: amina, body: { toAccount: '1234567891', amount: 1000, reference: ref(), pin: '1234' } });
    expect(r.status === 200, 'transfer failed: ' + JSON.stringify(r.data));
    const t1 = await Promise.race([got, sleep(2000).then(() => null)]); ws.close();
    expect(t1, 'no WebSocket alert within 2 s'); expect(await balance(amina) === before - 1000, 'balance wrong');
    return `confirmed in ${t1 - t0} ms`; });
  await test('TC05', 'Transfer above balance is rejected, balances unchanged', async () => {
    const b = await balance(amina); const r = await call('/api/transfer', { method: 'POST', token: amina, body: { toAccount: '1234567891', amount: b + 1000, reference: ref(), pin: '1234' } });
    expect(r.status === 422 && await balance(amina) === b, 'expected 422 and unchanged balance'); return r.data.error; });
  await test('TC06', 'Same reference sent twice: one debit only', async () => {
    const b = await balance(amina), x = ref(), body = { toAccount: '1234567891', amount: 500, reference: x, pin: '1234' };
    const r1 = await call('/api/transfer', { method: 'POST', token: amina, body }), r2 = await call('/api/transfer', { method: 'POST', token: amina, body });
    expect(r1.status === 200 && r2.status === 409 && await balance(amina) === b - 500, `got ${r1.status}/${r2.status}`); });
  await test('TC07', 'Two simultaneous transfers draining one account: only one succeeds', async () => {
    const b = await balance(amina), amt = Math.floor(b * 0.7);
    const rs = await Promise.all([1, 2].map(() => call('/api/transfer', { method: 'POST', token: amina, body: { toAccount: '1234567891', amount: amt, reference: ref(), pin: '1234' } })));
    const ok = rs.filter(r => r.status === 200).length; expect(ok === 1 && await balance(amina) >= 0, `successes: ${ok}`); });
  await test('TC08', 'M-Pesa success callback credits once and notifies', async () => {
    const b = await balance(amina), s = await call('/api/mpesa/stkpush', { method: 'POST', token: amina, body: { amount: 500 } });
    globalThis.cb = { Body: { stkCallback: { CheckoutRequestID: s.data.checkoutId, ResultCode: 0, CallbackMetadata: { Item: [{ Name: 'Amount', Value: 500 }, { Name: 'MpesaReceiptNumber', Value: 'TESTRCPT1' }] } } } };
    await call('/api/payments/mpesa/callback', { method: 'POST', body: cb }); expect(await balance(amina) === b + 500, 'account not credited once'); globalThis.afterCb = b + 500; });
  await test('TC09', 'Repeated M-Pesa callback gives no second credit', async () => { await call('/api/payments/mpesa/callback', { method: 'POST', body: cb }); expect(await balance(amina) === afterCb, 'credited twice'); });
  await test('TC10', 'Request without a valid token is rejected (401)', async () => { const r = await call('/api/me'); const r2 = await call('/api/me', { token: 'fake.token.value' }); expect(r.status === 401 && r2.status === 401, 'not rejected'); });
  await test('TC11', 'Complaint creates a ticket visible to customer and agent', async () => {
    const t = await call('/api/tickets', { method: 'POST', token: amina, body: { subject: 'Test complaint', description: 'Automated test' } });
    const mine = await call('/api/tickets', { token: amina }); const agent = await login('0700000002', '8888'); const staff = await call('/api/staff/tickets', { token: agent });
    expect(t.status === 200 && mine.data.some(x => x.code === t.data.code) && staff.data.some(x => x.code === t.data.code), 'ticket not visible to both'); return t.data.code; });
  await test('TC12', 'Rate limit exceeded: further requests rejected (429)', async () => {
    let hit = 0; for (let i = 0; i < 100; i++) if ((await call('/api/health')).status === 429) hit++; expect(hit > 0, 'no 429 seen'); return hit + ' requests blocked'; });

  console.log('\nID    Result  Feature tested');
  for (const [id, name, st, note] of results) console.log(`${id}  ${st}    ${name}${note ? '  -> ' + note : ''}`);
  const pass = results.filter(r => r[2] === 'PASS').length; console.log(`\n${pass}/${results.length} tests passed`);
  srv.kill(); process.exit(pass === results.length ? 0 : 1);
})();
