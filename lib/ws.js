// Minimal WebSocket server (RFC 6455) so the project needs no npm packages. Server -> client push only.
const crypto = require('crypto');
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const clients = new Map(); // userId -> Set of sockets

function frame(text, op = 1) {
  const p = Buffer.from(text), n = p.length;
  let h;
  if (n < 126) h = Buffer.from([0x80 | op, n]);
  else if (n < 65536) { h = Buffer.alloc(4); h[0] = 0x80 | op; h[1] = 126; h.writeUInt16BE(n, 2); }
  else { h = Buffer.alloc(10); h[0] = 0x80 | op; h[1] = 127; h.writeBigUInt64BE(BigInt(n), 2); }
  return Buffer.concat([h, p]);
}
function accept(req, socket, userId) {
  const key = req.headers['sec-websocket-key'];
  const acc = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ' + acc + '\r\n\r\n');
  if (!clients.has(userId)) clients.set(userId, new Set());
  clients.get(userId).add(socket);
  socket.on('data', b => { const op = b[0] & 15; if (op === 8) socket.end(frame('', 8)); else if (op === 9) socket.write(frame('', 10)); });
  const drop = () => { const s = clients.get(userId); if (s) { s.delete(socket); if (!s.size) clients.delete(userId); } };
  socket.on('close', drop); socket.on('error', drop);
}
// Alerts reach only the owner's own connections (Table 2.3.2: delivery only to the owner).
function push(userId, obj) {
  const s = clients.get(userId); if (!s) return 0;
  for (const k of s) k.write(frame(JSON.stringify(obj)));
  return s.size;
}
module.exports = { accept, push };
