require('dotenv').config();
const express = require('express'), path = require('path'), fs = require('fs'), crypto = require('crypto');
const { DatabaseSync } = require('node:sqlite'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const helmet = require('helmet'), rateLimit = require('express-rate-limit'), compression = require('compression');
const cookieParser = require('cookie-parser'), multer = require('multer'), Razorpay = require('razorpay');
const nodemailer = require('nodemailer'), PDFDocument = require('pdfkit');

const { JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET } = process.env;
if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error('Set a JWT_SECRET of 32+ characters in .env');
const prod = process.env.NODE_ENV === 'production';
const E = process.env, rupees = n => 'Rs. ' + (n / 100).toFixed(2);
const FREE_ABOVE = (+E.FREE_DELIVERY_ABOVE || 1500) * 100, DELIVERY = (+E.DELIVERY_CHARGE || 80) * 100;
const SHOP = E.SHOP_NAME || 'Sivakasi Sparks', BASE = E.BASE_URL || 'http://localhost:3000';
// Email (any SMTP: Gmail, Brevo, Zoho...) and SMS (Twilio). Both are optional: if not configured they are skipped.
const mailer = E.SMTP_HOST ? nodemailer.createTransport({ host: E.SMTP_HOST, port: +E.SMTP_PORT || 587, auth: { user: E.SMTP_USER, pass: E.SMTP_PASS } }) : null;
const mail = (to, subject, text, attachments) => mailer ? mailer.sendMail({ from: E.MAIL_FROM || E.SMTP_USER, to, subject, text, attachments }).catch(e => console.error('mail:', e.message)) : Promise.resolve();
const sms = (phone, body) => E.TWILIO_SID ? fetch(`https://api.twilio.com/2010-04-01/Accounts/${E.TWILIO_SID}/Messages.json`, { method: 'POST',
  headers: { Authorization: 'Basic ' + Buffer.from(E.TWILIO_SID + ':' + E.TWILIO_TOKEN).toString('base64'), 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ To: '+91' + phone, From: E.TWILIO_FROM, Body: body }) }).catch(e => console.error('sms:', e.message)) : Promise.resolve();

// ---------- Database (WAL mode = many readers + one writer, no lag) ----------
const db = new DatabaseSync(path.join(__dirname, 'shop.db'));   // built into Node: nothing to compile
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000;');
db.transaction = fn => (...a) => { db.exec('BEGIN IMMEDIATE'); try { const r = fn(...a); db.exec('COMMIT'); return r; } catch (e) { db.exec('ROLLBACK'); throw e; } };
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT, email TEXT UNIQUE, hash TEXT, role TEXT DEFAULT 'customer');
CREATE TABLE IF NOT EXISTS products(id INTEGER PRIMARY KEY, name TEXT NOT NULL, description TEXT, price INTEGER NOT NULL,
  stock INTEGER NOT NULL DEFAULT 0, category TEXT, image TEXT, active INTEGER DEFAULT 1, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS orders(id INTEGER PRIMARY KEY, user_id INTEGER, total INTEGER, status TEXT DEFAULT 'pending',
  address TEXT, phone TEXT, rzp_order TEXT, rzp_payment TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS order_items(order_id INTEGER, product_id INTEGER, name TEXT, price INTEGER, qty INTEGER);
CREATE INDEX IF NOT EXISTS idx_prod ON products(active, category);
`);
require('./seed.js').seedCatalogue(db);   // first start: load the 102-cracker catalogue (hidden until the admin switches items on)
if (ADMIN_EMAIL && ADMIN_PASSWORD) {   // keeps the admin login in sync with .env (change the email in .env and restart)
  const em = ADMIN_EMAIL.toLowerCase(), ad = db.prepare("SELECT * FROM users WHERE role='admin'").get(), same = db.prepare('SELECT * FROM users WHERE email=?').get(em), h = bcrypt.hashSync(ADMIN_PASSWORD, 12);
  if (same && same.role !== 'admin') { db.prepare("UPDATE users SET role='admin',hash=? WHERE id=?").run(h, same.id); if (ad) db.prepare("UPDATE users SET role='customer' WHERE id=?").run(ad.id); }
  else if (!same && ad) db.prepare('UPDATE users SET email=?,hash=? WHERE id=?').run(em, h, ad.id);
  else if (!same && !ad) db.prepare("INSERT INTO users(name,email,hash,role) VALUES(?,?,?,'admin')").run('Admin', em, h);
}

// ---------- App + security ----------
const app = express();
app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrcAttr: ["'unsafe-inline'"], scriptSrc: ["'self'", "'unsafe-inline'", 'https://checkout.razorpay.com'],
  styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'], fontSrc: ['https://fonts.gstatic.com'],
  imgSrc: ["'self'", 'data:'], frameSrc: ['https://api.razorpay.com'], connectSrc: ["'self'", 'https://*.razorpay.com'] } } }));
app.use(compression()); app.use(express.json({ limit: '50kb', verify: (req, _, buf) => { req.raw = buf; } })); app.use(cookieParser());
app.use(rateLimit({ windowMs: 60_000, max: 300 }));
const authLimit = rateLimit({ windowMs: 15 * 60_000, max: 20, message: { error: 'Too many attempts. Try again later.' } });
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', setHeaders: (r, f) => f.endsWith('.html') && r.setHeader('Cache-Control', 'no-cache') }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), { maxAge: '7d' }));

// CSRF: cookie is SameSite=Strict, and every write must carry this header
app.use((req, res, next) => (['GET', 'HEAD'].includes(req.method) || req.path === '/api/webhook' || req.get('X-Requested-With') === 'diwali') ? next() : res.status(403).json({ error: 'Blocked' }));

const sign = u => jwt.sign({ id: u.id, role: u.role }, JWT_SECRET, { expiresIn: '8h' });
const setCookie = (res, u) => res.cookie('t', sign(u), { httpOnly: true, sameSite: 'strict', secure: prod, maxAge: 8 * 3600e3 });
const auth = (req, res, next) => { try { req.user = jwt.verify(req.cookies.t, JWT_SECRET); next(); } catch { res.status(401).json({ error: 'Please log in' }); } };
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ error: 'Admins only' });
const wrap = fn => (req, res) => { try { fn(req, res); } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); } };

// ---------- Image upload (admin only; type + size checked) ----------
const upload = multer({
  storage: multer.diskStorage({ destination: path.join(__dirname, 'uploads'),
    filename: (_, f, cb) => cb(null, crypto.randomBytes(12).toString('hex') + ({ 'image/jpeg': '.jpg', 'image/png': '.png', 'image/webp': '.webp' })[f.mimetype]) }),
  limits: { fileSize: 3 * 1024 * 1024 },
  fileFilter: (_, f, cb) => cb(null, ['image/jpeg', 'image/png', 'image/webp'].includes(f.mimetype))
});

// ---------- Auth ----------
app.post('/api/register', authLimit, wrap((req, res) => {
  const { name, email, password } = req.body;
  if (!name || !/^\S+@\S+\.\S+$/.test(email) || !password || password.length < 8) return res.status(400).json({ error: 'Enter name, valid email and 8+ character password' });
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email.toLowerCase())) return res.status(409).json({ error: 'Email already registered' });
  const id = db.prepare('INSERT INTO users(name,email,hash) VALUES(?,?,?)').run(String(name).slice(0, 80), email.toLowerCase(), bcrypt.hashSync(password, 12)).lastInsertRowid;
  const u = { id, role: 'customer', name }; setCookie(res, u); res.json({ name, role: 'customer' });
}));
app.post('/api/login', authLimit, wrap((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(req.body.email || '').toLowerCase());
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.hash)) return res.status(401).json({ error: 'Wrong email or password' });
  setCookie(res, u); res.json({ name: u.name, role: u.role });
}));
app.post('/api/logout', (req, res) => res.clearCookie('t').json({ ok: true }));
app.get('/api/me', auth, wrap((req, res) => res.json(db.prepare('SELECT name,role FROM users WHERE id=?').get(req.user.id))));

// ---------- Shop details for the footer (edit in .env) ----------
app.get('/api/shop', (req, res) => res.json({ name: SHOP, address: E.SHOP_ADDRESS || '', phone: E.SHOP_PHONE || '', email: E.SHOP_EMAIL || '',
  hours: E.SHOP_HOURS || '', whatsapp: E.SHOP_WHATSAPP || '', license: E.EXPLOSIVES_LICENSE || '' }));

// ---------- Public catalogue (read-only) ----------
app.get('/api/products', wrap((req, res) =>
  res.json(db.prepare('SELECT id,name,description,price,stock,category,image FROM products WHERE active=1 ORDER BY id DESC').all())));

// ---------- Admin product management ----------
const parseProduct = b => ({ name: String(b.name || '').trim().slice(0, 120), description: String(b.description || '').slice(0, 1000),
  price: Math.round(Number(b.price) * 100), stock: parseInt(b.stock, 10), category: String(b.category || 'General').slice(0, 40) });
const valid = p => p.name && p.price > 0 && p.stock >= 0;
app.post('/api/admin/products', auth, admin, upload.single('image'), wrap((req, res) => {
  const p = parseProduct(req.body); if (!valid(p)) return res.status(400).json({ error: 'Name, price and stock are required' });
  const id = db.prepare('INSERT INTO products(name,description,price,stock,category,image) VALUES(?,?,?,?,?,?)')
    .run(p.name, p.description, p.price, p.stock, p.category, req.file ? '/uploads/' + req.file.filename : null).lastInsertRowid;
  res.json({ id });
}));
app.put('/api/admin/products/:id', auth, admin, upload.single('image'), wrap((req, res) => {
  const p = parseProduct(req.body); if (!valid(p)) return res.status(400).json({ error: 'Name, price and stock are required' });
  db.prepare('UPDATE products SET name=?,description=?,price=?,stock=?,category=?,image=COALESCE(?,image) WHERE id=?')
    .run(p.name, p.description, p.price, p.stock, p.category, req.file ? '/uploads/' + req.file.filename : null, req.params.id);
  res.json({ ok: true });
}));
app.delete('/api/admin/products/:id', auth, admin, wrap((req, res) => { db.prepare('UPDATE products SET active=0 WHERE id=?').run(req.params.id); res.json({ ok: true }); }));
app.get('/api/admin/orders', auth, admin, wrap((req, res) => {
  const orders = db.prepare('SELECT o.*,u.name customer,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 200').all();
  const items = db.prepare('SELECT name,qty,price FROM order_items WHERE order_id=?');
  res.json(orders.map(o => ({ ...o, items: items.all(o.id) })));
}));
app.put('/api/admin/orders/:id', auth, admin, wrap((req, res) => {
  if (!['paid', 'shipped', 'delivered', 'cancelled'].includes(req.body.status)) return res.status(400).json({ error: 'Bad status' });
  db.prepare('UPDATE orders SET status=? WHERE id=?').run(req.body.status, req.params.id);
  const o = db.prepare('SELECT o.id,o.phone,u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?').get(req.params.id);
  if (o && ['shipped', 'delivered'].includes(req.body.status)) { mail(o.email, `Order #${o.id} ${req.body.status}`, `Your ${SHOP} order #${o.id} is now ${req.body.status}.`); sms(o.phone, `${SHOP}: order #${o.id} is ${req.body.status}.`); }
  res.json({ ok: true });
}));

// ---------- Checkout (prices & stock ALWAYS taken from the database, never from the browser) ----------
const rzp = RAZORPAY_KEY_ID ? new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET }) : null;
const getCoupon = code => code ? db.prepare('SELECT * FROM coupons WHERE code=? AND active=1').get(String(code).trim().toUpperCase()) : null;
function priceCart(cart, code) {           // single source of truth for prices, coupon and delivery
  let subtotal = 0; const lines = [];
  for (const c of cart) {
    const qty = parseInt(c.qty, 10), p = db.prepare('SELECT * FROM products WHERE id=? AND active=1').get(c.id);
    if (!p || !(qty > 0)) throw new Error('Invalid item in cart');
    if (p.stock < qty) throw new Error(`Only ${p.stock} left of ${p.name}`);
    subtotal += p.price * qty; lines.push([p.id, p.name, p.price, qty]);
  }
  const cp = getCoupon(code); if (code && !cp) throw new Error('Invalid coupon code');
  if (cp && subtotal < cp.min_total) throw new Error(`Coupon needs a minimum order of ${rupees(cp.min_total)}`);
  const discount = cp ? Math.floor(subtotal * cp.percent / 100) : 0, delivery = subtotal - discount >= FREE_ABOVE ? 0 : DELIVERY;
  return { lines, subtotal, discount, delivery, total: subtotal - discount + delivery, coupon: cp ? cp.code : null };
}
const reserve = db.transaction((userId, cart, address, phone, code) => {
  const q = priceCart(cart, code);
  q.lines.forEach(l => { if (!db.prepare('UPDATE products SET stock=stock-? WHERE id=? AND stock>=?').run(l[3], l[0], l[3]).changes) throw new Error('Stock changed, please try again'); });
  const oid = db.prepare('INSERT INTO orders(user_id,total,address,phone,subtotal,discount,delivery,coupon) VALUES(?,?,?,?,?,?,?,?)')
    .run(userId, q.total, address, phone, q.subtotal, q.discount, q.delivery, q.coupon).lastInsertRowid;
  q.lines.forEach(l => db.prepare('INSERT INTO order_items VALUES(?,?,?,?,?)').run(oid, ...l));
  return { oid, total: q.total };
});
const restock = db.transaction(oid => {
  db.prepare('SELECT product_id,qty FROM order_items WHERE order_id=?').all(oid).forEach(i => db.prepare('UPDATE products SET stock=stock+? WHERE id=?').run(i.qty, i.product_id));
  db.prepare("UPDATE orders SET status='cancelled' WHERE id=?").run(oid);
});
app.post('/api/checkout', auth, wrap(async (req, res) => {
  const { cart, address, phone } = req.body;
  if (!Array.isArray(cart) || !cart.length || cart.length > 50 || !address || !/^\d{10}$/.test(phone)) return res.status(400).json({ error: 'Add address and a 10-digit phone number' });
  if (!rzp) return res.status(503).json({ error: 'Payments are not configured yet' });
  let r; try { r = reserve(req.user.id, cart, String(address).slice(0, 300), phone, req.body.coupon); } catch (e) { return res.status(400).json({ error: e.message }); }
  try {
    const o = await rzp.orders.create({ amount: r.total, currency: 'INR', receipt: 'o' + r.oid });
    db.prepare('UPDATE orders SET rzp_order=? WHERE id=?').run(o.id, r.oid);
    res.json({ key: RAZORPAY_KEY_ID, rzpOrder: o.id, amount: r.total, orderId: r.oid });
  } catch { restock(r.oid); res.status(502).json({ error: 'Payment gateway error. Try again.' }); }
}));
app.post('/api/verify', auth, wrap((req, res) => {
  const { razorpay_order_id: oid, razorpay_payment_id: pid, razorpay_signature: sig } = req.body;
  const expected = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(oid + '|' + pid).digest('hex');
  const ok = sig && sig.length === expected.length && crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
  if (!ok) return res.status(400).json({ error: 'Payment verification failed' });
  markPaid(oid, pid);
  res.json({ ok: true });
}));
app.get('/api/my-orders', auth, wrap((req, res) => res.json(db.prepare('SELECT id,total,status,created FROM orders WHERE user_id=? ORDER BY id DESC').all(req.user.id))));

// ---------- Payment confirmed: used by BOTH the browser callback and the Razorpay webhook (safe to run twice) ----------
function markPaid(rzpOrder, pid) {
  const o = db.prepare('SELECT * FROM orders WHERE rzp_order=?').get(rzpOrder);
  if (!o || ['paid', 'shipped', 'delivered'].includes(o.status)) return;
  db.transaction(() => {
    if (o.status === 'cancelled') db.prepare('SELECT product_id,qty FROM order_items WHERE order_id=?').all(o.id)   // paid after the 20-min timeout: take stock again
      .forEach(i => db.prepare('UPDATE products SET stock=MAX(stock-?,0) WHERE id=?').run(i.qty, i.product_id));
    db.prepare("UPDATE orders SET status='paid',rzp_payment=? WHERE id=?").run(pid, o.id);
  })();
  notifyPaid(o.id).catch(e => console.error('notify:', e.message));
}
async function notifyPaid(id) {
  const o = db.prepare('SELECT o.*,u.email,u.name FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?').get(id), pdf = await invoiceBuffer(id);
  mail(o.email, `Order #${id} confirmed`, `Hi ${o.name}, your order #${id} of ${rupees(o.total)} is confirmed. Your invoice is attached. Thank you for shopping with ${SHOP}!`, [{ filename: `invoice-${id}.pdf`, content: pdf }]);
  mail(E.ADMIN_NOTIFY_EMAIL || ADMIN_EMAIL, `New paid order #${id}`, `${o.name} (${o.phone}) paid ${rupees(o.total)}.\nShip to: ${o.address}`);
  sms(o.phone, `${SHOP}: order #${id} confirmed, ${rupees(o.total)}. Thank you!`);
  if (E.ADMIN_PHONE) sms(E.ADMIN_PHONE, `New paid order #${id}, ${rupees(o.total)}`);
}
app.post('/api/webhook', wrap((req, res) => {   // set this URL in Razorpay Dashboard > Webhooks
  const secret = E.RAZORPAY_WEBHOOK_SECRET, sig = req.get('x-razorpay-signature') || '';
  if (!secret) return res.status(503).end();
  const exp = crypto.createHmac('sha256', secret).update(req.raw || '').digest('hex');
  if (sig.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(exp))) return res.status(400).end();
  const p = req.body.payload && req.body.payload.payment && req.body.payload.payment.entity;
  if (['payment.captured', 'order.paid'].includes(req.body.event) && p) markPaid(p.order_id, p.id);
  res.json({ ok: true });
}));

// ---------- Invoice PDF ----------
function invoiceBuffer(id) {
  return new Promise(resolve => {
    const o = db.prepare('SELECT o.*,u.name,u.email FROM orders o JOIN users u ON u.id=o.user_id WHERE o.id=?').get(id), items = db.prepare('SELECT * FROM order_items WHERE order_id=?').all(id);
    const d = new PDFDocument({ margin: 50 }), bufs = []; d.on('data', b => bufs.push(b)); d.on('end', () => resolve(Buffer.concat(bufs)));
    d.fontSize(20).text(SHOP + ' - Invoice'); if (E.GSTIN) d.fontSize(10).text('GSTIN: ' + E.GSTIN);
    d.moveDown().fontSize(11).text(`Invoice #${id}     Date: ${o.created}`).text(`Customer: ${o.name} (${o.email})`).text(`Phone: ${o.phone}`).text(`Ship to: ${o.address}`).moveDown();
    items.forEach(i => d.text(`${i.name}  x ${i.qty}  @ ${rupees(i.price)}  =  ${rupees(i.price * i.qty)}`));
    d.moveDown().text(`Subtotal: ${rupees(o.subtotal == null ? o.total : o.subtotal)}`);
    if (o.discount) d.text(`Discount (${o.coupon}): -${rupees(o.discount)}`);
    d.text(`Delivery: ${rupees(o.delivery || 0)}`).moveDown().fontSize(14).text(`Total paid: ${rupees(o.total)}`); d.end();
  });
}
app.get('/api/invoice/:id', auth, async (req, res) => {
  try {
    const o = db.prepare('SELECT user_id,status FROM orders WHERE id=?').get(req.params.id);
    if (!o || (o.user_id !== req.user.id && req.user.role !== 'admin') || !['paid', 'shipped', 'delivered'].includes(o.status)) return res.status(404).json({ error: 'Invoice not found' });
    res.type('pdf').set('Content-Disposition', `inline; filename=invoice-${req.params.id}.pdf`).send(await invoiceBuffer(req.params.id));
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error' }); }
});

// ---------- Cart quote (subtotal, coupon, delivery) ----------
app.post('/api/quote', wrap((req, res) => {
  try { const q = priceCart((req.body.cart || []).slice(0, 50), req.body.coupon); res.json({ subtotal: q.subtotal, discount: q.discount, delivery: q.delivery, total: q.total, coupon: q.coupon }); }
  catch (e) { res.status(400).json({ error: e.message }); }
}));

// ---------- Password reset (link valid 30 minutes, stored hashed) ----------
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
app.post('/api/forgot', authLimit, wrap((req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE email=?').get(String(req.body.email || '').toLowerCase());
  if (u) { const t = crypto.randomBytes(32).toString('hex'); db.prepare('UPDATE users SET reset_hash=?,reset_exp=? WHERE id=?').run(sha(t), Date.now() + 30 * 60e3, u.id);
    mail(u.email, 'Reset your password', `Open this link within 30 minutes to choose a new password:\n${BASE}/#reset=${t}\n\nIf you did not ask for this, ignore this email.`); }
  res.json({ ok: true });   // same answer whether or not the email exists
}));
app.post('/api/reset', authLimit, wrap((req, res) => {
  const { token, password } = req.body; if (!token || !password || password.length < 8) return res.status(400).json({ error: 'Use a password of 8+ characters' });
  const u = db.prepare('SELECT id FROM users WHERE reset_hash=? AND reset_exp>?').get(sha(String(token)), Date.now());
  if (!u) return res.status(400).json({ error: 'This reset link is invalid or expired' });
  db.prepare('UPDATE users SET hash=?,reset_hash=NULL,reset_exp=NULL WHERE id=?').run(bcrypt.hashSync(password, 12), u.id); res.json({ ok: true });
}));

// ---------- Admin stock & prices (all products, including hidden ones) ----------
app.get('/api/admin/products', auth, admin, wrap((req, res) => res.json(db.prepare('SELECT id,name,description,price,stock,category,image,active FROM products ORDER BY active DESC,category,name').all())));
app.put('/api/admin/inventory', auth, admin, wrap((req, res) => {
  const items = Array.isArray(req.body.items) ? req.body.items.slice(0, 500) : [], up = db.prepare('UPDATE products SET stock=?,price=?,active=? WHERE id=?');
  db.transaction(() => items.forEach(i => { const stock = parseInt(i.stock, 10), price = Math.round(Number(i.price) * 100), id = parseInt(i.id, 10);
    if (id > 0 && stock >= 0 && price > 0) up.run(stock, price, i.active ? 1 : 0, id); }))();
  res.json({ ok: true });
}));

// ---------- Admin coupons ----------
app.get('/api/admin/coupons', auth, admin, wrap((req, res) => res.json(db.prepare('SELECT * FROM coupons WHERE active=1').all())));
app.post('/api/admin/coupons', auth, admin, wrap((req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase(), percent = parseInt(req.body.percent, 10), min = Math.round(Number(req.body.min || 0) * 100);
  if (!/^[A-Z0-9]{3,20}$/.test(code) || !(percent > 0 && percent <= 90)) return res.status(400).json({ error: 'Code: 3-20 letters/numbers. Discount: 1-90%' });
  db.prepare('INSERT OR REPLACE INTO coupons VALUES(?,?,?,1)').run(code, percent, min); res.json({ ok: true });
}));
app.delete('/api/admin/coupons/:code', auth, admin, wrap((req, res) => { db.prepare('UPDATE coupons SET active=0 WHERE code=?').run(req.params.code); res.json({ ok: true }); }));

// Release stock for unpaid orders older than 20 minutes
setInterval(() => db.prepare("SELECT id FROM orders WHERE status='pending' AND created < datetime('now','-20 minutes')").all().forEach(o => restock(o.id)), 60_000);

app.listen(process.env.PORT || 3000, () => console.log('Store running on port ' + (process.env.PORT || 3000)));