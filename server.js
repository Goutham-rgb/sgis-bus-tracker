require('dotenv').config();
const path = require('path');

const express = require('express');
const cors = require('cors');
const http = require('http');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { Server } = require('socket.io');
const { query } = require('./data/db');

const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
    secure: process.env.NODE_ENV === 'production', // requires HTTPS in production
    sameSite: 'lax'
  }
}));

const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

const DRIVER_PIN = process.env.DRIVER_PIN || '1234';
const OTP_DEV_MODE = process.env.OTP_DEV_MODE !== 'false'; // default true — see .env.example

// ============================================================
// AUTH — Admin (session login)
// ============================================================

function requireAdmin(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.status(401).json({ error: 'Not logged in' });
}

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const rows = await query('SELECT * FROM admin_users WHERE username = $1', [username]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid username or password' });

  req.session.isAdmin = true;
  req.session.username = user.username;
  res.json({ ok: true, username: user.username });
});

app.post('/api/admin/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/admin/session', (req, res) => {
  res.json({ loggedIn: !!(req.session && req.session.isAdmin), username: req.session ? req.session.username : null });
});

// Gate the admin.html page itself — must be logged in to load it
app.get('/admin.html', (req, res, next) => {
  if (req.session && req.session.isAdmin) return next();
  res.redirect('/login.html');
});

// Gate the parent.html page itself — must be logged in (MID + OTP) to load it
app.get('/parent.html', (req, res, next) => {
  if (req.session && req.session.parentPhone) return next();
  res.redirect('/parent-login.html');
});

app.use(express.static('public'));

// ============================================================
// AUTH — Parent login (Member ID + OTP, session-based)
// ============================================================

function generateOtp() {
  return String(crypto.randomInt(100000, 999999));
}

function maskPhone(phone) {
  if (!phone || phone.length < 4) return phone;
  return phone.slice(0, -4).replace(/./g, '•') + phone.slice(-4);
}

// Step 1: parent enters their Member ID (MID) — never a phone number or username
app.post('/api/parent/request-otp', async (req, res) => {
  const { member_id } = req.body;
  if (!member_id) return res.status(400).json({ error: 'Member ID is required' });

  const rows = await query('SELECT * FROM students WHERE member_id = $1', [member_id]);
  if (!rows.length) return res.status(404).json({ error: 'No student found for that Member ID' });

  const phone = rows[0].parent_phone;
  const otp = generateOtp();
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes
  await query(
    'INSERT INTO parent_otps (phone, otp_code, expires_at) VALUES ($1, $2, $3)',
    [phone, otp, expiresAt]
  );

  // ---- Wire a real SMS provider here for production (e.g. MSG91, Twilio) ----
  // Example: await smsProvider.send(phone, `Your SSGIS Bus Tracker OTP is ${otp}`);
  console.log(`[OTP] MID ${member_id} (${phone}) -> ${otp} (expires in 5 min)`);

  const response = { ok: true, message: 'OTP sent', masked_phone: maskPhone(phone) };
  if (OTP_DEV_MODE) response.dev_otp = otp; // remove this in production once a real SMS provider is wired in
  res.json(response);
});

// Step 2: parent enters the OTP — on success, logs them in (session cookie)
app.post('/api/parent/verify-otp', async (req, res) => {
  const { member_id, otp } = req.body;
  const studentRows = await query('SELECT * FROM students WHERE member_id = $1', [member_id]);
  if (!studentRows.length) return res.status(404).json({ error: 'No student found for that Member ID' });
  const phone = studentRows[0].parent_phone;

  const otpRows = await query(
    `SELECT * FROM parent_otps WHERE phone = $1 AND otp_code = $2 AND used = false AND expires_at > now()
     ORDER BY created_at DESC LIMIT 1`,
    [phone, otp]
  );
  if (!otpRows.length) return res.status(401).json({ error: 'Invalid or expired OTP' });

  await query('UPDATE parent_otps SET used = true WHERE id = $1', [otpRows[0].id]);

  req.session.parentPhone = phone;
  req.session.parentMemberId = member_id;
  res.json({ ok: true });
});

app.post('/api/parent/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

function requireParent(req, res, next) {
  if (req.session && req.session.parentPhone) return next();
  return res.status(401).json({ error: 'Not logged in' });
}

// The logged-in parent's own data — parent.html calls this on load
app.get('/api/parent/me', requireParent, async (req, res) => {
  const result = await getParentData(req.session.parentPhone);
  res.json(result);
});

async function getParentData(phone) {
  const students = await query('SELECT * FROM students WHERE parent_phone = $1', [phone]);
  const out = [];
  for (const student of students) {
    const routeRows = student.route_id ? await query('SELECT * FROM routes WHERE id = $1', [student.route_id]) : [];
    const route = routeRows[0] || null;
    const stopRows = student.stop_id ? await query('SELECT * FROM stops WHERE id = $1', [student.stop_id]) : [];
    const stop = stopRows[0] || null;
    const busRows = route && route.bus_id ? await query('SELECT * FROM buses WHERE id = $1', [route.bus_id]) : [];
    const bus = busRows[0] || null;
    const tripRows = route
      ? await query(`SELECT * FROM trips WHERE route_id = $1 AND status = 'active' LIMIT 1`, [route.id])
      : [];
    out.push({ student, route, stop, bus, activeTrip: tripRows[0] || null });
  }
  return out;
}

// ============================================================
// READ endpoints
// ============================================================

app.get('/api/school', async (req, res) => {
  const rows = await query('SELECT * FROM school LIMIT 1');
  res.json(rows[0] || null);
});

app.get('/api/buses', async (req, res) => {
  res.json(await query('SELECT * FROM buses ORDER BY id'));
});

app.get('/api/routes', async (req, res) => {
  const routes = await query('SELECT * FROM routes ORDER BY id');
  const buses = await query('SELECT * FROM buses');
  const stops = await query('SELECT * FROM stops ORDER BY sequence');
  const withDetails = routes.map(r => ({
    ...r,
    bus: buses.find(b => b.id === r.bus_id) || null,
    stops: stops.filter(s => s.route_id === r.id)
  }));
  res.json(withDetails);
});

app.get('/api/students', async (req, res) => {
  res.json(await query('SELECT * FROM students ORDER BY id'));
});

app.get('/api/trips/active', async (req, res) => {
  res.json(await query(`SELECT * FROM trips WHERE status = 'active' ORDER BY id`));
});

// ============================================================
// ADMIN write endpoints — session-protected
// ============================================================

app.post('/api/buses', requireAdmin, async (req, res) => {
  const { bus_no, registration_no, capacity, driver_name, driver_phone } = req.body;
  const rows = await query(
    `INSERT INTO buses (bus_no, registration_no, capacity, driver_name, driver_phone)
     VALUES ($1,$2,$3,$4,$5) RETURNING *`,
    [bus_no, registration_no, capacity, driver_name, driver_phone]
  );
  res.status(201).json(rows[0]);
});

app.post('/api/routes', requireAdmin, async (req, res) => {
  const { route_name, bus_id } = req.body;
  const rows = await query(
    'INSERT INTO routes (route_name, bus_id) VALUES ($1,$2) RETURNING *',
    [route_name, bus_id]
  );
  res.status(201).json(rows[0]);
});

app.post('/api/stops', requireAdmin, async (req, res) => {
  const { route_id, stop_name, lat, lng, sequence, pickup_time } = req.body;
  const rows = await query(
    `INSERT INTO stops (route_id, stop_name, lat, lng, sequence, pickup_time)
     VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
    [route_id, stop_name, lat, lng, sequence, pickup_time]
  );
  res.status(201).json(rows[0]);
});

app.post('/api/students', requireAdmin, async (req, res) => {
  const { member_id, name, class: cls, section, parent_phone, route_id, stop_id } = req.body;
  const rows = await query(
    `INSERT INTO students (member_id, name, class, section, parent_phone, route_id, stop_id)
     VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [member_id, name, cls, section, parent_phone, route_id, stop_id]
  );
  res.status(201).json(rows[0]);
});

// ============================================================
// Trip lifecycle — driver PIN protected
// ============================================================

function requireDriverPin(req, res, next) {
  if (req.body.driver_pin === DRIVER_PIN) return next();
  return res.status(401).json({ error: 'Incorrect driver PIN' });
}

app.post('/api/trips/start', requireDriverPin, async (req, res) => {
  const { route_id } = req.body;
  const routeRows = await query('SELECT * FROM routes WHERE id = $1', [route_id]);
  const route = routeRows[0];
  if (!route) return res.status(404).json({ error: 'Route not found' });

  const rows = await query(
    `INSERT INTO trips (route_id, bus_id, status) VALUES ($1,$2,'active') RETURNING *`,
    [route_id, route.bus_id]
  );
  const trip = rows[0];
  io.emit('trip-started', trip);
  res.status(201).json(trip);
});

app.post('/api/trips/:id/end', async (req, res) => {
  const rows = await query(
    `UPDATE trips SET status = 'completed', end_time = now() WHERE id = $1 RETURNING *`,
    [req.params.id]
  );
  if (!rows.length) return res.status(404).json({ error: 'Trip not found' });
  io.emit('trip-ended', rows[0]);
  res.json(rows[0]);
});

// Driver app POSTs here (works even if the driver's socket connection drops);
// the server both stores it and re-broadcasts over Socket.IO.
app.post('/api/trips/:id/location', async (req, res) => {
  const tripId = Number(req.params.id);
  const { lat, lng, speed } = req.body;

  const tripRows = await query('SELECT * FROM trips WHERE id = $1', [tripId]);
  if (!tripRows.length) return res.status(404).json({ error: 'Trip not found' });

  const rows = await query(
    `INSERT INTO locations (trip_id, lat, lng, speed) VALUES ($1,$2,$3,$4)
     RETURNING trip_id, lat, lng, speed, recorded_at AS timestamp`,
    [tripId, lat, lng, speed || null]
  );
  const point = rows[0];
  io.to(`trip-${tripId}`).emit('location-update', point);
  res.status(201).json(point);
});

// ---------- Socket.IO: parents subscribe to a trip's room ----------
io.on('connection', (socket) => {
  socket.on('subscribe-trip', (tripId) => {
    socket.join(`trip-${tripId}`);
  });
});
// Routing for separate views
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/driver', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'driver.html'));
});

app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/parent', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'parent.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`SSGIS Bus Tracker running at http://localhost:${PORT}`);
});

