/**
 * ArthSathi / SmartBudget PRO - Backend
 * Node.js + Express, JWT auth, JSON-file persistence (no native deps).
 *
 * Run:  npm install && npm start
 * Env:  PORT, JWT_SECRET, ADMIN_USER, ADMIN_PASS, DATA_FILE
 */
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'admin123';
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');

const CATEGORIES = ['Food', 'Travel', 'Bills', 'Shopping', 'Health', 'Entertainment', 'Rent', 'Subscriptions', 'Other'];
const XP_PER_LEVEL = 200;
const DEFAULT_BUDGET = 10000;
const DAILY_CATEGORY_LIMIT = 3000;

/* ───────────── Storage (JSON file, atomic writes) ───────────── */
let db = { users: {} };
function loadDB() {
  try {
    if (fs.existsSync(DATA_FILE)) db = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    if (!db.users) db.users = {};
  } catch (e) {
    console.error('Failed to load DB, starting fresh:', e.message);
  }
}
let saveTimer = null;
function saveDB() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const tmp = DATA_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
    fs.renameSync(tmp, DATA_FILE);
  }, 50);
}
loadDB();

/* ───────────── Helpers ───────────── */
const today = () => new Date().toISOString().split('T')[0];
const daysAgo = (d) => { const t = new Date(); t.setDate(t.getDate() - d); return t.toISOString().split('T')[0]; };
const randId = () => crypto.randomBytes(4).toString('hex');
const sum = (arr) => arr.reduce((s, e) => s + e.amount, 0);
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

function publicUser(u, id) {
  return {
    id, name: u.displayName || id, xp: u.xp, level: u.level, streak: u.streak,
    badges: u.badges, budget: u.budget, income: u.income, currency: u.currency,
    createdAt: u.createdAt, lastActive: u.lastActive,
  };
}

function parseSMS(txt) {
  const m = txt.match(/(?:₹|rs\.?|inr)\s?(\d+(?:,\d+)*(?:\.\d{1,2})?)/i);
  const amount = m ? parseFloat(m[1].replace(/,/g, '')) : null;
  const low = txt.toLowerCase();
  let category = 'Other';
  if (/swiggy|zomato|food|restaurant|cafe|pizza|burger/.test(low)) category = 'Food';
  else if (/uber|ola|flight|travel|train|metro|bus/.test(low)) category = 'Travel';
  else if (/netflix|spotify|prime|subscription/.test(low)) category = 'Subscriptions';
  else if (/electricity|bill|water|gas|recharge/.test(low)) category = 'Bills';
  else if (/amazon|flipkart|myntra|shop/.test(low)) category = 'Shopping';
  else if (/hospital|pharmacy|medicine|health|doctor/.test(low)) category = 'Health';
  return { amount, category };
}

function detectPersonality(expenses) {
  if (!expenses.length) return { type: 'New User', icon: '🌱', tip: 'Start tracking to get insights!' };
  const avg = sum(expenses) / expenses.length;
  const impulsive = ['Shopping', 'Entertainment', 'Food'];
  const ratio = expenses.filter((e) => impulsive.includes(e.category)).length / expenses.length;
  if (ratio > 0.6) return { type: 'Impulsive Spender', icon: '🔥', tip: 'Try the 48-hour rule before impulse buys!' };
  if (avg < 500) return { type: 'Smart Saver', icon: '🧠', tip: 'Amazing! Keep building your savings streak.' };
  return { type: 'Balanced Planner', icon: '⚖️', tip: "You're doing well. Small optimizations can help!" };
}

function updateStreak(u) {
  const t = today();
  if (u.lastActive === t) return;
  u.streak = u.lastActive === daysAgo(1) ? (u.streak || 0) + 1 : 1;
  u.lastActive = t;
}

function evaluateBadges(u) {
  const add = (id) => { if (!u.badges.includes(id)) u.badges.push(id); };
  if (u.expenses.length >= 20) add('king');
  if ((u.streak || 0) >= 7) add('streak');
  if ((u.analyticsViews || 0) >= 5) add('analyst');
  if (u.groups.length >= 1) add('social');
  // Smart Saver: stayed under budget for the last 7 days (needs 7 days of history)
  const monthTotal = sum(u.expenses.filter((e) => e.date >= daysAgo(30)));
  if (u.expenses.length && monthTotal <= u.budget && (u.streak || 0) >= 7) add('saver');
}

function grantXP(u, amount) {
  u.xp = (u.xp || 0) + amount;
  u.level = Math.floor(u.xp / XP_PER_LEVEL) + 1;
}

/* ───────────── App + auth middleware ───────────── */
const app = express();
app.use(cors());
app.use(express.json({ limit: '2mb' }));

function sign(payload) { return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' }); }

function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.auth = jwt.verify(token, JWT_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  next();
}
function userOnly(req, res, next) {
  if (req.auth.role !== 'user') return res.status(403).json({ error: 'User access only' });
  const u = db.users[req.auth.id];
  if (!u) return res.status(404).json({ error: 'User not found' });
  req.u = u;
  next();
}
function adminOnly(req, res, next) {
  if (req.auth.role !== 'admin') return res.status(403).json({ error: 'Admin access only' });
  next();
}

/* ───────────── Health ───────────── */
app.get('/api/health', (req, res) => res.json({ ok: true, time: new Date().toISOString() }));

/* ───────────── Auth ───────────── */
app.post('/api/auth/signup', wrap(async (req, res) => {
  const { username, password, displayName } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Fill all fields' });
  if (!/^[a-zA-Z0-9_.-]{3,30}$/.test(username)) return res.status(400).json({ error: 'Username must be 3-30 chars (letters, numbers, _ . -)' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (username.toLowerCase() === ADMIN_USER.toLowerCase()) return res.status(400).json({ error: 'Username reserved' });
  if (db.users[username]) return res.status(409).json({ error: 'Username taken' });

  db.users[username] = {
    passwordHash: await bcrypt.hash(password, 10),
    displayName: displayName || username,
    createdAt: new Date().toISOString(),
    expenses: [], groups: [], xp: 0, level: 1, streak: 0,
    lastActive: null, badges: [], budget: DEFAULT_BUDGET, income: 50000,
    currency: '₹', analyticsViews: 0,
  };
  saveDB();
  res.status(201).json({ message: 'Account created! Please login.' });
}));

app.post('/api/auth/login', wrap(async (req, res) => {
  const { username, password, as } = req.body || {};
  if (as === 'admin') {
    if (username === ADMIN_USER && password === ADMIN_PASS) {
      return res.json({ token: sign({ id: 'admin', role: 'admin' }), user: { id: 'admin', name: 'Admin', role: 'admin' } });
    }
    return res.status(401).json({ error: 'Invalid admin credentials' });
  }
  const u = db.users[username];
  if (!u) return res.status(404).json({ error: 'User not found. Sign up first.' });
  if (!(await bcrypt.compare(password || '', u.passwordHash))) return res.status(401).json({ error: 'Wrong password' });
  res.json({ token: sign({ id: username, role: 'user' }), user: { ...publicUser(u, username), role: 'user' } });
}));

app.get('/api/me', auth, userOnly, (req, res) => {
  res.json({ ...publicUser(req.u, req.auth.id), personality: detectPersonality(req.u.expenses) });
});

app.patch('/api/me', auth, userOnly, (req, res) => {
  const { displayName, budget, income, currency } = req.body || {};
  if (displayName) req.u.displayName = String(displayName).slice(0, 40);
  if (budget !== undefined) {
    if (!(Number(budget) > 0)) return res.status(400).json({ error: 'Invalid budget' });
    req.u.budget = Number(budget);
  }
  if (income !== undefined) {
    if (!(Number(income) >= 0)) return res.status(400).json({ error: 'Invalid income' });
    req.u.income = Number(income);
  }
  if (currency && ['₹', '$'].includes(currency)) req.u.currency = currency;
  saveDB();
  res.json(publicUser(req.u, req.auth.id));
});

app.post('/api/me/password', auth, userOnly, wrap(async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!(await bcrypt.compare(oldPassword || '', req.u.passwordHash))) return res.status(401).json({ error: 'Wrong password' });
  if (!newPassword || newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  req.u.passwordHash = await bcrypt.hash(newPassword, 10);
  saveDB();
  res.json({ message: 'Password updated' });
}));

/* ───────────── Expenses ───────────── */
app.get('/api/expenses', auth, userOnly, (req, res) => {
  const { category, q, range, from, to } = req.query;
  let list = req.u.expenses.slice();
  if (category && category !== 'All') list = list.filter((e) => e.category === category);
  if (q) {
    const s = String(q).toLowerCase();
    list = list.filter((e) => e.category.toLowerCase().includes(s) || (e.note || '').toLowerCase().includes(s));
  }
  if (range === 'today') list = list.filter((e) => e.date === today());
  else if (range === 'week') list = list.filter((e) => e.date >= daysAgo(7));
  else if (range === 'month') list = list.filter((e) => e.date >= daysAgo(30));
  if (from) list = list.filter((e) => e.date >= from);
  if (to) list = list.filter((e) => e.date <= to);
  list.sort((a, b) => b.ts - a.ts);
  res.json({ count: list.length, total: sum(list), expenses: list });
});

app.post('/api/expenses', auth, userOnly, (req, res) => {
  const u = req.u;
  const amount = Number(req.body.amount);
  const category = CATEGORIES.includes(req.body.category) ? req.body.category : 'Other';
  if (!(amount > 0)) return res.status(400).json({ error: 'Amount must be a positive number' });

  const date = /^\d{4}-\d{2}-\d{2}$/.test(req.body.date || '') ? req.body.date : today();
  const warnings = [];
  const todayCat = sum(u.expenses.filter((e) => e.date === date && e.category === category));
  if (todayCat + amount > DAILY_CATEGORY_LIMIT) warnings.push(`You're exceeding today's ${category} limit!`);

  const exp = { id: randId(), amount, category, note: String(req.body.note || '').slice(0, 200), date, ts: Date.now() };
  u.expenses.push(exp);
  updateStreak(u);
  grantXP(u, 10);
  evaluateBadges(u);

  const total = sum(u.expenses);
  if (total > u.budget) warnings.push('Budget exceeded! Time to pause spending.');
  else if (total > u.budget * 0.8) warnings.push('At 80% of budget. Slow down!');
  else if (total > u.budget * 0.5) warnings.push('Halfway through budget.');

  saveDB();
  res.status(201).json({ expense: exp, warnings, xp: u.xp, level: u.level, badges: u.badges, streak: u.streak, total });
});

app.put('/api/expenses/:id', auth, userOnly, (req, res) => {
  const e = req.u.expenses.find((x) => x.id === req.params.id);
  if (!e) return res.status(404).json({ error: 'Expense not found' });
  if (req.body.amount !== undefined) {
    if (!(Number(req.body.amount) > 0)) return res.status(400).json({ error: 'Invalid amount' });
    e.amount = Number(req.body.amount);
  }
  if (req.body.category && CATEGORIES.includes(req.body.category)) e.category = req.body.category;
  if (req.body.note !== undefined) e.note = String(req.body.note).slice(0, 200);
  if (/^\d{4}-\d{2}-\d{2}$/.test(req.body.date || '')) e.date = req.body.date;
  saveDB();
  res.json(e);
});

app.delete('/api/expenses/:id', auth, userOnly, (req, res) => {
  const before = req.u.expenses.length;
  req.u.expenses = req.u.expenses.filter((e) => e.id !== req.params.id);
  if (req.u.expenses.length === before) return res.status(404).json({ error: 'Expense not found' });
  saveDB();
  res.json({ message: 'Deleted' });
});

/* ───────────── Smart input: SMS / receipt ───────────── */
app.post('/api/parse-sms', auth, userOnly, (req, res) => {
  const { text } = req.body || {};
  if (!text) return res.status(400).json({ error: 'text is required' });
  const parsed = parseSMS(String(text));
  if (!parsed.amount) return res.status(422).json({ error: 'Could not parse amount from SMS' });
  res.json(parsed);
});

// Mock receipt scan (placeholder - plug in an OCR / vision API here)
app.post('/api/scan-receipt', auth, userOnly, (req, res) => {
  const amts = [450, 1200, 89, 350, 2500, 670];
  const cats = ['Food', 'Shopping', 'Health', 'Entertainment', 'Bills', 'Travel'];
  const i = Math.floor(Math.random() * amts.length);
  res.json({ amount: amts[i], category: cats[i], mock: true });
});

/* ───────────── Dashboard / Analytics ───────────── */
app.get('/api/dashboard', auth, userOnly, (req, res) => {
  const u = req.u;
  const total = sum(u.expenses);
  const byCat = {};
  u.expenses.forEach((e) => (byCat[e.category] = (byCat[e.category] || 0) + e.amount));
  res.json({
    total,
    budget: u.budget,
    budgetUsedPct: Math.min((total / u.budget) * 100, 100),
    todayTotal: sum(u.expenses.filter((e) => e.date === today())),
    byCategory: byCat,
    personality: detectPersonality(u.expenses),
    xp: u.xp, level: u.level, streak: u.streak,
    xpIntoLevel: u.xp % XP_PER_LEVEL, xpPerLevel: XP_PER_LEVEL,
  });
});

app.get('/api/analytics', auth, userOnly, (req, res) => {
  const u = req.u;
  u.analyticsViews = (u.analyticsViews || 0) + 1;
  evaluateBadges(u);
  saveDB();

  const total = sum(u.expenses);
  const names = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  const weekly = Array.from({ length: 7 }, (_, i) => {
    const d = daysAgo(6 - i);
    return { date: d, day: names[new Date(d).getUTCDay()], total: sum(u.expenses.filter((e) => e.date === d)) };
  });
  const byCategory = {};
  u.expenses.forEach((e) => (byCategory[e.category] = (byCategory[e.category] || 0) + e.amount));
  const categories = Object.entries(byCategory)
    .sort((a, b) => b[1] - a[1])
    .map(([category, amount]) => ({ category, amount, pct: total ? +((amount / total) * 100).toFixed(1) : 0 }));
  const activeDays = new Set(u.expenses.map((e) => e.date)).size;

  const subs = u.expenses.filter((e) => e.category === 'Subscriptions');
  const subscriptions = Object.values(subs.reduce((acc, e) => {
    const k = (e.note || 'Subscription').toLowerCase();
    if (!acc[k] || acc[k].date < e.date) acc[k] = { name: e.note || 'Subscription', amount: e.amount, date: e.date };
    return acc;
  }, {}));

  res.json({
    total, transactions: u.expenses.length,
    avgPerDay: total / Math.max(1, activeDays),
    topCategory: categories[0]?.category || null,
    weekly, categories, subscriptions,
    badges: u.badges,
  });
});

/* ───────────── FutureFlow ───────────── */
function avgDailySpend(expenses) {
  if (!expenses.length) return 500;
  return sum(expenses) / Math.max(1, new Set(expenses.map((e) => e.date)).size);
}

app.post('/api/futureflow/forecast', auth, userOnly, (req, res) => {
  const u = req.u;
  const days = [30, 60, 90].includes(Number(req.body.days)) ? Number(req.body.days) : 30;
  const income = req.body.income !== undefined ? Number(req.body.income) : u.income;
  const avgDaily = avgDailySpend(u.expenses);
  const balance = income - sum(u.expenses.filter((e) => e.date >= daysAgo(30)));
  let bal = balance;
  const points = [];
  for (let i = 1; i <= days; i++) { bal -= avgDaily; points.push({ day: i, balance: Math.round(bal) }); }
  const idx = points.findIndex((p) => p.balance < 0);
  res.json({
    currentBalance: Math.round(balance), avgDaily: Math.round(avgDaily), days, points,
    finalBalance: points[points.length - 1].balance,
    runOutInDays: idx >= 0 ? idx + 1 : null,
    healthy: idx < 0,
  });
});

app.post('/api/futureflow/goal', auth, userOnly, (req, res) => {
  const goal = Number(req.body.goalAmount), save = Number(req.body.monthlySavings);
  if (!(goal > 0) || !(save > 0)) return res.status(400).json({ error: 'goalAmount and monthlySavings must be positive' });
  const months = Math.ceil(goal / save);
  const tip = months > 24 ? 'Consider increasing savings or finding additional income sources.'
    : months > 12 ? "You're on track! Small daily savings can accelerate this."
    : 'Great pace! You\'ll hit your goal soon.';
  res.json({ months, pct: Math.min((save / goal) * 100, 100), tip });
});

app.post('/api/futureflow/scenario', auth, userOnly, (req, res) => {
  const u = req.u;
  const salaryChg = Number(req.body.salaryChange) || 0;
  const rentChg = Number(req.body.rentChange) || 0;
  const expChg = Number(req.body.expenseChange) || 0;
  const baseRent = Number(req.body.baseRent) || 5000;
  const newIncome = u.income * (1 + salaryChg / 100);
  const newRent = baseRent * (1 + rentChg / 100);
  const newExpenses = avgDailySpend(u.expenses) * 30 * (1 + expChg / 100);
  const newBalance = newIncome - newRent - newExpenses;
  const risk = newBalance < 5000 ? 'danger' : newBalance < 15000 ? 'warn' : 'safe';
  res.json({ newIncome: Math.round(newIncome), newBalance: Math.round(newBalance), risk });
});

/* ───────────── Gamification ───────────── */
app.post('/api/streak/checkin', auth, userOnly, (req, res) => {
  const u = req.u;
  if (u.lastActive === today()) return res.json({ message: 'Already checked in today', streak: u.streak });
  updateStreak(u);
  grantXP(u, 5);
  evaluateBadges(u);
  saveDB();
  res.json({ message: 'Streak extended!', streak: u.streak, badges: u.badges, xp: u.xp, level: u.level });
});

/* ───────────── Groups / bill splitting ───────────── */
function calcSplits(g) {
  const perHead = sum(g.expenses) / g.members.length;
  const paid = Object.fromEntries(g.members.map((m) => [m, 0]));
  g.expenses.forEach((e) => (paid[e.payer] = (paid[e.payer] || 0) + e.amount));
  const balances = g.members.map((m) => ({ name: m, paid: paid[m] || 0, balance: +((paid[m] || 0) - perHead).toFixed(2) }));

  // Minimal settlement suggestions (greedy)
  const debtors = balances.filter((b) => b.balance < -0.01).map((b) => ({ ...b })).sort((a, b) => a.balance - b.balance);
  const creditors = balances.filter((b) => b.balance > 0.01).map((b) => ({ ...b })).sort((a, b) => b.balance - a.balance);
  const settlements = [];
  let i = 0, j = 0;
  while (i < debtors.length && j < creditors.length) {
    const amt = Math.min(-debtors[i].balance, creditors[j].balance);
    settlements.push({ from: debtors[i].name, to: creditors[j].name, amount: +amt.toFixed(2) });
    debtors[i].balance += amt; creditors[j].balance -= amt;
    if (Math.abs(debtors[i].balance) < 0.01) i++;
    if (Math.abs(creditors[j].balance) < 0.01) j++;
  }
  return { perHead: +perHead.toFixed(2), balances, settlements };
}

app.get('/api/groups', auth, userOnly, (req, res) => {
  res.json(req.u.groups.map((g) => ({ ...g, total: sum(g.expenses), ...calcSplits(g) })));
});

app.post('/api/groups', auth, userOnly, (req, res) => {
  const { name } = req.body || {};
  let members = req.body.members;
  if (typeof members === 'string') members = members.split(',');
  members = [...new Set((members || []).map((m) => String(m).trim()).filter(Boolean))];
  if (!name || members.length < 2) return res.status(400).json({ error: 'Group name and at least 2 members are required' });
  const g = { id: randId(), name: String(name).slice(0, 50), members, expenses: [], createdAt: new Date().toISOString() };
  req.u.groups.push(g);
  evaluateBadges(req.u);
  saveDB();
  res.status(201).json(g);
});

app.post('/api/groups/:id/expenses', auth, userOnly, (req, res) => {
  const g = req.u.groups.find((x) => x.id === req.params.id);
  if (!g) return res.status(404).json({ error: 'Group not found' });
  const amount = Number(req.body.amount), payer = req.body.payer;
  if (!(amount > 0) || !payer) return res.status(400).json({ error: 'amount and payer are required' });
  if (!g.members.includes(payer)) return res.status(400).json({ error: 'Payer must be a group member' });
  g.expenses.push({ id: randId(), amount, desc: String(req.body.desc || '').slice(0, 100), payer, date: today() });
  saveDB();
  res.status(201).json({ ...g, total: sum(g.expenses), ...calcSplits(g) });
});

app.delete('/api/groups/:id', auth, userOnly, (req, res) => {
  const before = req.u.groups.length;
  req.u.groups = req.u.groups.filter((g) => g.id !== req.params.id);
  if (req.u.groups.length === before) return res.status(404).json({ error: 'Group not found' });
  saveDB();
  res.json({ message: 'Group deleted' });
});

/* ───────────── Export (CSV) ───────────── */
app.get('/api/export/csv', auth, userOnly, (req, res) => {
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const rows = ['Date,Category,Amount,Note', ...req.u.expenses.map((e) => [e.date, e.category, e.amount, esc(e.note)].join(','))];
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="SmartBudget_Report.csv"');
  res.send(rows.join('\n'));
});

/* ───────────── Sync (bulk import of existing localStorage data) ───────────── */
app.post('/api/import', auth, userOnly, (req, res) => {
  const { expenses, groups } = req.body || {};
  let added = 0;
  if (Array.isArray(expenses)) {
    const ids = new Set(req.u.expenses.map((e) => e.id));
    for (const e of expenses) {
      if (!(Number(e.amount) > 0)) continue;
      const id = e.id && !ids.has(e.id) ? e.id : randId();
      req.u.expenses.push({
        id, amount: Number(e.amount),
        category: CATEGORIES.includes(e.category) ? e.category : 'Other',
        note: String(e.note || '').slice(0, 200),
        date: /^\d{4}-\d{2}-\d{2}$/.test(e.date || '') ? e.date : today(),
        ts: e.ts || Date.now(),
      });
      ids.add(id); added++;
    }
  }
  if (Array.isArray(groups)) {
    const gids = new Set(req.u.groups.map((g) => g.id));
    groups.forEach((g) => { if (g.id && !gids.has(g.id) && g.name && Array.isArray(g.members)) req.u.groups.push(g); });
  }
  evaluateBadges(req.u);
  saveDB();
  res.json({ imported: added });
});

/* ───────────── Admin ───────────── */
app.get('/api/admin/stats', auth, adminOnly, (req, res) => {
  const all = Object.entries(db.users).flatMap(([uid, u]) => u.expenses.map((e) => ({ ...e, userId: uid })));
  const totalSpend = sum(all);
  const categoryBreakdown = {};
  all.forEach((e) => (categoryBreakdown[e.category] = (categoryBreakdown[e.category] || 0) + e.amount));
  const userCount = Object.keys(db.users).length;
  res.json({
    totalUsers: userCount, totalTransactions: all.length, platformSpend: totalSpend,
    avgPerUser: userCount ? Math.round(totalSpend / userCount) : 0, categoryBreakdown,
  });
});

app.get('/api/admin/users', auth, adminOnly, (req, res) => {
  res.json(Object.entries(db.users).map(([id, u]) => ({
    ...publicUser(u, id), expenseCount: u.expenses.length, groupCount: u.groups.length, totalSpent: sum(u.expenses),
  })));
});

app.get('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  const u = db.users[req.params.id];
  if (!u) return res.status(404).json({ error: 'User not found' });
  res.json({ ...publicUser(u, req.params.id), recentExpenses: u.expenses.slice(-5).reverse() });
});

app.delete('/api/admin/users/:id', auth, adminOnly, (req, res) => {
  if (!db.users[req.params.id]) return res.status(404).json({ error: 'User not found' });
  delete db.users[req.params.id];
  saveDB();
  res.json({ message: 'User deleted' });
});

app.post('/api/admin/users/:id/reset-password', auth, adminOnly, wrap(async (req, res) => {
  const u = db.users[req.params.id];
  if (!u) return res.status(404).json({ error: 'User not found' });
  const pw = req.body.newPassword;
  if (!pw || pw.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  u.passwordHash = await bcrypt.hash(pw, 10);
  saveDB();
  res.json({ message: 'Password reset' });
}));

/* ───────────── Static frontend (optional) ─────────────
 * Put your HTML (renamed index.html) in a ./public folder and it will be served at "/".
 */
const PUBLIC_DIR = path.join(__dirname, 'public');
if (fs.existsSync(PUBLIC_DIR)) app.use(express.static(PUBLIC_DIR));

/* ───────────── Errors ───────────── */
app.use('/api', (req, res) => res.status(404).json({ error: 'Not found' }));
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

process.on('SIGINT', () => { clearTimeout(saveTimer); fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2)); process.exit(0); });

app.listen(PORT, () => {
  console.log(`ArthSathi backend running on http://localhost:${PORT}`);
  if (JWT_SECRET === 'change-this-secret-in-production') console.warn('⚠️  Set JWT_SECRET (and ADMIN_PASS) before deploying.');
});