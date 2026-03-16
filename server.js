require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const axios = require('axios');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const session = require('express-session');
const FileStore = require('session-file-store')(session);
const bcrypt = require('bcryptjs');

// --- SECURITY PACKAGES ---
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

//const { v4: uuidv4 } = require('uuid');
let uuidv4;

try {
    uuidv4 = require('uuid').v4;
} catch (err) {
    uuidv4 = require('crypto').randomUUID;
}

const app = express();

const {
  ATLANTIC_BASE = 'https://atlantich2h.com',
  ATLANTIC_KEY,
  ATLANTIC_PROFIT = 0,
  FEE_BY_CUSTOMER = true,
  SALDO_DISPLAY_NAME = 'Saldo Akun',
  SMTP_HOST,
  SMTP_PORT,
  SMTP_SECURE,
  SMTP_USER,
  SMTP_PASS,
  ADMIN_PASS = 'admin123',
  BANK_CODE = 'DANA',
  ACCOUNT_NUMBER,
  SERVER_HOST = 'localhost',
  SERVER_PORT = 3000,
  SESSION_SECRET = 'rahasia_super_aman_inovixa_jgn_disebar',
  NODE_ENV = 'development'
} = process.env;

if (!ATLANTIC_KEY || !SMTP_HOST || !SMTP_PORT || !SMTP_USER || !SMTP_PASS) {
  console.warn('WARNING: SMTP configuration incomplete. Set ATLANTIC_KEY, SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS in .env');
}

const PROFIT_PERCENT = ATLANTIC_PROFIT;

app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false,
}));

app.set('trust proxy', 1);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(bodyParser.json());

app.use(session({
  store: new FileStore({
    path: './sessions',
    ttl: 86400 * 7,
    retries: 0
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24 * 7,
    httpOnly: true,
    secure: NODE_ENV === 'production',
    sameSite: 'lax'
  }
}));

const csrfMiddleware = (req, res, next) => {
  // Generate token jika belum ada di session
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  
  // Ekspos token ke View (EJS)
  res.locals.csrfToken = req.session.csrfToken;
  res.locals.user = req.session.user || null; // Sekalian user locals

  // Validasi Token untuk method POST/PUT/DELETE
  if (['POST', 'PUT', 'DELETE'].includes(req.method)) {
    const clientToken = req.body._csrf || req.headers['x-csrf-token'];
    
    if (!clientToken || clientToken !== req.session.csrfToken) {
      console.error(`[CSRF ERROR] IP: ${req.ip} - Invalid Token`);
      return res.status(403).json({ 
        ok: false, 
        message: 'Security Token Invalid (CSRF). Silakan refresh halaman.' 
      });
    }
  }
  next();
};

//app.use(csrfMiddleware);

// --- CSRF FUNCTIONS ---

// 1. GENERATOR: Pasang di route halaman (GET) yang me-render provider.ejs
const csrfGenerator = (req, res, next) => {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  // Kirim ke EJS via locals
  res.locals.csrfToken = req.session.csrfToken;
  next();
};

// 2. VALIDATOR: Pasang di route API (POST) yang dipanggil oleh provider.ejs
const csrfValidator = (req, res, next) => {
  const clientToken = req.headers['x-csrf-token'] || req.body._csrf;
  const sessionToken = req.session.csrfToken;

  if (!clientToken || !sessionToken || clientToken !== sessionToken) {
    console.error(`[CSRF BLOCKED] IP: ${req.ip} - URL: ${req.originalUrl}`);
    return res.status(403).json({ 
      ok: false, 
      message: 'Sesi kadaluarsa atau token tidak valid. Silakan refresh halaman.' 
    });
  }
  next();
};

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 menit
  max: 100, // Maksimal 100 request per IP per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, message: "Terlalu banyak permintaan, coba lagi nanti." }
});

app.use('/api/', apiLimiter);
app.use('/auth/', apiLimiter);

// Middleware untuk inject user ke view
app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

// --- USER DATA HELPERS ---
const USERS_FILE = path.join(__dirname, 'data', 'users.json');

function readUsers() {
  if (!fs.existsSync(USERS_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
  } catch (e) { return []; }
}

function writeUsers(data) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(data, null, 2));
}

function findUserByEmail(email) {
  const users = readUsers();
  return users.find(u => u.email === email);
}

function normalizeAddr(addr = '') {
  return String(addr).trim().toLowerCase().replace(/^::ffff:/, '');
}

const smtpPortNum = parseInt(SMTP_PORT, 10);
const smtpSecureBool = String(SMTP_SECURE || '').toLowerCase() === 'true';

// Transporter generik
const transporter = nodemailer.createTransport({
  host: SMTP_HOST,
  port: smtpPortNum || 465,
  secure: smtpSecureBool, // true utk 465, false utk 587
  auth: { user: SMTP_USER, pass: SMTP_PASS }
});

// Verify di startup
transporter.verify()
  .then(() => console.log('SMTP transporter siap.'))
  .catch(err => console.error('SMTP verify gagal:', err.message));

// Helper escape HTML
function escapeHtml(str) {
  if (typeof str !== 'string') return str;
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Validasi email sederhana
function isEmail(s) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(s || ''));
}

const tmpDir = path.join(__dirname, 'tmp');
if (!fs.existsSync(tmpDir)) {
  fs.mkdirSync(tmpDir, {
    recursive: true
  });
}

const CONFIG_PATH = path.join(__dirname, 'config.json');

  // Load config (best-effort). If invalid / missing, continue with empty config.
  let CONFIG = {};
  try {
    const raw = fs.readFileSync(CONFIG_PATH, 'utf8');
    CONFIG = JSON.parse(raw) || {};
  } catch (e) {
    CONFIG = {};
  }
  
const ORDERS_FILE = path.join(tmpDir, 'orders.json');

function generateRef(len = 12) {
  return crypto.randomBytes(Math.ceil(len / 2)).toString('hex').slice(0, len).toUpperCase();
}

function slugify(s) {
  if (s == null) return '';
  return String(s)
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-');
}

function endsWithTopup(v) {
  if (v == null) return false;
  return /\btopup\s*$/i.test(String(v).trim());
}

// ----------------------- helper & existing functions (full) -----------------------
function sanitizeProductName(rawName, providerName) {
  if (rawName == null) return '';
  let name = String(rawName).trim();
  if (name.length === 0) return '';

  // removal khusus manual
  const manualRemovals = [
    'MOBILELEGENDS - ',
    'MOBILELEGEND - ',
    'MOBILELEGENDS-',
    'MOBILELEGEND-',
    
    'Free Fire ',
    
    'Honor of Kings '
  ];
  const lowerOrig = name.toLowerCase();
  for (const prefix of manualRemovals) {
    if (lowerOrig.startsWith(prefix.toLowerCase())) {
      name = name.slice(prefix.length).trim();
      break;
    }
  }

  // hapus nama provider kalau ada di depan
  if (providerName) {
    const prov = providerName.toLowerCase().trim();
    // bikin regex agar fleksibel (misal "free fire", "FreeFire", "FREE-FIRE")
    const provRegex = new RegExp('^' + prov.replace(/\s+/g, '\\s*') + '\\s*', 'i');
    name = name.replace(provRegex, '').trim();
  }

  // cari separator paling kanan
  const separators = [' - ', '- ', ' -', '-'];
  let lastPos = -1;
  let sepLen = 0;
  for (const sep of separators) {
    const pos = name.lastIndexOf(sep);
    if (pos > lastPos) {
      if (sep.trim() === '-' && pos === 1) {
        continue;
      }
      lastPos = pos;
      sepLen = sep.length;
    }
  }
  if (lastPos >= 0) {
    const after = name.slice(lastPos + sepLen).trim();
    if (after.length > 0) {
      name = after;
    }
  }

  // normalisasi plural
  name = name.replace(/\bDiamond\b/gi, 'Diamonds');

  return name;
}

function extractItemPrice(item) {
  if (!item) return 0;
  const candidates = ['price', 'harga', 'amount', 'nominal', 'sell_price', 'sellPrice', 'value', 'selling_price'];
  for (const k of candidates) {
    if (typeof item[k] !== 'undefined' && item[k] !== null && item[k] !== '') {
      const n = Number(String(item[k]).replace(/[^0-9.-]+/g, ''));
      if (!Number.isNaN(n)) return n;
    }
  }
  return 0;
}

function readOrders() {
  try {
    if (!fs.existsSync(ORDERS_FILE)) return [];

    const raw = fs.readFileSync(ORDERS_FILE, 'utf8').trim();
    if (!raw) return [];

    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      console.error('orders.json parse error, resetting to empty array:', e.message);
      return [];
    }

    let arr = [];
    if (Array.isArray(parsed)) {
      arr = parsed;
    } else if (parsed && Array.isArray(parsed.orders)) {
      arr = parsed.orders;
    } else if (parsed && typeof parsed === 'object') {
      arr = Object.keys(parsed).map(k => parsed[k]);
    } else {
      arr = [];
    }

    arr = arr
      .filter(o => o && typeof o === 'object')
      .map(o => {
        const copy = Object.assign({}, o);
        if (typeof copy.id === 'undefined' || copy.id === null || copy.id === '') {
          copy.id = generateRef(12);
        } else {
          copy.id = String(copy.id);
        }
        return copy;
      });

    return arr;
  } catch (err) {
    console.error('Error reading orders file:', err);
    return [];
  }
}

function writeOrders(orders) {
  try {
    const arr = Array.isArray(orders) ? orders : [];
    fs.writeFileSync(ORDERS_FILE, JSON.stringify(arr, null, 2));
  } catch (err) {
    console.error('Error writing orders file:', err);
  }
}

/*async function fetchPriceList() {
  const _sanitize = sanitizeProductName;
  const profitPercent = PROFIT_PERCENT / 100;
  const priceKeys = ['price', 'harga', 'amount', 'nominal', 'sell_price', 'sellPrice', 'value', 'selling_price'];

  try {
    const url = `${ATLANTIC_BASE}/layanan/price_list`;
    const res = await axios.post(
      url,
      new URLSearchParams({
        api_key: ATLANTIC_KEY,
        type: 'prabayar'
      }).toString(), {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        },
        timeout: 15000
      }
    );

    const raw = (res.data && res.data.data) ? res.data.data : [];

    const availableOnly = raw.filter(item => {
      if (!item || typeof item === 'undefined') return false;
      const s = item.status;
      if (typeof s === 'string') return s.toLowerCase() === 'available';
      if (typeof s === 'boolean') return s === true;
      if (typeof s === 'number') return s === 1;
      return false;
    });

    const cleaned = availableOnly
      .map(item => {
        const copy = Object.assign({}, item);
        copy.layanan = _sanitize(item.layanan || item.name || item.title || '');
        if (item.name) copy.name = _sanitize(item.name);
        if (item.title) copy.title = _sanitize(item.title);
        if (item.provider) copy.provider = _sanitize(item.provider);
        if (item.category) copy.category = _sanitize(item.category);

        if (profitPercent > 0) {
          for (const key of priceKeys) {
            if (typeof copy[key] !== 'undefined' && copy[key] !== null && copy[key] !== '') {
              let num = Number(String(copy[key]).replace(/[^0-9.-]+/g, ''));
              if (!Number.isNaN(num)) {
                copy[`_orig_${key}`] = num;
                copy[key] = Math.ceil(num * (1 + profitPercent));
              }
            }
          }
        }
        return copy;
      })
      .filter(item => {
        const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name, item.title].filter(Boolean);
        const catCandidates = [item.category, item.type, item.group, item.service_type].filter(Boolean);

        const provHasTopup = provCandidates.some(p => endsWithTopup(p));
        const catHasTopup = catCandidates.some(c => endsWithTopup(c));
        return !(provHasTopup || catHasTopup);
      });

    return cleaned;
  } catch (err) {
    console.error('fetchPriceList error:', err && err.message ? err.message : err);
    return [];
  }
}*/

// --- ADD THESE LINES AT THE TOP (after other constants) ---
const CACHE_FILE = path.join(tmpDir, 'priceListCache.json');
const ERROR_LOG_FILE = path.join(tmpDir, 'priceListError.log');
const CACHE_TTL = 6 * 60 * 60 * 1000; // 6 jam dalam milidetik
let cachedPriceList = [];
let lastFetchTime = 0;
let lastSuccessFetchTime = 0;
let isApiDown = false;

// Fungsi untuk load cache dari file
function loadCacheFromFile() {
  try {
    if (fs.existsSync(CACHE_FILE)) {
      const data = fs.readFileSync(CACHE_FILE, 'utf8');
      const parsed = JSON.parse(data);
      cachedPriceList = parsed.data || [];
      lastFetchTime = parsed.lastFetchTime || 0;
      lastSuccessFetchTime = parsed.lastSuccessFetchTime || lastFetchTime;
      isApiDown = false;
      
      console.log(`📂 Cache loaded: ${cachedPriceList.length} items`);
      console.log(`   Last successful fetch: ${new Date(lastSuccessFetchTime).toLocaleString('id-ID')}`);
      console.log(`   Cache age: ${Math.round((Date.now() - lastSuccessFetchTime) / (60 * 60 * 1000))} hours`);
    } else {
      console.log('📭 No cache file found, starting fresh');
      cachedPriceList = [];
      lastFetchTime = 0;
      lastSuccessFetchTime = 0;
    }
  } catch (err) {
    console.error('❌ Failed to load cache file:', err.message);
    cachedPriceList = [];
    lastFetchTime = 0;
    lastSuccessFetchTime = 0;
  }
}

// Fungsi untuk save cache ke file
function saveCacheToFile(data, success = true) {
  try {
    const toSave = {
      data: data,
      lastFetchTime: Date.now(),
      lastSuccessFetchTime: success ? Date.now() : lastSuccessFetchTime,
      metadata: {
        itemCount: data.length,
        savedAt: new Date().toISOString(),
        processed: true, // Menandakan data sudah diproses (renamed)
        server: SERVER_HOST,
        configHash: getConfigHash(), // Hash config untuk detect perubahan
        version: '2.0'
      }
    };
    
    fs.writeFileSync(CACHE_FILE, JSON.stringify(toSave, null, 2));
    
    if (success) {
      console.log(`✅ Cache saved: ${data.length} items (processed data)`);
      lastSuccessFetchTime = Date.now();
      isApiDown = false;
    } else {
      console.log(`⚠️  Cache updated timestamp only (API down)`);
    }
  } catch (err) {
    console.error('❌ Failed to save cache file:', err.message);
  }
}

// Hash untuk mendeteksi perubahan config
function getConfigHash() {
  try {
    const configData = {
      rename_providers: CONFIG.rename_providers || {},
      hidden_providers: CONFIG.hidden_providers || [],
      hidden_categories: CONFIG.hidden_categories || [],
      img_providers: CONFIG.img_providers || {},
      priority_slugs: CONFIG.priority_slugs || []
    };
    
    return crypto.createHash('md5').update(JSON.stringify(configData)).digest('hex');
  } catch {
    return 'default';
  }
}

// Fungsi untuk log error
function logErrorToFile(error) {
  try {
    const logEntry = {
      timestamp: new Date().toISOString(),
      type: 'price_list_fetch_error',
      error: error.message || String(error),
      code: error.code,
      status: error.response?.status,
      statusText: error.response?.statusText,
      apiUrl: `${ATLANTIC_BASE}/layanan/price_list`,
      isApiDown: isApiDown,
      cacheAge: lastSuccessFetchTime ? Math.round((Date.now() - lastSuccessFetchTime) / (60 * 60 * 1000)) + ' hours' : 'N/A'
    };
    
    const logLine = JSON.stringify(logEntry) + '\n';
    fs.appendFileSync(ERROR_LOG_FILE, logLine, 'utf8');
    
    console.error(`📝 Error logged: ${error.message}`);
  } catch (logErr) {
    console.error('❌ Failed to write error log:', logErr.message);
  }
}

// Load cache saat startup
loadCacheFromFile();

// --- MODIFIED fetchPriceList FUNCTION WITH SMART CACHE ---
async function fetchPriceList() {
  const now = Date.now();
  const cacheAge = now - lastSuccessFetchTime;
  
  // 🔄 LOGIC UTAMA: Kapan harus fetch data baru?
  // 1. Jika cache kosong
  // 2. Jika cache lebih dari 6 jam DAN API tidak down
  // 3. Jika config berubah (deteksi via hash)
  
  const shouldFetchNewData = 
    cachedPriceList.length === 0 || 
    (cacheAge > CACHE_TTL && !isApiDown) ||
    checkConfigChanged();
  
  if (!shouldFetchNewData) {
    // Gunakan cache yang ada
    console.log(`📊 Using cached price list (${cachedPriceList.length} items)`);
    console.log(`   Cache age: ${Math.round(cacheAge / (60 * 60 * 1000))} hours`);
    return cachedPriceList;
  }
  
  console.log('🔄 Attempting to fetch fresh price list...');
  
  try {
    const freshData = await fetchAndProcessPriceList();
    
    // Update cache dengan data baru
    cachedPriceList = freshData;
    saveCacheToFile(freshData, true);
    
    console.log(`✅ Fresh data fetched: ${freshData.length} items`);
    return freshData;
    
  } catch (err) {
    console.error('❌ Failed to fetch fresh data:', err.message);
    
    // MARK API AS DOWN
    isApiDown = true;
    
    // Log error
    logErrorToFile(err);
    
    // 🔥 PENTING: JANGAN fetch ulang jika gagal, gunakan cache lama
    // Hanya update timestamp cache (tanpa ubah data)
    lastFetchTime = Date.now();
    
    // Save cache dengan timestamp baru (data tetap sama)
    if (cachedPriceList.length > 0) {
      saveCacheToFile(cachedPriceList, false);
      console.log(`🛡️  Keeping old cache (${cachedPriceList.length} items) - API is down`);
    }
    
    // Return cache yang ada (meskipun mungkin stale)
    return cachedPriceList.length > 0 ? cachedPriceList : [];
  }
}

// Fungsi untuk fetch dan process data dari API
async function fetchAndProcessPriceList() {
  const _sanitize = sanitizeProductName;
  const profitPercent = PROFIT_PERCENT / 100;
  const priceKeys = ['price', 'harga', 'amount', 'nominal', 'sell_price', 'sellPrice', 'value', 'selling_price'];

  // Helper untuk decode HTML entities
  function decodeHtmlEntities(s) {
    if (!s || typeof s !== 'string') return s;
    return s.replace(/&amp;|&AMP;/g, '&')
      .replace(/&nbsp;|&#160;/g, ' ')
      .trim();
  }

  function escapeRegex(s) {
    return String(s).replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
  }

  // --- Build rename maps from CONFIG (original -> target) and reverse (targetSlug -> [originals]) ---
  const providerRenameRaw = (CONFIG && CONFIG.rename_providers && typeof CONFIG.rename_providers === 'object')
    ? CONFIG.rename_providers
    : {
      'HBOGO&amp;MAX': 'HBO GO MAX',
      'MOBILE LEGENDS': 'Mobile Legends: BB',
      'canva': 'Canva',
      'PICSART': 'Picsart',
      'Capcut': 'CapCut',
      'CHATGPT': 'ChatGPT',
      'AI BLACKBOX': 'BLACKBOX.AI',
      'AI PERPLEXITY': 'Perplexity',
      'Youtube Premium': 'YouTube Premium',
      'VPN Express Premium': 'ExpressVPN'
    };

  // originalSlug -> targetDisplayName
  const ORIGINAL_TO_TARGET = new Map();
  // targetSlug -> Set(originalDecodedStrings)
  const TARGETSLUG_TO_ORIGINALS = new Map();

  Object.keys(providerRenameRaw).forEach(origKey => {
    try {
      const origDecoded = decodeHtmlEntities(String(origKey || '')).trim();
      const targetVal = String(providerRenameRaw[origKey] || '').trim();
      const targetDecoded = decodeHtmlEntities(targetVal);
      const origSlug = slugify(origDecoded);
      const targetSlug = slugify(targetDecoded || origDecoded);

      if (origSlug) ORIGINAL_TO_TARGET.set(origSlug, targetDecoded || origDecoded);

      if (!TARGETSLUG_TO_ORIGINALS.has(targetSlug)) TARGETSLUG_TO_ORIGINALS.set(targetSlug, new Set());
      // store both original decoded and slug forms for robust matching
      TARGETSLUG_TO_ORIGINALS.get(targetSlug).add(origDecoded);
      TARGETSLUG_TO_ORIGINALS.get(targetSlug).add(origDecoded.replace(/[^\w\s]/g, ' ').replace(/\s+/g, ' ').trim());
      TARGETSLUG_TO_ORIGINALS.get(targetSlug).add(origDecoded.replace(/[^\w]/g, '').trim());
    } catch (e) { /* ignore bad entry */ }
  });

  // hidden sets (from CONFIG or defaults)
  const hiddenProvidersFromConfig = Array.isArray(CONFIG && CONFIG.hidden_providers) ? CONFIG.hidden_providers : ['voucher'];
  const hiddenCategoriesFromConfig = Array.isArray(CONFIG && CONFIG.hidden_categories) ? CONFIG.hidden_categories : [];
  const HIDDEN_PROVIDERS = new Set(hiddenProvidersFromConfig.map(s => slugify(String(s || ''))));
  const HIDDEN_CATEGORIES = new Set(hiddenCategoriesFromConfig.map(s => slugify(String(s || ''))));

  // Build provider variant generator (many variants to match)
  function buildProviderVariants(providerRaw) {
    const out = new Set();
    if (!providerRaw || typeof providerRaw !== 'string') return out;
    let dec = decodeHtmlEntities(providerRaw).trim();
    if (!dec) return out;

    out.add(dec);
    out.add(dec.replace(/[™®©]/g, '').trim());
    // left-most part before common separators
    const sepParts = dec.split(/[:\-–—\/\\\(\)\[\|]/);
    if (sepParts && sepParts.length) out.add(sepParts[0].trim());

    // word prefix variants (1..3)
    const words = dec.split(/\s+/).filter(Boolean);
    for (let n = 1; n <= Math.min(3, words.length); n++) out.add(words.slice(0, n).join(' ').trim());

    // collapsed punctuation and compacted variants
    Array.from(Array.from(out)).forEach(v => {
      out.add(v.replace(/[^\w\s]/g, ' ').replace(/\s+/g, ' ').trim());
      out.add(v.replace(/[^\w]/g, '').trim());
    });

    // remove tiny values
    const final = new Set();
    out.forEach(v => { if (v && v.length >= 2) final.add(v); });
    return final;
  }

  // Remove provider text from a title using many variants + slug fallback
  function stripProviderFromTitle(title, provider) {
    if (!title || typeof title !== 'string') return title;
    if (!provider || typeof provider !== 'string') return title;

    let out = title;

    const provVariants = buildProviderVariants(provider);
    // add provider without diacritics/punctuations again
    Array.from(provVariants).sort((a, b) => b.length - a.length).forEach(v => {
      try {
        const tokens = v.split(/\s+/).filter(Boolean);
        if (!tokens.length) return;
        const pat = tokens.map(t => escapeRegex(t)).join('[\\s\\W]+');
        const re = new RegExp(`\\b${pat}\\b`, 'gi');
        out = out.replace(re, ' ').replace(/\s{2,}/g, ' ').trim();
      } catch (e) { /* ignore */ }
    });

    // slug-based fallback: if slug(provider) is prefix of slug(title)
    try {
      const provSlug = slugify(decodeHtmlEntities(provider || ''));
      const titleSlug = slugify(out || '');
      if (provSlug && titleSlug && titleSlug.indexOf(provSlug) === 0) {
        const provParts = provSlug.split('-').filter(Boolean);
        const titleWords = out.split(/\s+/).filter(Boolean);
        let removed = false;
        for (let n = provParts.length; n >= 1; n--) {
          const candidate = titleWords.slice(0, n).join(' ');
          if (slugify(candidate) === provParts.slice(0, n).join('-')) {
            out = titleWords.slice(n).join(' ').trim();
            removed = true;
            break;
          }
        }
        if (!removed && provParts.length && titleWords.length && slugify(titleWords[0]) === provParts[0]) {
          out = titleWords.slice(1).join(' ').trim();
        }
      }
    } catch (e) { /* ignore */ }

    out = out.replace(/\s{2,}/g, ' ').trim();
    if (!out) return title.trim();
    return out;
  }

  // 🔥 PENTING: TAMBAHKAN LOGIC RENAME CATEGORY DI SINI
  // Contoh: PLN -> voucher, dll
  function renameCategory(originalCategory) {
    if (!originalCategory) return originalCategory;
    
    const category = String(originalCategory).toLowerCase().trim();
    
    // Rename rules untuk kategori
    const categoryRenameMap = (CONFIG && CONFIG.rename_categories && typeof CONFIG.rename_categories === 'object')
    ? CONFIG.rename_categories
    : {
      'pln': 'Vouchers',
      'token pln': 'Vouchers',
      'listrik pln': 'Vouchers',
      'voucher': 'Vouchers',
      'game': 'Games',
      'game voucher': 'Games',
      'voucher game': 'Games',
      'entertainment': 'Entertainment',
      'streaming': 'Entertainment',
      'akun premium': 'Subscriptions',
      'subscription': 'Subscriptions',
      'tv': 'Cable TV'
    };
    
    // Cari exact match
    if (categoryRenameMap[category]) {
      return categoryRenameMap[category];
    }
    
    // Cari partial match
    for (const [key, value] of Object.entries(categoryRenameMap)) {
      if (category.includes(key) || key.includes(category)) {
        return value;
      }
    }
    
    return originalCategory;
  }

  const url = `${ATLANTIC_BASE}/layanan/price_list`;
  const res = await axios.post(
    url,
    new URLSearchParams({
      api_key: ATLANTIC_KEY,
      type: 'prabayar'
    }).toString(), {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 20000 // 20 detik timeout
    }
  );

  const raw = (res.data && res.data.data) ? res.data.data : [];

  const availableOnly = raw.filter(item => {
    if (!item) return false;
    const s = item.status;
    if (typeof s === 'string') return s.toLowerCase() === 'available';
    if (typeof s === 'boolean') return s === true;
    if (typeof s === 'number') return s === 1;
    return false;
  });

  const cleaned = availableOnly
    .map(item => {
      const copy = Object.assign({}, item);

      // sanitize existing fields
      copy.layanan = _sanitize(item.layanan || item.name || item.title || '');
      if (item.name) copy.name = _sanitize(item.name);
      if (item.title) copy.title = _sanitize(item.title);
      if (item.provider) copy.provider = _sanitize(item.provider);
      if (item.category) {
        // 🔥 APPLY CATEGORY RENAME HERE
        const originalCategory = _sanitize(item.category);
        copy.category = renameCategory(originalCategory);
      }

      // --- apply rename if original key matched ---
      try {
        const provRaw = (item.provider || item.layanan || item.name || '').toString();
        const provDecoded = decodeHtmlEntities(provRaw);
        const provSlug = slugify(provDecoded);
        if (ORIGINAL_TO_TARGET.has(provSlug)) {
          const newName = ORIGINAL_TO_TARGET.get(provSlug);
          copy.provider = newName;
          if (copy.name && slugify(decodeHtmlEntities(copy.name)) === provSlug) copy.name = newName;
          if (copy.title && slugify(decodeHtmlEntities(copy.title)) === provSlug) copy.title = newName;
          if (copy.layanan && slugify(decodeHtmlEntities(copy.layanan)) === provSlug) copy.layanan = newName;
        } else {
          // also support case where API already gives the target name (normalize its casing)
          const provSlugNow = slugify(decodeHtmlEntities(copy.provider || ''));
          if (TARGETSLUG_TO_ORIGINALS.has(provSlugNow)) {
            // keep provider as is (target), but we have originals available in reverse map
          }
        }
      } catch (e) { /* ignore */ }

      // --- build list of provider candidates to strip:
      // include: current display provider (copy.provider),
      // all original names that map to this target (from TARGETSLUG_TO_ORIGINALS),
      // plus original provider raw value from API.
      const stripCandidates = new Set();
      try {
        const currentProv = decodeHtmlEntities(String(copy.provider || '')).trim();
        if (currentProv) stripCandidates.add(currentProv);
        // originals for this target
        const targetSlug = slugify(currentProv || '');
        if (targetSlug && TARGETSLUG_TO_ORIGINALS.has(targetSlug)) {
          for (const o of TARGETSLUG_TO_ORIGINALS.get(targetSlug)) {
            if (o && typeof o === 'string') stripCandidates.add(o);
          }
        }
        // also include the raw provider from the API (before rename), defensive
        const rawProv = decodeHtmlEntities(String(item.provider || item.layanan || item.name || '')).trim();
        if (rawProv) stripCandidates.add(rawProv);
      } catch (e) { /* ignore */ }

      // --- strip all candidates from product labels ---
      try {
        if (stripCandidates.size) {
          ['layanan', 'name', 'title'].forEach(k => {
            if (copy[k] && typeof copy[k] === 'string') {
              let out = copy[k];
              for (const cand of stripCandidates) {
                out = stripProviderFromTitle(out, cand);
              }
              copy[k] = out;
            }
          });
        }
      } catch (e) { /* ignore strip errors */ }

      // --- apply profit markup ---
      if (profitPercent > 0) {
        for (const key of priceKeys) {
          if (typeof copy[key] !== 'undefined' && copy[key] !== null && copy[key] !== '') {
            let num = Number(String(copy[key]).replace(/[^0-9.-]+/g, ''));
            if (!Number.isNaN(num)) {
              copy[`_orig_${key}`] = num;
              copy[key] = Math.ceil(num * (1 + profitPercent));
            }
          }
        }
      }

      return copy;
    })
    .filter(item => {
      // final filtering: hidden providers/categories + topup filter
      const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name, item.title].filter(Boolean);
      const catCandidates = [item.category, item.type, item.group, item.service_type].filter(Boolean);

      for (const p of provCandidates) {
        try {
          const s = slugify(decodeHtmlEntities(String(p || '')));
          if (HIDDEN_PROVIDERS.has(s)) return false;
        } catch (e) {}
      }

      for (const c of catCandidates) {
        try {
          const s = slugify(String(c || ''));
          if (HIDDEN_CATEGORIES.has(s)) return false;
        } catch (e) {}
      }

      const provHasTopup = provCandidates.some(p => endsWithTopup(p));
      const catHasTopup = catCandidates.some(c => endsWithTopup(c));
      return !(provHasTopup || catHasTopup);
    });

  return cleaned;
}

// Fungsi untuk cek apakah config berubah
function checkConfigChanged() {
  try {
    if (!fs.existsSync(CACHE_FILE)) return false;
    
    const cacheData = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    const currentConfigHash = getConfigHash();
    const cachedConfigHash = cacheData.metadata?.configHash || 'default';
    
    if (currentConfigHash !== cachedConfigHash) {
      console.log(`🔄 Config changed! Old hash: ${cachedConfigHash}, New hash: ${currentConfigHash}`);
      console.log(`   Need to refetch data with new config...`);
      return true;
    }
    
    return false;
  } catch {
    return false;
  }
}

// --- SCHEDULED UPDATES (SMART) ---
async function tryUpdatePriceListCache() {
  const now = Date.now();
  const cacheAge = now - lastSuccessFetchTime;
  
  // 🔄 HANYA coba update jika:
  // 1. Cache lebih dari 6 jam
  // 2. API tidak dalam status "down"
  // 3. Atau jika config berubah
  
  if ((cacheAge > CACHE_TTL && !isApiDown) || checkConfigChanged()) {
    console.log('⏰ Scheduled update check: Attempting to fetch...');
    
    try {
      const freshData = await fetchAndProcessPriceList();
      
      // Update cache
      cachedPriceList = freshData;
      saveCacheToFile(freshData, true);
      
      console.log(`✅ Scheduled update successful: ${freshData.length} items`);
      
    } catch (err) {
      console.error('❌ Scheduled update failed:', err.message);
      
      // MARK API AS DOWN
      isApiDown = true;
      logErrorToFile(err);
      
      // 🔥 PENTING: Jangan ubah cache, hanya update timestamp
      lastFetchTime = Date.now();
      if (cachedPriceList.length > 0) {
        saveCacheToFile(cachedPriceList, false);
        console.log(`🛡️  Keeping old cache - API is down`);
      }
      
      // Coba lagi nanti (dalam 1 jam)
      setTimeout(tryUpdatePriceListCache, 60 * 60 * 1000);
    }
  } else {
    const nextCheck = CACHE_TTL - cacheAge;
    console.log(`⏰ Next scheduled check in: ${Math.round(nextCheck / (60 * 60 * 1000))} hours`);
  }
}

// Start scheduled updates (setiap 10 menit cek kondisi)
console.log(`🔄 Setting up smart scheduled updates (check every 10 minutes)`);
setInterval(tryUpdatePriceListCache, 10 * 60 * 1000); // Cek setiap 10 menit

// Initial check after 30 seconds
setTimeout(() => {
  if (cachedPriceList.length === 0) {
    console.log('🔄 Performing initial cache population...');
    tryUpdatePriceListCache();
  } else {
    console.log(`📊 Initial cache OK: ${cachedPriceList.length} items`);
    
    // Cek apakah perlu update
    const cacheAge = Date.now() - lastSuccessFetchTime;
    if (cacheAge > CACHE_TTL) {
      console.log(`🔄 Cache is stale (${Math.round(cacheAge / (60 * 60 * 1000))} hours), checking API...`);
      tryUpdatePriceListCache();
    }
  }
}, 30000);

// --- MANUAL UPDATE ENDPOINT (optional) ---
app.get('/api/refresh-cache', async (req, res) => {
  try {
    console.log('🔄 Manual cache refresh requested');
    const freshData = await fetchAndProcessPriceList();
    
    cachedPriceList = freshData;
    saveCacheToFile(freshData, true);
    
    res.json({
      success: true,
      message: `Cache refreshed with ${freshData.length} items`,
      items: freshData.length,
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Manual refresh failed:', err.message);
    res.json({
      success: false,
      message: `Failed to refresh: ${err.message}`,
      usingCache: cachedPriceList.length,
      cacheAge: lastSuccessFetchTime ? Math.round((Date.now() - lastSuccessFetchTime) / (60 * 60 * 1000)) + ' hours' : 'N/A'
    });
  }
});

// --- Cache status endpoint ---
app.get('/api/cache-status', (req, res) => {
  res.json({
    cacheSize: cachedPriceList.length,
    lastSuccessFetch: lastSuccessFetchTime ? new Date(lastSuccessFetchTime).toISOString() : null,
    lastFetch: lastFetchTime ? new Date(lastFetchTime).toISOString() : null,
    cacheAgeHours: lastSuccessFetchTime ? Math.round((Date.now() - lastSuccessFetchTime) / (60 * 60 * 1000)) : null,
    isApiDown: isApiDown,
    configHash: getConfigHash(),
    nextCheckIn: CACHE_TTL - (Date.now() - lastFetchTime)
  });
});

// --- INITIALIZE ---
console.log(`📊 Smart cache system initialized`);
console.log(`   Cache file: ${CACHE_FILE}`);
console.log(`   Error log: ${ERROR_LOG_FILE}`);
console.log(`   Cache TTL: 6 hours`);
console.log(`   Current cache: ${cachedPriceList.length} items`);
console.log(`   API Status: ${isApiDown ? 'DOWN' : 'OK'}`);

// ----------------------- helper: Fisher-Yates shuffle (pure, non-destructive) -----------------------
function shuffleArray(arr) {
  if (!Array.isArray(arr)) return [];
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = a[i];
    a[i] = a[j];
    a[j] = tmp;
  }
  return a;
}

function extractMeta(priceList) {
  // Normalize img_providers into a lookup map keyed by slugified key
  const imgProvidersRaw = (CONFIG && CONFIG.img_providers && typeof CONFIG.img_providers === 'object') ? CONFIG.img_providers : {};
  const imgProvidersMap = new Map();
  Object.keys(imgProvidersRaw).forEach(k => {
    try {
      const normKey = String(k).trim();
      const slugKey = slugify(normKey);
      imgProvidersMap.set(slugKey, String(imgProvidersRaw[k]));
      imgProvidersMap.set(normKey.toLowerCase(), String(imgProvidersRaw[k]));
    } catch (e) {
      // ignore invalid keys
    }
  });

  function maybePrefixOrigin(imgPath) {
    if (!imgPath || typeof imgPath !== 'string') return imgPath || null;
    const trimmed = imgPath.trim();
    if (!trimmed) return null;
    if (/^https?:\/\//i.test(trimmed)) return trimmed;
    if (trimmed.startsWith('/')) {
      const origin = (process.env.SITE_ORIGIN || '').replace(/\/$/, '');
      return origin ? `${origin}${trimmed}` : trimmed;
    }
    return trimmed;
  }

  function sanitizeLocal(r) {
    return sanitizeProductName(r);
  }

  const list = Array.isArray(priceList) ? priceList : [];

  const sanitized = list
    .map(item => {
      const copy = Object.assign({}, item);
      copy.layanan = sanitizeLocal(item.layanan || item.name || item.title || '');
      if (item.name) copy.name = sanitizeLocal(item.name);
      if (item.title) copy.title = sanitizeLocal(item.title);
      if (item.provider) copy.provider = sanitizeLocal(item.provider);
      if (item.category) copy.category = sanitizeLocal(item.category);
      return copy;
    })
    .filter(item => {
      const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name, item.title].filter(Boolean);
      const catCandidates = [item.category, item.type, item.group, item.service_type].filter(Boolean);
      return !(provCandidates.some(p => endsWithTopup(p)) || catCandidates.some(c => endsWithTopup(c)));
    });

  const catMap = new Map();
  const provMap = new Map();

  sanitized.forEach(item => {
    const providerNameRaw = item.provider || item.layanan || item.service || item.operator || item.name || 'Unknown';
    const providerName = sanitizeLocal(providerNameRaw) || providerNameRaw || 'Unknown';

    const categoryNameRaw = item.category || item.type || item.group || 'Other';
    const categoryName = sanitizeLocal(categoryNameRaw) || categoryNameRaw || 'Other';

    if (endsWithTopup(providerName) || endsWithTopup(categoryName)) return;

    const pSlug = slugify(providerName);
    const cSlug = slugify(categoryName) || 'other';

    // === Determine override image from config (img_providers) ===
    let overrideImg = null;
    if (imgProvidersMap.has(pSlug)) {
      overrideImg = imgProvidersMap.get(pSlug);
    } else {
      const lowerName = String(providerNameRaw).toLowerCase();
      if (imgProvidersMap.has(lowerName)) {
        overrideImg = imgProvidersMap.get(lowerName);
      } else {
        const altKey = slugify(String(providerNameRaw || '').trim());
        if (imgProvidersMap.has(altKey)) overrideImg = imgProvidersMap.get(altKey);
      }
    }

    if (overrideImg) {
      overrideImg = maybePrefixOrigin(overrideImg);
    }

    const fallbackImg = item.img_url || item.img || item.image || item.logo || null;
    const finalImg = overrideImg || fallbackImg || null;

    if (!provMap.has(pSlug)) {
      provMap.set(pSlug, {
        slug: pSlug,
        name: providerName,
        subtitle: item.subtitle || item.provider || item.layanan || '',
        img_url: finalImg,
        img: item.img || item.image || item.logo || null,
        count: 0,
        type: cSlug
      });
    } else {
      const existing = provMap.get(pSlug);
      if (!existing.img_url && finalImg) existing.img_url = finalImg;
    }
    provMap.get(pSlug).count += 1;

    if (!catMap.has(cSlug)) {
      catMap.set(cSlug, {
        slug: cSlug,
        name: categoryName,
        count: 0
      });
    }
    catMap.get(cSlug).count += 1;
  });

  // Special-case PLN => move into voucher category (preserve original logic)
  const plnSlug = 'pln';
  const voucherSlug = 'vouchers';
  if (provMap.has(plnSlug)) {
    const plnProv = provMap.get(plnSlug);
    plnProv.type = voucherSlug;
    const plnCount = plnProv.count || 0;
    if (catMap.has(voucherSlug)) {
      catMap.get(voucherSlug).count += plnCount;
    } else {
      catMap.set(voucherSlug, {
        slug: voucherSlug,
        name: 'Vouchers',
        count: plnCount
      });
    }
  }

  // ----------------------- NEW: Merge pulsa + data into pulsa-data -----------------------
  // Define candidate slugs/variants to merge
  const mergeCandidates = new Set([
    'pulsa-reguler', 'pulsa_reguler', 'pulsa reguler', 'pulsa',
    'data-internet', 'data_internet', 'data internet', 'data'
  ].map(s => slugify(s)));

  const targetSlug = 'pulsa-data';
  const targetDisplayName = 'Pulsa & Data';

  // 1) Reassign provider types that belong to mergeCandidates -> targetSlug
  provMap.forEach((prov, key) => {
    const provType = (prov.type && String(prov.type).trim()) ? slugify(prov.type) : '';
    if (!provType) return;
    if (mergeCandidates.has(provType)) {
      prov.type = targetSlug;
    } else {
      // also check if provider name contains 'pulsa' or 'data' as defensive fallback
      const lowerName = String(prov.name || '').toLowerCase();
      if (lowerName.includes('pulsa') && !lowerName.includes('voucher')) {
        prov.type = targetSlug;
      } else if (lowerName.includes('data') && !lowerName.includes('internet-package') && !lowerName.includes('voucher')) {
        prov.type = targetSlug;
      }
    }
  });

  // 2) Aggregate counts in catMap into targetSlug
  let mergedCount = 0;
  // collect keys to delete afterwards
  const keysToDelete = [];
  catMap.forEach((catObj, slugKey) => {
    const s = slugKey || '';
    if (mergeCandidates.has(s)) {
      mergedCount += (catObj.count || 0);
      keysToDelete.push(s);
    } else {
      // defensive: if name contains pulsa/data => include
      const nameLower = String(catObj.name || '').toLowerCase();
      if (nameLower.includes('pulsa') || nameLower.includes('data')) {
        mergedCount += (catObj.count || 0);
        keysToDelete.push(s);
      }
    }
  });

  // remove merged keys
  keysToDelete.forEach(k => catMap.delete(k));

  // add/merge targetSlug in catMap
  if (catMap.has(targetSlug)) {
    catMap.get(targetSlug).count += mergedCount;
    catMap.get(targetSlug).name = targetDisplayName;
  } else {
    // if mergedCount is zero but providers were moved, count should reflect provMap counts
    if (mergedCount === 0) {
      // compute count from provMap types
      let derivedCount = 0;
      provMap.forEach(p => { if (p.type === targetSlug) derivedCount += (p.count || 0); });
      mergedCount = derivedCount;
    }
    catMap.set(targetSlug, {
      slug: targetSlug,
      name: targetDisplayName,
      count: mergedCount
    });
  }

  // ----------------------- end merge logic -----------------------

  // Convert maps to arrays
  let categoriesArray = Array.from(catMap.values());
  let providersArray = Array.from(provMap.values());

  // Sort providers and categories alphabetically (Indonesian locale)
  providersArray.sort((a, b) => String(a.name || a.slug || '').localeCompare(String(b.name || b.slug || ''), 'id', {
    sensitivity: 'base'
  }));
  categoriesArray.sort((a, b) => String(a.name || a.slug || '').localeCompare(String(b.name || b.slug || ''), 'id', {
    sensitivity: 'base'
  }));

  const allCategory = {
    slug: 'all',
    name: 'Semua',
    count: sanitized.length
  };

  const prioritySlugs = Array.isArray(CONFIG.priority_slugs) ? CONFIG.priority_slugs.map(String) : [];

  const catBySlug = new Map();
  categoriesArray.forEach(c => {
    if (c && c.slug) catBySlug.set(c.slug, c);
  });

  const ordered = [allCategory];
  prioritySlugs.forEach(s => {
    if (catBySlug.has(s)) {
      ordered.push(catBySlug.get(s));
      catBySlug.delete(s);
    }
  });

  const remaining = Array.from(catBySlug.values()).sort((a, b) => String(a.name || a.slug || '').localeCompare(String(b.name || b.slug || ''), 'id', {
    sensitivity: 'base'
  }));

  categoriesArray = [...ordered, ...remaining];

  // ----------------------- order providers by category priority (respect merge) -----------------------
  const providersByType = new Map();
  providersArray.forEach(p => {
    const t = (p.type && String(p.type).trim()) ? String(p.type).trim() : 'other';
    if (!providersByType.has(t)) providersByType.set(t, []);
    providersByType.get(t).push(p);
  });

  providersByType.forEach((arr, t) => {
    arr.sort((a, b) => String(a.name || a.slug || '').localeCompare(String(b.name || b.slug || ''), 'id', {
      sensitivity: 'base'
    }));
  });

  const orderedProviders = [];
  function pushGroupIfExists(typeSlug) {
    if (providersByType.has(typeSlug)) {
      providersByType.get(typeSlug).forEach(p => orderedProviders.push(p));
      providersByType.delete(typeSlug);
    }
  }

  prioritySlugs.forEach(s => {
    pushGroupIfExists(s);
  });

  const remainingTypeSlugs = Array.from(providersByType.keys()).sort((a, b) => {
    const catA = categoriesArray.find(c => c.slug === a);
    const catB = categoriesArray.find(c => c.slug === b);
    const nameA = (catA && catA.name) ? String(catA.name) : a;
    const nameB = (catB && catB.name) ? String(catB.name) : b;
    return nameA.localeCompare(nameB, 'id', { sensitivity: 'base' });
  });

  remainingTypeSlugs.forEach(t => {
    providersByType.get(t).forEach(p => orderedProviders.push(p));
    providersByType.delete(t);
  });

  providersByType.forEach(arr => {
    arr.forEach(p => orderedProviders.push(p));
  });

  return {
    categories: categoriesArray,
    providers: orderedProviders
  };
}

// ----------------------- route: index (acak providers tiap request) -----------------------
app.get('/', async (req, res) => {
  try {
    const list = await fetchPriceList();
    const meta = extractMeta(list);
    
    //console.log(list);
    
    // Randomize providers on each reload (kalo mau non-acak, ganti jadi meta.providers)
    const providersShuffled = shuffleArray(meta.providers || []);

    res.render('index', {
      categories: meta.categories || [],
      providers: providersShuffled,
      rawProductsCount: list.length || 0,
      config: CONFIG,
      slugify
    });
  } catch (err) {
    console.error('Error rendering index:', err && err.message ? err.message : err);
    res.render('index', {
      categories: [],
      providers: [],
      rawProductsCount: 0,
      config: CONFIG,
      slugify
    });
  }
});

function firstApiImageFromProduct(p) {
  if (!p || typeof p !== 'object') return null;
  return p.img_url || p.img || p.image || p.logo || null;
}

// ----------------------- helper: try lookup logo from CONFIG.img_providers with multiple candidate keys
function pickLogoFromConfigOrApi(imgProvidersRaw, productsList, providerCandidates = []) {
  // build map (lowercase + slug keys)
  const map = new Map();
  if (imgProvidersRaw && typeof imgProvidersRaw === 'object') {
    Object.keys(imgProvidersRaw).forEach(k => {
      try {
        const v = imgProvidersRaw[k];
        if (v == null) return;
        map.set(String(k).toLowerCase(), String(v));
        map.set(slugify(String(k)), String(v));
      } catch (e) {}
    });
  }

  // try candidate keys in order
  for (const cand of providerCandidates) {
    if (!cand) continue;
    const k1 = String(cand).toLowerCase();
    const k2 = slugify(String(cand));
    if (map.has(k1)) return map.get(k1);
    if (map.has(k2)) return map.get(k2);
  }

  // fallback: first api image from product list
  if (Array.isArray(productsList)) {
    for (const p of productsList) {
      const img = firstApiImageFromProduct(p);
      if (img) return img;
    }
  }

  return null;
}

// ----------------------- helper: find most common value in array (mode)
function mostCommon(arr) {
  if (!Array.isArray(arr) || !arr.length) return null;
  const m = new Map();
  for (const v of arr) {
    const k = (v == null) ? '' : String(v);
    m.set(k, (m.get(k) || 0) + 1);
  }
  let top = null, topCount = 0;
  m.forEach((cnt, k) => { if (cnt > topCount) { top = k; topCount = cnt; }});
  return top;
}

// ----------------------- Revised route: provider page (more strict matching + logo priority)
// ----------------------- route: provider page (revised, full) -----------------------
app.get('/:category/:provider', csrfGenerator, async (req, res) => {
  try {
    const { category, provider } = req.params;
    // ambil list sekali saja
    const rawList = await fetchPriceList();
    const list = Array.isArray(rawList) ? rawList : [];

    // Normalize incoming slugs
    const reqProvSlug = slugify(provider || '');
    const reqCatSlug = slugify(category || '');

    // pulsa-data merge variants (slugified)
    const pulsaDataVariants = new Set(
      [
        'pulsa-reguler','pulsa_reguler','pulsa reguler','pulsa',
        'data-internet','data_internet','data internet','data',
        'pulsa-data','pulsa_data','pulsa data'
      ].map(s => slugify(s))
    );

    const wantMergedPulsaData = pulsaDataVariants.has(reqCatSlug);

    // helper: prefix origin for relative image paths
    function maybePrefixOriginLocal(imgPath) {
      if (!imgPath || typeof imgPath !== 'string') return null;
      const trimmed = imgPath.trim();
      if (!trimmed) return null;
      if (/^https?:\/\//i.test(trimmed)) return trimmed;
      if (trimmed.startsWith('/')) {
        const origin = (process.env.SITE_ORIGIN || '').replace(/\/$/, '');
        return origin ? `${origin}${trimmed}` : trimmed;
      }
      return trimmed;
    }

    // sanitized list: filter out "topup" junk entries using your existing rule
    const sanitized = list.filter(item => {
      const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name, item.title].filter(Boolean);
      const catCandidates = [item.category, item.type, item.group, item.service_type].filter(Boolean);
      const provHasTopup = provCandidates.some(p => endsWithTopup(p));
      const catHasTopup = catCandidates.some(c => endsWithTopup(c));
      const nameHasTopup = endsWithTopup(item.name) || endsWithTopup(item.title) || false;
      return !(provHasTopup || catHasTopup || nameHasTopup);
    });

    // helper: get slug candidates from an item (raw fields)
    function itemProviderSlugs(item) {
      const vals = [item.provider, item.layanan, item.service, item.operator, item.name, item.title].filter(Boolean);
      return Array.from(new Set(vals.map(v => slugify(String(v || '')))));
    }
    function itemCategorySlugs(item) {
      const vals = [item.category, item.type, item.group, item.service_type].filter(Boolean);
      return Array.from(new Set(vals.map(v => slugify(String(v || '')))));
    }

    // provider match used for filtering later (STRICT matching rules)
    function providerStrictMatches(item) {
      const slugs = itemProviderSlugs(item);
      if (!slugs.length) return false;

      // 1) exact slug match
      if (slugs.includes(reqProvSlug)) return true;

      // 2) token exact match: split each candidate slug and match tokens exactly
      for (const s of slugs) {
        const tokens = (s || '').split('-').filter(Boolean);
        if (tokens.includes(reqProvSlug)) return true;
      }

      // 3) whole-word raw match against combined raw fields (word boundary)
      const rawCombined = ((item.provider||'') + ' ' + (item.layanan||'') + ' ' + (item.name||'') + ' ' + (item.title||'')).toLowerCase();
      if (new RegExp('\\b' + reqProvSlug.replace(/[-\/\\^$*+?.()|[\]{}]/g,'\\$&') + '\\b').test(rawCombined)) return true;

      // NO substring/includes check here — keep strict!
      return false;
    }

    // category match used for filtering later (STRICT for existence check)
    function categoryStrictMatches(item) {
      const cslugs = itemCategorySlugs(item);

      if (wantMergedPulsaData) {
        // accept if item contains a pulsa/data variant slug exactly
        if (cslugs.some(c => pulsaDataVariants.has(c))) return true;
        const raw = ((item.category||'') + ' ' + (item.type||'') + ' ' + (item.group||'') + ' ' + (item.name||'') + ' ' + (item.title||'')).toLowerCase();
        if (/\b(pulsa|paket data|paket|data|internet)\b/.test(raw)) return true;
        return false;
      } else {
        // 1) exact category slug match
        if (cslugs.includes(reqCatSlug)) return true;

        // 2) token exact match
        for (const cs of cslugs) {
          const tokens = (cs || '').split('-').filter(Boolean);
          if (tokens.includes(reqCatSlug)) return true;
        }

        // 3) whole-word raw match
        const rawCat = ((item.category||'') + ' ' + (item.type||'') + ' ' + (item.group||'') + ' ' + (item.service_type||'')).toLowerCase();
        if (new RegExp('\\b' + (category || '').toLowerCase().replace(/[-\/\\^$*+?.()|[\]{}]/g,'\\$&') + '\\b').test(rawCat)) return true;

        // NO substring/includes check here — keep strict!
        return false;
      }
    }

    // ---------- PRELIMINARY STRICT existence validation ----------
    // Only allow rendering if provider AND category exist under strict rules.
    function hasProviderInList() {
      if (!reqProvSlug) return false;
      for (const it of sanitized) {
        if (providerStrictMatches(it)) return true;
      }
      return false;
    }

    function hasCategoryInList() {
      if (!reqCatSlug) return false;
      for (const it of sanitized) {
        if (categoryStrictMatches(it)) return true;
      }
      return false;
    }

    const providerExists = hasProviderInList();
    const categoryExists = hasCategoryInList();

    if (!providerExists || !categoryExists) {
      // Strict validation failed: redirect to home
      return res.redirect('/');
    }
    // ---------- END prelim validation ----------

    // FIRST strict filter (same as before) — find items that match both strictly
    let filtered = sanitized.filter(it => providerStrictMatches(it) && categoryStrictMatches(it));

    // RELAXED filters (fallbacks) if nothing found — only applied AFTER existence confirmed
    if (!filtered.length) {
      filtered = sanitized.filter(item => {
        const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name].filter(Boolean);
        const provMatch = provCandidates.some(p => {
          const ps = slugify(p);
          // allow some relaxed equality/token matching but still avoid blind substring acceptance
          if (ps === reqProvSlug) return true;
          const tokens = ps.split('-').filter(Boolean);
          if (tokens.includes(reqProvSlug)) return true;
          // allow request token inside provider tokens, but NOT vice-versa
          // (this is safer than ps.includes(reqProvSlug) || reqProvSlug.includes(ps))
          return false;
        });

        const catMatch = wantMergedPulsaData ? true : (
          [item.category, item.type, item.group, item.service_type].filter(Boolean).some(c => {
            const cs = slugify(c);
            if (cs === reqCatSlug) return true;
            const tokens = cs.split('-').filter(Boolean);
            if (tokens.includes(reqCatSlug)) return true;
            return false;
          })
          || ([item.category, item.type, item.group, item.service_type].filter(Boolean).length === 0)
        );
        return provMatch && catMatch;
      });
    }

    // last resort: provider-only relaxed (ignore category)
    if (!filtered.length) {
      filtered = sanitized.filter(item => {
        const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name].filter(Boolean);
        return provCandidates.some(p => {
          const ps = slugify(p);
          if (ps === reqProvSlug) return true;
          const tokens = ps.split('-').filter(Boolean);
          if (tokens.includes(reqProvSlug)) return true;
          return false;
        });
      });
    }

    // If still nothing (should be rare because we validated existence strictly earlier) redirect to home to be safe
    if (!filtered.length) {
      return res.redirect('/');
    }

    // sort by price ascending
    filtered.sort((a,b) => extractItemPrice(a) - extractItemPrice(b));

    // determine display names
    let providerName = provider || '';
    let categoryName = category || '';

    if (filtered.length) {
      const providerCandidates = filtered.map(p => (p.provider || p.layanan || p.service || p.operator || p.name || '').toString().trim()).filter(Boolean);
      const mostProv = mostCommon(providerCandidates);
      providerName = mostProv || providerName;

      if (wantMergedPulsaData) {
        categoryName = 'Pulsa & Data';
      } else {
        const catCandidates = filtered.map(p => (p.category || p.type || p.group || p.service_type || '').toString().trim()).filter(Boolean);
        const mostCat = mostCommon(catCandidates);
        categoryName = mostCat || categoryName;
      }
    }

    // ---------- LOGO selection (unchanged) ----------
    const imgProvidersRaw = (CONFIG && CONFIG.img_providers && typeof CONFIG.img_providers === 'object') ? CONFIG.img_providers : {};

    // candidate keys to lookup in CONFIG.img_providers
    const logoCandidates = [];

    if (providerName) logoCandidates.push(providerName);
    if (provider) logoCandidates.push(provider);
    if (reqProvSlug) logoCandidates.push(reqProvSlug);

    if (filtered.length) {
      const rawProvVals = filtered.map(p => (p.provider || p.layanan || p.name || p.service || p.operator || '').toString()).filter(Boolean);
      const commonRaw = mostCommon(rawProvVals);
      if (commonRaw) logoCandidates.push(commonRaw);
    }

    function pickLogoFromConfig(imgProvidersObj, candidates = [], productsFallback = []) {
      const m = new Map();
      if (imgProvidersObj && typeof imgProvidersObj === 'object') {
        Object.keys(imgProvidersObj).forEach(k => {
          try {
            const v = imgProvidersObj[k];
            if (v == null) return;
            m.set(String(k).toLowerCase(), String(v));
            m.set(slugify(String(k)), String(v));
          } catch (e) {}
        });
      }
      for (const cand of candidates) {
        if (!cand) continue;
        const k1 = String(cand).toLowerCase();
        const k2 = slugify(String(cand));
        if (m.has(k1)) return m.get(k1);
        if (m.has(k2)) return m.get(k2);
      }
      if (Array.isArray(productsFallback)) {
        for (const p of productsFallback) {
          const img = p && (p.img_url || p.img || p.image || p.logo);
          if (img) return img;
        }
      }
      return null;
    }

    const productsForFallback = filtered.length ? filtered : list;
    let providerLogoRaw = pickLogoFromConfig(imgProvidersRaw, logoCandidates, productsForFallback);

    if (!providerLogoRaw && provider) {
      const alt = pickLogoFromConfig(imgProvidersRaw, [provider, slugify(provider), String(provider).toLowerCase()], productsForFallback);
      if (alt) providerLogoRaw = alt;
    }

    const finalProviderLogo = maybePrefixOriginLocal(providerLogoRaw);

    res.render('provider', {
      categorySlug: category,
      providerSlug: provider,
      products: filtered,
      categoryName,
      providerName,
      providerLogo: finalProviderLogo,
      showAllCategory: true,
      feeByCustomer: FEE_BY_CUSTOMER,
      config: CONFIG
    });
  } catch (err) {
    console.error('Error in provider route:', err && err.message ? err.message : err);
    res.status(500).render('provider', {
      categorySlug: req.params && req.params.category,
      providerSlug: req.params && req.params.provider,
      products: [],
      categoryName: req.params && req.params.category,
      providerName: req.params && req.params.provider,
      providerLogo: null,
      showAllCategory: true,
      feeByCustomer: true,
      config: CONFIG
    });
  }
});

app.get('/payment', csrfGenerator, (req, res) => {
  const {
    trx_id
  } = req.query;

  if (!trx_id) {
    return res.status(400).json({
      message: 'Paramter trx_id diperlukan'
    });
  }

  const orders = readOrders();
  const order = orders.find(o => String(o.id) === String(trx_id));

  if (!order) {
    return res.render('payment', {
      trx_id,
      order: null,
      notfound: true,
      config: CONFIG
    });
  }

  res.render('payment', {
    trx_id,
    order,
    notfound: false,
    config: CONFIG
  });
});

app.get('/status', (req, res) => {
  res.render('status', { config: CONFIG });
});

app.get('/contact', (req, res) => {
  res.redirect('/support');
});

app.get('/support', (req, res) => {
  res.render('support', { config: CONFIG });
});

app.get('/faq', (req, res) => {
  res.render('faq', { config: CONFIG });
});

app.get('/panduan', (req, res) => {
  res.render('panduan', { config: CONFIG });
});

app.get('/syarat-dan-ketentuan', (req, res) => {
  res.render('syarat-dan-ketentuan', { config: CONFIG });
});

app.get('/refund-dan-kebijakan', (req, res) => {
  res.render('refund-dan-kebijakan', { config: CONFIG });
});

app.get('/api/price-list', async (req, res) => {
  
  
  const data = await fetchPriceList();
  const sanitized = (Array.isArray(data) ? data : []).filter(item => {
    const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name].filter(Boolean);
    const catCandidates = [item.category, item.type, item.group, item.service_type].filter(Boolean);
    const provHasTopup = provCandidates.some(p => endsWithTopup(p));
    const catHasTopup = catCandidates.some(c => endsWithTopup(c));
    const nameHasTopup = endsWithTopup(item.name) || endsWithTopup(item.title) || false;
    return !(provHasTopup || catHasTopup || nameHasTopup);
  });
  res.json({
    ok: true,
    count: sanitized.length,
    data: sanitized
  });
});

app.get('/api/categories', async (req, res) => {
  
  
  const list = await fetchPriceList();
  const {
    categories
  } = extractMeta(list);
  res.json({
    ok: true,
    count: categories.length,
    data: categories
  });
});

app.get('/api/providers', async (req, res) => {
  
  
  const {
    category = 'all'
  } = req.query;
  const list = await fetchPriceList();
  const {
    providers
  } = extractMeta(list);

  if (category === 'all') return res.json({
    ok: true,
    count: providers.length,
    data: providers
  });

  const filtered = providers.filter(p => p.type === slugify(category) || (p.name && p.name.toLowerCase().includes(String(category).toLowerCase())));
  filtered.sort((a, b) => String(a.name || '').localeCompare(String(b.name || ''), 'id', {
    sensitivity: 'base'
  }));
  res.json({
    ok: true,
    count: filtered.length,
    data: filtered
  });
});

app.get('/api/products', async (req, res) => {
  
  
  const {
    provider = '', category = ''
  } = req.query;
  const list = await fetchPriceList();

  const sanitized = (Array.isArray(list) ? list : []).filter(item => {
    const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name].filter(Boolean);
    const catCandidates = [item.category, item.type, item.group, item.service_type].filter(Boolean);
    const provHasTopup = provCandidates.some(p => endsWithTopup(p));
    const catHasTopup = catCandidates.some(c => endsWithTopup(c));
    const nameHasTopup = endsWithTopup(item.name) || endsWithTopup(item.title) || false;
    return !(provHasTopup || catHasTopup || nameHasTopup);
  });

  const filtered = sanitized.filter(item => {
    const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name].filter(Boolean);
    const catCandidates = [item.category, item.type, item.group].filter(Boolean);
    const provMatch = provider ? provCandidates.some(p => slugify(p).includes(slugify(provider)) || slugify(provider).includes(slugify(p))) : true;
    const catMatch = category ? catCandidates.some(c => slugify(c).includes(slugify(category)) || slugify(category).includes(slugify(c))) : true;
    return provMatch && catMatch;
  });

  filtered.sort((a, b) => extractItemPrice(a) - extractItemPrice(b));

  res.json({
    ok: true,
    count: filtered.length,
    data: filtered
  });
});

// =========================================================================
// [REVISI] ROUTE: API DEPOSIT METHODS (INJECT CUSTOM SALDO NAME)
// =========================================================================
app.post('/api/deposit-methods', csrfValidator, async (req, res) => {
  try {
    const { type = '', method = '' } = req.body || {};

    // 1. Ambil metode deposit dari Atlantic
    const url = `${ATLANTIC_BASE}/deposit/metode`;
    const params = new URLSearchParams({ api_key: ATLANTIC_KEY });
    if (type) params.append('type', type);
    if (method) params.append('metode', method);
    
    // Default fetch empty array jika gagal
    let items = [];
    try {
        const resp = await axios.post(url, params.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            timeout: 15000
        });
        const payload = resp.data || {};
        items = Array.isArray(payload.data) ? payload.data : [];
    } catch (e) {
        console.warn('Atlantic deposit methods fetch failed, using empty list');
    }

    // 2. Logic sorting & ranking metode (Original Logic)
    const getTypeRank = (item) => {
      const raw = (item && (item.type || item.method || item.metode || item.category || item.kategori || item.name || item.nama)) || '';
      const s = String(raw).toLowerCase();
      if (/ewallet/.test(s) || /e-?wallet/.test(s)) return 0;
      if (/gopay|ovo|dana|linkaja|shopeepay/.test(s)) return 0;
      if (/bank/.test(s)) return 1;
      if (/va\b|virtual/.test(s) || /virtualaccount/.test(s)) return 2;
      return 3;
    };

    const ranked = items.map((it, idx) => ({ it, idx, rank: getTypeRank(it) }));
    ranked.sort((a, b) => {
      if (a.rank !== b.rank) return a.rank - b.rank;
      return a.idx - b.idx;
    });
    let sortedData = ranked.map(r => r.it);

    // =======================================================
    // 3. LOGIKA BARU: FILTER PRIORITAS QRIS (FAST > BIASA)
    // =======================================================
    
    // A. Kumpulkan semua yang berbau "QRIS"
    // Regex ini mencocokkan 'qris' di nama/metode/code
    const allQrisItems = sortedData.filter(it => {
        const n = String((it && (it.method || it.metode || it.name || it.nama || it.code)) || '').toLowerCase();
        return /qris/i.test(n);
    });

    if (allQrisItems.length > 0) {
        // B. Cari Prioritas Utama: Yang namanya mengandung 'fast' atau 'instant'
        let selectedQris = allQrisItems.find(it => {
            const n = String((it && (it.method || it.name)) || '').toLowerCase();
            return /fast|instant/i.test(n);
        });

        // C. Fallback: Jika 'fast/instant' TIDAK ada, pakai QRIS apa saja yang tersisa (misal QRIS biasa)
        if (!selectedQris) {
            selectedQris = allQrisItems[0];
        }

        // D. Terapkan Override (Ubah Paksa Min/Max) pada QRIS yang terpilih
        if (selectedQris) {
            selectedQris.min_deposit = 500;
            selectedQris.min = 500;
            selectedQris.max = 5000000;
            if(selectedQris.limit) {
                selectedQris.limit.min = 500;
                selectedQris.limit.max = 5000000;
            }

            // E. UPDATE SORTED DATA
            // Kita buang bank/ewallet lain, hanya sisakan QRIS yang terpilih ini
            sortedData = [selectedQris];
        }
    } else {
        // Opsional: Jika TIDAK ADA QRIS sama sekali dari Atlantic (sedang gangguan total)
        // Apakah mau menampilkan list Bank biasa? Atau Kosong?
        // Kode di bawah membuat list jadi kosong agar user tidak salah pilih bank di menu QRIS
        sortedData = []; 
    }

    // =======================================================
    // [FITUR BARU] INJEKSI METODE SALDO USER (Tetap Ada)
    // =======================================================
    let currentBalance = 0;
    let isLoggedIn = false;

    if (req.session.user) {
        const allUsers = readUsers(); 
        const user = allUsers.find(u => u.id === req.session.user.id);
        if (user) {
            currentBalance = Number(user.balance || 0);
            isLoggedIn = true;
        }
    }

    const saldoName = process.env.SALDO_DISPLAY_NAME || 'Saldo Akun';

    const saldoMethod = {
        name: saldoName,
        type: 'BALANCE',
        method: 'SALDO',
        code: 'SALDO',
        img_url: '', 
        min_deposit: 0,
        min: 0,
        max: 0,
        fee: 0,
        fee_persen: 0,
        is_saldo: true,
        user_balance: currentBalance,
        is_logged_in: isLoggedIn,
        status: 'active'
    };

    // Masukkan Saldo ke urutan paling atas
    sortedData.unshift(saldoMethod);

    return res.json({
      ok: true,
      status: true,
      code: 200,
      data: sortedData
    });

  } catch (err) {
    console.error('deposit-methods error:', err && err.message);
    return res.status(500).json({ ok: false, message: 'fetch deposit methods failed', error: err.message });
  }
});

// =========================================================================
// [REVISI] ROUTE: API CREATE DEPOSIT (HANDLE SALDO & VALIDASI ADMIN)
// =========================================================================

const transactionLocks = new Set();

app.post('/api/create-deposit', csrfValidator, async (req, res) => {
  

  try {
    const {
      price,
      type = 'ewallet',
      method = 'QRISFAST',
      email,
      phone,
      product // Object: { code, target, price, name }
    } = req.body;

    if (!price) return res.status(400).json({ ok: false, message: 'nominal required' });

    // =====================================================
    // LOGIC PEMBAYARAN VIA SALDO (LANGSUNG TRANSAKSI)
    // =====================================================
    if (method === 'SALDO') {
    	
        // 1. Cek Login
        if (!req.session.user) {
            return res.status(401).json({ ok: false, message: 'Silakan login untuk menggunakan Saldo Akun.' });
        }
        
        if (transactionLocks.has(userId)) {
            return res.status(429).json({ ok: false, message: 'Transaksi sebelumnya sedang diproses. Mohon tunggu.' });
        }
        
        // Lock user
        transactionLocks.add(userId);

        // 2. Baca User Terbaru & Validasi Saldo User
        const users = readUsers();
        const userIndex = users.findIndex(u => u.id === req.session.user.id);
        
        if (userIndex === -1) {
            return res.status(404).json({ ok: false, message: 'User tidak ditemukan.' });
        }

        const user = users[userIndex];
        const totalPrice = Number(price); 
        
        // 3. Validasi: Apakah Saldo User Cukup?
        if (user.balance < totalPrice) {
            return res.status(400).json({ 
                ok: false, 
                message: `Saldo akun Anda tidak cukup. Saldo: Rp ${formatCurrency(user.balance)}, Total: Rp ${formatCurrency(totalPrice)}` 
            });
        }

        // 4. Potong Saldo User (Optimistic Update)
        // Kita potong dulu, kalau nanti gagal di provider, kita refund (kembalikan).
        const oldBalance = user.balance;
        users[userIndex].balance -= totalPrice;
        writeUsers(users); 
        
        // Update session agar UI header sinkron
        req.session.user.balance = users[userIndex].balance;

        // 5. Siapkan Data Order Lokal
        const reff_id = generateRef(12);
        let orders = readOrders();
        
        const newOrder = {
            trx_type: 'transaction', // Langsung transaction, bukan deposit
            id: String(reff_id),
            reff_id: String(reff_id),
            nominal: totalPrice,
            type: 'BALANCE',
            method: 'SALDO', // Method harus SALDO agar dikenali di payment.ejs
            email: email || (req.session.user ? req.session.user.email : ''),
            status: 'processing',    // Status awal processing
            trx_status: 'pending',   
            created_at: new Date().toISOString(),
            expired_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
            user_id: user.id,
            product: product || {},
            history_balance: { before: oldBalance, after: users[userIndex].balance }
        };

        // 6. Tembak API Atlantic (Transaksi)
        try {
        	if (!/^[a-zA-Z0-9.\-_@|]+$/.test(product.target)) {
                 throw new Error("Format target tidak valid (potensi injeksi)");
             }
             
            const productCode = product ? (product.code || product.kode) : '';
            const targetNum = product ? (product.target || product.tujuan) : '';
            
            const atlanticUrl = `${ATLANTIC_BASE}/transaksi/create`;
            const atlanticParams = new URLSearchParams({
                api_key: ATLANTIC_KEY,
                reff_id: reff_id,
                code: String(productCode).toUpperCase(),
                target: targetNum
            }).toString();

            const atlResp = await axios.post(atlanticUrl, atlanticParams, {
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
            });

            const atlData = atlResp.data;

            // Cek respon provider
            if (atlData.status || atlData.ok || atlData.success) {
                // SUKSES: Provider menerima order
                const d = atlData.data || {};
                newOrder.trx_id = d.id; // Simpan ID asli dari provider
                newOrder.sn = d.sn || '';
                newOrder.note = d.message || '';
                
                // Simpan order sukses ke database lokal
                orders.push(newOrder);
                writeOrders(orders);

                // Response Sukses ke Frontend
                return res.json({
                    ok: true,
                    order_id: reff_id, // Redirect ke ID lokal ini
                    message: 'Transaksi berhasil diproses.'
                });

            } else {
                // GAGAL DI PROVIDER (Misal: Saldo Atlantic Habis, Gangguan, Produk Close)
                // ==> REFUND SALDO USER <==
                users[userIndex].balance += totalPrice; // Balikin saldo
                writeUsers(users);
                req.session.user.balance = users[userIndex].balance;
                
                // Ambil pesan error dari provider jika ada
                const providerMsg = atlData.message || 'Gagal memproses transaksi di pusat.';
                
                console.error(`[SALDO REFUND] Trx Gagal: ${providerMsg}`);
                
                return res.status(500).json({ 
                    ok: false, 
                    message: `${providerMsg} (Saldo Anda telah dikembalikan)` 
                });
            }

        } catch (apiErr) {
             // ERROR JARINGAN (TIMEOUT/CONNECTION REFUSED)
             // ==> REFUND SALDO USER <==
             users[userIndex].balance += totalPrice;
             writeUsers(users);
             req.session.user.balance = users[userIndex].balance;

             console.error('Atlantic Network Error:', apiErr.message);
             return res.status(500).json({ 
                 ok: false, 
                 message: 'Gagal menghubungi server pusat. Silakan coba lagi nanti. (Saldo telah dikembalikan)' 
             });
        } finally {
             transactionLocks.delete(userId);
        }
    }

    // =====================================================
    // LOGIC DEPOSIT BIASA (NON-SALDO: QRIS, VA, E-WALLET)
    // =====================================================
    const reff_id = generateRef(12);
    const url = `${ATLANTIC_BASE}/deposit/create`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY,
      reff_id,
      nominal: price,
      type,
      metode: method,
      phone
    }).toString();

    const resp = await axios.post(url, params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    const data = resp.data;

    if (!data || !data.data) {
      return res.status(500).json({
        ok: false,
        message: data && data.message ? data.message : 'deposit create failed',
        raw: data
      });
    }

    let orders = readOrders();
    if (!Array.isArray(orders)) orders = [];

    const depositData = data.data;
    const order = {
      trx_type: 'deposit',
      id: depositData.id != null ? String(depositData.id) : String(reff_id),
      reff_id: String(reff_id),
      nominal: Number(price),
      type: type,
      method: method,
      email: email,
      status: 'pending',
      created_at: new Date().toISOString(),
      expired_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      product: product || {}
    };

    if (depositData.nomor_va) order.account_number = depositData.nomor_va;
    if (depositData.tujuan) order.destination_number = depositData.tujuan;
    if (depositData.url) order.url = depositData.url;
    if (depositData.qr_string) order.qr_string = depositData.qr_string;
    if (depositData.qr_image) order.qr_image = depositData.qr_image;
    if (depositData.tambahan) order.addition = depositData.tambahan;
    if (depositData.fee) order.fee = depositData.fee;
    if (depositData.get_balance) order.get_balance = depositData.get_balance;

    orders.push(order);
    writeOrders(orders);

    res.json({
      ok: true,
      reff_id,
      price,
      deposit: data.data,
      order_id: order.id
    });

  } catch (err) {
    console.error('create-deposit error:', err && err.response ? err.response.data || err.message : err);
    res.status(500).json({
      ok: false,
      message: 'Terjadi kesalahan sistem.',
      error: err.message
    });
  }
});

app.post('/api/deposit-status', async (req, res) => {
	
    
  try {
    const { id } = req.body || {};
    if (!id) return res.status(400).json({ ok: false, message: 'id required' });

    const url = `${ATLANTIC_BASE}/deposit/status`;
    const resp = await axios.post(
      url,
      new URLSearchParams({ api_key: ATLANTIC_KEY, id }).toString(),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const data = resp.data;
    if (data && data.data) {
      let orders = readOrders();
      const orderIndex = orders.findIndex(o => String(o.id) === String(id));
      if (orderIndex !== -1) {
        const newStatus = data.data.status || orders[orderIndex].status;
        orders[orderIndex].status = newStatus;
        if (!['pending', 'success'].includes(newStatus)) orders.splice(orderIndex, 1);
        writeOrders(orders);
      }
    }

    return res.json({ ok: true, data: resp.data });
  } catch (err) {
    console.error('deposit-status error:', err.response ? err.response.data : err.message);
    return res.status(500).json({ ok: false, message: 'deposit status failed', error: err.message });
  }
});

app.post('/api/deposit-cancel', async (req, res) => {
  
  
  try {
    const {
      id
    } = req.body;
    const url = `${ATLANTIC_BASE}/deposit/cancel`;
    const resp = await axios.post(url, new URLSearchParams({
      api_key: ATLANTIC_KEY,
      id
    }).toString(), {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    let orders = readOrders();
    orders = orders.filter(o => String(o.id) !== String(id));
    writeOrders(orders);

    res.json({
      ok: true,
      data: resp.data
    });
  } catch (err) {
    console.error('deposit-cancel error:', err.response ? err.response.data : err.message);
    res.status(500).json({
      ok: false,
      message: 'cancel failed',
      error: err.message
    });
  }
});

app.post('/api/transaction-create', csrfValidator, async (req, res) => {
  

  try {
    const {
      reff_id,
      code,
      target
    } = req.body;
    if (!reff_id || !code || !target) {
      return res.status(400).json({
        ok: false,
        message: 'reff_id, code, target required'
      });
    }

    const url = `${ATLANTIC_BASE}/transaksi/create`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY,
      reff_id,
      code: String(code).toUpperCase(),
      target
    }).toString();

    const resp = await axios.post(url, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    const data = resp.data;
    console.log(data)

    if (!data || !data.data) {
      return res.status(500).json({
        ok: false,
        message: data && data.message ? data.message : 'transaksi create failed',
        raw: data
      });
    }

    let orders = readOrders();
    let updatedIds = [];
    if (Array.isArray(orders)) {
      orders = orders.map(o => {
        if (o.trx_type === 'deposit' && o.status === 'success') {
          o.trx_type = 'transaction';
          o.trx_status = 'pending';
          o.trx_id = data.data.id;
          updatedIds.push(o.id || o.reff_id);
        }
        return o;
      });
      if (updatedIds.length > 0) {
        writeOrders(orders);
      }
    }

    res.json({
      ok: true,
      data: data.data,
      updated: updatedIds.length > 0 ? `orders updated: ${updatedIds.join(', ')}` : 'no matching orders found'
    });
  } catch (err) {
    console.error('transaction-create error:', err.response ? err.response.data : err.message);
    res.status(500).json({
      ok: false,
      message: 'transaksi create failed',
      error: err.message
    });
  }
});

app.post('/api/transaction-status', csrfValidator, async (req, res) => {
  
  
  try {
    const {
      id,
      type = 'prabayar'
    } = req.body;
    const url = `${ATLANTIC_BASE}/transaksi/status`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY,
      id,
      type
    }).toString();
    const resp = await axios.post(url, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const data = resp.data;
    //console.log(data)

    if (data && data.data) {
      const trxStatus = data.data.status || data.data.state || data.data.result || data.data.transaction_status || data.data.tx_status;
      const lowerStatus = String(trxStatus || '').toLowerCase();

      if (['success', 'done', 'paid', 'completed', 'failed', 'error', 'expired', 'cancel', 'cancelled'].includes(lowerStatus)) {
        /*let orders = readOrders();
        orders = orders.filter(o => String(o.id) !== String(id));
        writeOrders(orders);*/
      }
    }

    res.json({
      ok: true,
      data: resp.data
    });
  } catch (err) {
    console.error('transaction-status error:', err.response ? err.response.data : err.message);
    res.status(500).json({
      ok: false,
      message: 'transaksi status failed',
      error: err.message
    });
  }
});

// Route admin
const requireAdmin = (req, res, next) => {
  if (req.session && req.session.isAdmin) {
    return next();
  }
  // Jika akses via API, return 401
  if (req.xhr || req.headers.accept.indexOf('json') > -1) {
    return res.status(401).json({ ok: false, message: 'Unauthorized' });
  }
  // Jika akses via browser tapi belum login, render halaman dengan status isLoggedIn = false
  // Kita biarkan route /admin menangani rendering login view
  return next();
};

// 1. Route Halaman Admin (GET)
app.get('/admin', (req, res) => {
  // Cek apakah user sudah login sebagai admin di session
  const isLoggedIn = req.session && req.session.isAdmin === true;

  res.render('admin', { 
    isLoggedIn: isLoggedIn, // Flag untuk EJS
    config: CONFIG          // Pass config jika diperlukan
  });
});

// 2. Route Proses Login Admin (POST)
app.post('/api/admin/login', (req, res) => {
  const { password } = req.body;
  
  // Validasi di Server Side
  if (password === ADMIN_PASS) {
    req.session.isAdmin = true; // Set session
    
    // TAMBAHAN: Paksa simpan session sebelum kirim respon
    return req.session.save((err) => {
        if (err) {
            console.error("Gagal simpan session admin:", err);
            return res.status(500).json({ ok: false, message: 'Gagal menyimpan sesi' });
        }
        // Kirim respon HANYA setelah session tersimpan di file
        return res.json({ ok: true, message: 'Login berhasil' });
    });
  }
  
  return res.status(401).json({ ok: false, message: 'Password salah' });
});

// 3. Route Logout Admin (POST/GET)
app.get('/admin/logout', (req, res) => {
  if (req.session) {
    req.session.isAdmin = false;
  }
  res.redirect('/admin');
});

// Route ambil profil (saldo)
app.post('/admin/api/get-profile', async (req, res) => {
	if (!req.session.isAdmin) return res.status(401).json({ok: false});
  
  try {
    const url = `${ATLANTIC_BASE}/get_profile`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY
    }).toString();

    const resp = await axios.post(url, params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });

    return res.json({ ok: true, data: resp.data });
  } catch (err) {
    console.error("get-profile error:", err.message);
    res.status(500).json({ ok: false, message: "Failed to fetch profile" });
  }
});

// Route tarik saldo
app.post('/admin/api/withdraw', async (req, res) => {
	
  
  try {
    const { nominal } = req.body;
    if (!nominal || nominal < 3000) {
      return res.status(400).json({ ok: false, message: "Minimum withdraw 3000" });
    }

    const ref_id = "REF" + Date.now();
    const url = `${ATLANTIC_BASE}/transfer/create`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY,
      ref_id,
      kode_bank: BANK_CODE,
      nomor_akun: ACCOUNT_NUMBER,
      nama_pemilik: "Admin System",
      nominal,
      note: "Withdraw saldo admin"
    }).toString();

    const resp = await axios.post(url, params, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    
    console.log(resp.data)

    return res.json({ ok: true, data: resp.data });
  } catch (err) {
    console.error("withdraw error:", err.message);
    res.status(500).json({ ok: false, message: "Failed to withdraw" });
  }
});

app.get('/admin/api/price-list', async (req, res) => {
  

  try {
    const url = `${ATLANTIC_BASE}/layanan/price_list`;

    const atlanticRes = await axios.post(
      url,
      new URLSearchParams({
        api_key: ATLANTIC_KEY,
        type: 'prabayar'
      }).toString(),
      {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        timeout: 15000
      }
    );

    const data = (atlanticRes.data && atlanticRes.data.data) ? atlanticRes.data.data : [];

    const availableOnly = data.filter(item => {
      if (!item) return false;
      const s = item.status;
      if (typeof s === 'string') return s.toLowerCase() === 'available';
      if (typeof s === 'boolean') return s === true;
      if (typeof s === 'number') return s === 1;
      return false;
    });

    const priceKeys = ['price', 'harga', 'amount', 'nominal', 'value', 'sell_price', 'selling_price', 'sellPrice'];

    function extractNumericPrice(obj) {
      if (!obj || typeof obj !== 'object') return null;
      for (const key of priceKeys) {
        if (Object.prototype.hasOwnProperty.call(obj, key)) {
          const raw = obj[key];
          if (raw == null || raw === '') continue;
          if (typeof raw === 'number' && !Number.isNaN(raw)) return Number(raw);
          const str = String(raw);
          const num = Number(str.replace(/[^0-9.-]+/g, ''));
          if (!Number.isNaN(num)) return num;
        }
      }
      return null;
    }

    const cleaned = availableOnly
      .map(item => {
        const copy = { ...item };
        copy.layanan = sanitizeProductName(item.layanan || item.name || item.title || '');
        if (item.name) copy.name = sanitizeProductName(item.name);
        if (item.title) copy.title = sanitizeProductName(item.title);
        if (item.provider) copy.provider = sanitizeProductName(item.provider);
        if (item.category) copy.category = sanitizeProductName(item.category);

        const numeric = extractNumericPrice(copy);
        copy._price = (numeric === null) ? Infinity : numeric;

        return copy;
      })
      .filter(item => {
        const provCandidates = [item.provider, item.layanan, item.service, item.operator, item.name, item.title].filter(Boolean);
        const catCandidates = [item.category, item.type, item.group, item.service_type].filter(Boolean);
        const provHasTopup = provCandidates.some(p => endsWithTopup(p));
        const catHasTopup = catCandidates.some(c => endsWithTopup(c));
        return !(provHasTopup || catHasTopup);
      })
      .sort((a, b) => {
        const pa = (typeof a._price === 'number') ? a._price : Infinity;
        const pb = (typeof b._price === 'number') ? b._price : Infinity;
        return pa - pb;
      });

    res.json({ ok: true, count: cleaned.length, data: cleaned });
  } catch (err) {
    console.error('Error /price-list:', err && err.message ? err.message : err);
    res.status(500).json({
      ok: false,
      message: 'Gagal mengambil price list',
      error: err && err.message ? err.message : String(err)
    });
  }
});

app.post('/admin/api/check-account', async (req, res) => {
  

  try {
    const {
      reff_id,
      account_number,
      method
    } = req.body;
    if (!reff_id || !account_number || !method) {
      return res.status(400).json({
        ok: false,
        message: 'reff_id, account_number, method required'
      });
    }

    const url = `${ATLANTIC_BASE}/transfer/cek_rekening`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY,
      account_number: account_number,
      bank_code: method
    }).toString();

    const resp = await axios.post(url, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    const data = resp.data;
    //console.log(data)

    if (!data || !data.data) {
      return res.status(500).json({
        ok: false,
        message: data && data.message ? data.message : 'transaksi create failed',
        raw: data
      });
    }

    res.json({
      ok: true,
      data: data.data,
    });
  } catch (err) {
    console.error('transaction-create error:', err.response ? err.response.data : err.message);
    res.status(500).json({
      ok: false,
      message: 'transaksi create failed',
      error: err.message
    });
  }
});

app.post('/admin/api/transaction-create', async (req, res) => {
  

  try {
    const {
      reff_id,
      code,
      target
    } = req.body;
    if (!reff_id || !code || !target) {
      return res.status(400).json({
        ok: false,
        message: 'reff_id, code, target required'
      });
    }

    const url = `${ATLANTIC_BASE}/transaksi/create`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY,
      reff_id,
      code: String(code).toUpperCase(),
      target
    }).toString();

    const resp = await axios.post(url, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    const data = resp.data;
    
	console.log(data)

    if (!data || !data.data) {
      return res.status(500).json({
        ok: false,
        message: data && data.message ? data.message : 'transaksi create failed',
        raw: data
      });
    }

    res.json({
      ok: true,
      data: data.data,
    });
  } catch (err) {
    console.error('transaction-create error:', err.response ? err.response.data : err.message);
    res.status(500).json({
      ok: false,
      message: 'transaksi create failed',
      error: err.message
    });
  }
});

// POST /api/send-trx-email
/*app.post('/api/send-trx-email', async (req, res) => {
  try {
    const {
      transactionId, sn, email,
      product, amount, date, status, method, target,
      subject, extraMessage
    } = req.body || {};

    if (!transactionId || !sn || !email) {
      return res.status(400).json({ ok: false, message: 'transactionId, sn, dan email wajib diisi' });
    }
    if (!isEmail(email)) {
      return res.status(400).json({ ok: false, message: 'Format email tidak valid' });
    }

    // helper format currency (IDR)
    function formatCurrency(n) {
      try {
        const v = Number(n || 0);
        return new Intl.NumberFormat('id-ID', { style: 'currency', currency: 'IDR', minimumFractionDigits: 0 }).format(v);
      } catch {
        return String(n || '-');
      }
    }

    // helper format date (simple)
    function formatDateTime(d) {
      if (!d) return '-';
      const dt = (typeof d === 'string' || typeof d === 'number') ? new Date(d) : d;
      if (isNaN(dt)) return String(d);
      return dt.toLocaleString('id-ID', {
        day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
      });
    }

    // SN handling: detect full-link or URL inside
    const snStr = String(sn || '');
    const isSnLink = /^https?:\/\//i.test(snStr.trim());
    const urlInSnMatch = snStr.match(/https?:\/\/[^\s<>"']+/i);

    let snHtml;
    if (isSnLink) {
      const safeUrl = escapeHtml(snStr.trim());
      snHtml = `<a href="${safeUrl}" style="color:#0d6efd; text-decoration:underline;" target="_blank" rel="noopener noreferrer">${safeUrl}</a>`;
    } else if (urlInSnMatch) {
      const url = urlInSnMatch[0];
      const safeUrl = escapeHtml(url);
      const escapedSn = escapeHtml(snStr);
      const escapedUrl = escapeHtml(url);
      const anchor = `<a href="${safeUrl}" style="color:#0d6efd; text-decoration:underline;" target="_blank" rel="noopener noreferrer">${safeUrl}</a>`;
      const replaced = escapedSn.replace(escapedUrl, anchor);
      snHtml = `<div style="font-family: monospace; background:#f3f4f6; padding:10px; display:inline-block; border-radius:6px; word-break:break-word;">${replaced}</div>`;
    } else {
      snHtml = `<div style="font-family: monospace; background:#f3f4f6; padding:10px 12px; display:inline-block; border-radius:6px; word-break:break-word;">${escapeHtml(snStr)}</div>`;
    }

    const mailSubject = subject || `Pesanan: ${transactionId} — ayutopup`;

    // Responsive, centered email HTML (table-based)
    // max-width 600px, padding for mobile, and small media query for clients that support it.
    const mailHtml = `
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width">
  <style>
    @media only screen and (max-width: 620px) {
      .container { width: 100% !important; padding: 12px !important; }
      .content-cell { padding: 12px !important; }
      .two-col { display:block !important; width:100% !important; }
    }
    a { color: #0d6efd; }
  </style>
</head>
<body style="margin:0;padding:0;background:#f3f4f6;-webkit-text-size-adjust:none;">
  <!-- outer full-width table -->
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" align="center" style="background:#f3f4f6;">
    <tr>
      <td align="center" style="padding:20px 12px;">
        <!-- centered container with max-width -->
        <table class="container" role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:600px;background:transparent;">
          <tr>
            <td class="content-cell" style="padding:18px;background:transparent;">
              <!-- Card -->
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background:#ffffff;border-radius:10px;overflow:hidden;">
                <tr>
                  <td style="padding:20px 20px 8px 20px;">
                    <h1 style="margin:0 0 6px 0;font-size:20px;color:#0b5ed7;font-family:Arial,Helvetica,sans-serif;">Informasi Serial Number — ayutopup</h1>
                    <p style="margin:0 0 12px 0;color:#374151;font-family:Arial,Helvetica,sans-serif;">Terima kasih telah melakukan transaksi di <strong>ayutopup</strong>.</p>
                  </td>
                </tr>

                <tr>
                  <td style="padding:0 20px 18px 20px;">
                    <!-- content inner -->
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="font-family:Arial,Helvetica,sans-serif;color:#374151;">
                      <!-- Transaction ID -->
                      <tr>
                        <td style="padding:8px 0;">
                          <div style="font-size:13px;color:#6b7280;"><strong>ID Transaksi:</strong></div>
                          <div style="margin-top:6px;font-weight:700;color:#0f1724;">${escapeHtml(transactionId)}</div>
                        </td>
                      </tr>

                      <!-- SN -->
                      <tr>
                        <td style="padding:8px 0;">
                          <div style="font-size:13px;color:#6b7280;"><strong>Serial Number (SN):</strong></div>
                          <div style="margin-top:8px;">${snHtml}</div>
                        </td>
                      </tr>

                      <!-- two-column-ish area (will wrap on small screens) -->
                      <tr>
                        <td style="padding:12px 0 0 0;">
                          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0">
                            <tr>
                              <td class="two-col" style="vertical-align:top;padding-right:12px;width:50%;min-width:160px;">
                                <div style="font-size:13px;color:#6b7280;"><strong>Produk</strong></div>
                                <div style="margin-top:6px;font-weight:600;color:#0f1724;">${escapeHtml(product || '-')}</div>
                                <div style="height:8px;"></div>
                                <div style="font-size:13px;color:#6b7280;"><strong>Jumlah</strong></div>
                                <div style="margin-top:6px;font-weight:600;color:#0f1724;">${escapeHtml(formatCurrency(amount))}</div>
                              </td>

                              <td class="two-col" style="vertical-align:top;padding-left:12px;width:50%;min-width:160px;">
                                <div style="font-size:13px;color:#6b7280;"><strong>Status</strong></div>
                                <div style="margin-top:6px;font-weight:700;color:${(String(status||'').toLowerCase()==='success')? '#16a34a' : (String(status||'').toLowerCase()==='pending'? '#f59e0b' : '#ef4444') };">${escapeHtml(status || '-')}</div>
                                <div style="height:8px;"></div>
                                <div style="font-size:13px;color:#6b7280;"><strong>Tanggal</strong></div>
                                <div style="margin-top:6px;font-weight:600;color:#0f1724;">${escapeHtml(formatDateTime(date))}</div>
                              </td>
                            </tr>
                            <tr>
                              <td colspan="2" style="padding-top:12px;">
                                <div style="font-size:13px;color:#6b7280;"><strong>Metode / Target</strong></div>
                                <div style="margin-top:6px;font-weight:600;color:#0f1724;">${escapeHtml(method || target || '-')}</div>
                              </td>
                            </tr>
                          </table>
                        </td>
                      </tr>

                      ${extraMessage ? `
                      <tr>
                        <td style="padding-top:14px;border-top:1px solid #eef2f7;color:#374151;">
                          ${escapeHtml(extraMessage)}
                        </td>
                      </tr>` : ''}

                      <tr>
                        <td style="padding-top:18px;">
                          <div style="color:#6b7280;font-size:13px;">Terima kasih sudah order di ayutopup!</div>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>

                <tr>
                  <td style="padding:12px 20px 20px 20px;border-top:1px solid #eef2f7;">
                    <div style="font-size:12px;color:#9ca3af;">Jika bukan Anda yang meminta email ini, abaikan saja.</div>
                  </td>
                </tr>
              </table>
              <!-- end card -->
            </td>
          </tr>
        </table>
        <!-- end container -->
      </td>
    </tr>
  </table>
</body>
</html>
    `;

    // Plain text fallback
    const mailText = `
Informasi Serial Number — ayutopup

ID Transaksi: ${transactionId}
Serial Number: ${sn}

Produk: ${product || '-'}
Jumlah: ${formatCurrency(amount)}
Status: ${status || '-'}
Tanggal: ${formatDateTime(date)}
Metode/Target: ${method || target || '-'}

${extraMessage ? `Pesan: ${extraMessage}\n\n` : ''}

Jika bukan Anda yang meminta email ini, abaikan saja.
    `.trim();

    const info = await transporter.sendMail({
      from: `"ayutopup" <${SMTP_USER}>`,
      to: email,
      subject: mailSubject,
      html: mailHtml,
      text: mailText
    });

    return res.json({
      ok: true,
      message: 'Email terkirim',
      messageId: info.messageId,
      accepted: info.accepted,
      rejected: info.rejected
    });

  } catch (err) {
    console.error('Gagal kirim email:', err);
    return res.status(500).json({ ok: false, message: 'Gagal kirim email', error: err && err.message ? err.message : String(err) });
  }
});*/

// === Interval 1: cek deposit pending ===
/*setInterval(async () => {
  try {
    let orders = readOrders();
    if (!Array.isArray(orders) || orders.length === 0) return;

    let updated = false;

    for (let o of orders) {
      if (o.trx_type === 'deposit' && o.status === 'pending') {
        try {
          const url = `${ATLANTIC_BASE}/deposit/status`;
          const resp = await axios.post(
            url,
            new URLSearchParams({ api_key: ATLANTIC_KEY, id: o.id }).toString(),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
          );

          const data = resp.data;
          //console.log('Deposit ID: ', data.data.id);
          if (data && data.data) {
            const newStatus = data.data.status || o.status;
            o.status = newStatus;

            if (newStatus === 'success') {
              o.trx_type = 'transaction';
              o.status = 'success'; // pastikan success
              o.trx_status = 'pending';
              updated = true;
              console.log(`[DEPOSIT->TRANSACTION] Order ${o.id} sukses, diubah jadi transaction`);
            } else if (!['pending', 'success'].includes(newStatus)) {
              // status lain → hapus
              orders = orders.filter(x => x.id !== o.id);
              updated = true;
              console.log(`[DEPOSIT REMOVED] Order ${o.id} status: ${newStatus}`);
            }
          }
        } catch (err) {
          console.warn(`Interval deposit check gagal [${o.id}]`, err.message);
        }
      }
    }

    if (updated) writeOrders(orders);
  } catch (err) {
    console.error('Interval deposit check error:', err);
  }
}, 5000);*/

// --- Konfigurasi ---
// true = lakukan pencairan instan saat status processing
// false = hanya cek status processing tanpa mencairkan
const INSTANT_DEPOSIT = true;

setInterval(async () => {
  try {
    let orders = readOrders();
    if (!Array.isArray(orders) || orders.length === 0) return;

    let updated = false;

    for (let o of orders) {
      if (o.trx_type === 'deposit' && o.status === 'pending') {
        try {
          const url = `${ATLANTIC_BASE}/deposit/status`;
          const body = new URLSearchParams({
            api_key: ATLANTIC_KEY,
            id: o.id
          }).toString();

          const resp = await axios.post(url, body, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
          });

          const data = resp?.data?.data;
          if (data) {
            const newStatus = data.status || o.status;

            if (newStatus !== o.status) {
              o.status = newStatus;
              updated = true;
            }

            if (newStatus === 'success') {
              o.trx_type = 'deposit';
              o.status = 'success';
              updated = true;
              console.log(`[DEPOSIT->TRANSACTION] Order ${o.id} sukses, diubah jadi transaction`);
            } else if (newStatus === 'processing') {
              o.status = 'processing';
              updated = true;
              console.log(`[DEPOSIT PROCESSING] Order ${o.id} menunggu penyelesaian.`);
            } else if (!['pending', 'processing', 'success'].includes(newStatus)) {
              orders = orders.filter(x => x.id !== o.id);
              updated = true;
              console.log(`[DEPOSIT REMOVED] Order ${o.id} status: ${newStatus}`);
            }
          }
        } catch (err) {
          console.warn(`Interval deposit (pending) gagal [${o.id}]`, err?.message || err);
        }
      }
    }

    if (updated) writeOrders(orders);
  } catch (err) {
    console.error('Interval deposit check (pending) error:', err);
  }
}, 5000);

setInterval(async () => {
  try {
    let orders = readOrders();
    if (!Array.isArray(orders) || orders.length === 0) return;

    let updated = false;

    for (let o of orders) {
      if (o.trx_type === 'deposit' && o.status === 'processing') {
        try {
          const url = `${ATLANTIC_BASE}/deposit/instant`;
          const body = new URLSearchParams({
            api_key: ATLANTIC_KEY,
            id: o.id,
            action: INSTANT_DEPOSIT ? 'true' : 'false'
          }).toString();

          const resp = await axios.post(url, body, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
          });

          const data = resp?.data?.data;
          if (data) {
            const apiStatus = data.status;

            Object.assign(o, {
              penanganan: data.penanganan,
              total_fee: data.total_fee,
              total_diterima: data.total_diterima
            });

            if (apiStatus === 'success') {
              o.trx_type = 'transaction';
              o.status = 'success';
              o.trx_status = 'pending';
              updated = true;
              console.log(`[PROCESSING->SUCCESS] Order ${o.id} selesai (instant=${INSTANT_DEPOSIT}).`);
            } else if (apiStatus === 'processing') {
              console.log(`[PROCESSING] Order ${o.id} masih diproses (instant=${INSTANT_DEPOSIT}).`);
            } else {
              orders = orders.filter(x => x.id !== o.id);
              updated = true;
              console.log(`[DEPOSIT REMOVED] Order ${o.id} status tak dikenal: ${apiStatus}`);
            }
          } else {
            console.warn(`[PROCESSING CHECK] Respon tidak valid untuk order ${o.id}`);
          }
        } catch (err) {
          console.warn(`Interval processing check gagal [${o.id}]`, err?.message || err);
        }
      }
    }

    if (updated) writeOrders(orders);
  } catch (err) {
    console.error('Interval deposit check (processing) error:', err);
  }
}, 5000);

function formatCurrency(n) {
  try {
    const v = Number(n || 0);
    return new Intl.NumberFormat('id-ID', { style: 'currency', currency: 'IDR', minimumFractionDigits: 0 }).format(v);
  } catch {
    return String(n || '-');
  }
}

// helper: format tanggal
function formatDateTime(d) {
  if (!d) return '-';
  const dt = (typeof d === 'string' || typeof d === 'number') ? new Date(d) : d;
  if (isNaN(dt)) return String(d);
  return dt.toLocaleString('id-ID', {
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

setInterval(async () => {
  try {
    let orders = readOrders();
    if (!Array.isArray(orders) || orders.length === 0) return;

    let updated = false;

    for (let o of orders) {
      if (o.trx_type === 'transaction' && o.status === 'success' && o.trx_status === 'pending') {
        try {
          const url = `${ATLANTIC_BASE}/transaksi/status`;
          const params = new URLSearchParams({
            api_key: ATLANTIC_KEY,
            id: o.trx_id,
            type: 'prabayar'
          }).toString();

          const resp = await axios.post(url, params, {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
          });

          const data = resp.data;
          //console.log('Transaksi ID: ', data.data.id);
          if (data && data.data) {
            const trxStatus = data.data.status || data.data.state || data.data.result || data.data.transaction_status || data.data.tx_status;
            const lowerStatus = String(trxStatus || '').toLowerCase();

            if (['success', 'done', 'paid', 'completed'].includes(lowerStatus)) {
              // ambil SN
              const sn = data.data.sn || '(SN tidak tersedia)';

              // build konten email
              const transactionId = o.trx_id;
              const email = o.email || o.product?.target || null;
              const product = o.product?.name || '-';
              const amount = o.nominal || null;
              const date = new Date().toISOString();
              const status = trxStatus;
              const method = o.method;
              const target = o.product?.target;
              const subject = `Transaksi berhasil [${o.trx_id}]`;
              const extraMessage = 'Terimakasih.';

              const snStr = String(sn || '');
              const isSnLink = /^https?:\/\//i.test(snStr.trim());
              const urlInSnMatch = snStr.match(/https?:\/\/[^\s<>"']+/i);

              let snHtml;
              if (isSnLink) {
                const safeUrl = escapeHtml(snStr.trim());
                snHtml = `<a href="${safeUrl}" style="color:#0d6efd; text-decoration:underline;" target="_blank" rel="noopener noreferrer">${safeUrl}</a>`;
              } else if (urlInSnMatch) {
                const url = urlInSnMatch[0];
                const safeUrl = escapeHtml(url);
                const escapedSn = escapeHtml(snStr);
                const escapedUrl = escapeHtml(url);
                const anchor = `<a href="${safeUrl}" style="color:#0d6efd; text-decoration:underline;" target="_blank" rel="noopener noreferrer">${safeUrl}</a>`;
                const replaced = escapedSn.replace(escapedUrl, anchor);
                snHtml = `<div style="font-family: monospace; background:#f3f4f6; padding:10px; display:inline-block; border-radius:6px; word-break:break-word;">${replaced}</div>`;
              } else {
                snHtml = `<div style="font-family: monospace; background:#f3f4f6; padding:10px 12px; display:inline-block; border-radius:6px; word-break:break-word;">${escapeHtml(snStr)}</div>`;
              }

              const mailSubject = subject || `Pesanan: ${transactionId} — ${CONFIG.name}`;

              /*const mailHtml = `
                <h2>Informasi Serial Number — ayutopup</h2>
                <p>Terima kasih telah melakukan transaksi.</p>
                <p><b>ID Transaksi:</b> ${transactionId}</p>
                <p><b>SN:</b> ${snHtml}</p>
                <p><b>Produk:</b> ${product}</p>
                <p><b>Jumlah:</b> ${formatCurrency(amount)}</p>
                <p><b>Status:</b> ${status}</p>
                <p><b>Tanggal:</b> ${formatDateTime(date)}</p>
                <p><b>Metode/Target:</b> ${method || target}</p>
                ${extraMessage ? `<p>${extraMessage}</p>` : ''}
              `;

              const mailText = `
Informasi Serial Number — ayutopup

ID Transaksi: ${transactionId}
Serial Number: ${sn}

Produk: ${product}
Jumlah: ${formatCurrency(amount)}
Status: ${status}
Tanggal: ${formatDateTime(date)}
Metode/Target: ${method || target}

${extraMessage ? `Pesan: ${extraMessage}\n\n` : ''}
              `.trim();*/
              
              const mailHtml = `
<!doctype html>
<html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <style>
    /* Minimal responsive styles — many email clients mendukung media queries */
    @media only screen and (max-width:600px) {
      .container { padding:16px !important; }
      .content { padding:18px !important; }
      .label { display:block; width:100%; margin-bottom:6px; font-size:13px !important; }
      .value { font-size:15px !important; }
      .sn { font-size:15px !important; padding:10px !important; }
    }
    /* Use system fonts for better rendering in email clients */
    body, table, td, a { -webkit-text-size-adjust:100%; -ms-text-size-adjust:100%; }
    a { color: inherit; text-decoration: none; }
  </style>
</head>
<body style="margin:0;background:#f4f6f9;font-family:Inter, system-ui, -apple-system, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="min-width:100%;background:#f4f6f9;padding:24px 12px;">
    <tr>
      <td align="center">
        <table role="presentation" class="container" width="680" cellpadding="0" cellspacing="0" style="width:100%;max-width:680px;">
          <tr>
            <td>
              <!-- Card -->
              <div style="background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 10px 30px rgba(16,24,40,0.06);">
                <!-- Header -->
                <div style="padding:20px 24px;border-bottom:1px solid #eef2f7;">
                  <h2 style="margin:0;font-size:20px;color:#0b1220;letter-spacing:-0.2px;">Informasi Serial Number — ${CONFIG.name}</h2>
                  <p style="margin:8px 0 0;color:#475569;font-size:14px;">Terima kasih telah melakukan transaksi. Berikut detail transaksi Anda.</p>
                </div>

                <!-- Content -->
                <div class="content" style="padding:20px 24px;">
                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
                    <!-- Row: ID Transaksi -->
                    <tr>
                      <td style="padding:10px 0;border-bottom:1px solid #f1f5f9;vertical-align:top;">
                        <div class="label" style="font-size:13px;color:#94a3b8;font-weight:600;">ID Transaksi</div>
                        <div class="value" style="font-size:15px;color:#0b1220;">${transactionId}</div>
                      </td>
                    </tr>

                    <!-- Row: SN (special responsive block) -->
                    <tr>
                      <td style="padding:12px 0;border-bottom:1px solid #f1f5f9;vertical-align:top;">
                        <div class="label" style="font-size:13px;color:#94a3b8;font-weight:600;margin-bottom:8px;">Serial Number (SN)</div>

                        <!-- SN block: monospace, wraps nicely on mobile & desktop -->
                        <div class="sn" style="
                          display:block;
                          background:linear-gradient(180deg,#fbfdff,#f7fbff);
                          border:1px solid #e6eef9;
                          padding:12px 14px;
                          border-radius:8px;
                          font-family:ui-monospace, SFMono-Regular, Menlo, Monaco, 'Roboto Mono', 'Courier New', monospace;
                          font-size:14px;
                          color:#0b1220;
                          word-break:break-all;
                          white-space:pre-wrap;
                          -webkit-font-smoothing:antialiased;
                        ">
                          ${snHtml}
                        </div>

                        <!-- Small hint for mobile users -->
                        <div style="margin-top:8px;font-size:12px;color:#64748b;">Tip: Salin nomor SN untuk aktivasi. (Jika SN panjang, akan terbungkus otomatis.)</div>
                      </td>
                    </tr>

                    <!-- Row: Produk -->
                    <tr>
                      <td style="padding:10px 0;border-bottom:1px solid #f1f5f9;vertical-align:top;">
                        <div class="label" style="font-size:13px;color:#94a3b8;font-weight:600;">Produk</div>
                        <div class="value" style="font-size:15px;color:#0b1220;">${product}</div>
                      </td>
                    </tr>

                    <!-- Row: Jumlah -->
                    <tr>
                      <td style="padding:10px 0;border-bottom:1px solid #f1f5f9;vertical-align:top;">
                        <div class="label" style="font-size:13px;color:#94a3b8;font-weight:600;">Jumlah</div>
                        <div class="value" style="font-size:15px;color:#0b1220;">${formatCurrency(amount)}</div>
                      </td>
                    </tr>

                    <!-- Row: Status -->
                    <tr>
                      <td style="padding:10px 0;border-bottom:1px solid #f1f5f9;vertical-align:top;">
                        <div class="label" style="font-size:13px;color:#94a3b8;font-weight:600;">Status</div>
                        <div class="value" style="font-size:15px;color:#0b1220;">${status}</div>
                      </td>
                    </tr>

                    <!-- Row: Tanggal -->
                    <tr>
                      <td style="padding:10px 0;border-bottom:1px solid #f1f5f9;vertical-align:top;">
                        <div class="label" style="font-size:13px;color:#94a3b8;font-weight:600;">Tanggal</div>
                        <div class="value" style="font-size:15px;color:#0b1220;">${formatDateTime(date)}</div>
                      </td>
                    </tr>

                    <!-- Row: Metode/Target -->
                    <tr>
                      <td style="padding:10px 0;vertical-align:top;">
                        <div class="label" style="font-size:13px;color:#94a3b8;font-weight:600;">Metode / Target</div>
                        <div class="value" style="font-size:15px;color:#0b1220;">${method || target}</div>
                      </td>
                    </tr>

                    <!-- Optional extra message -->
                    ${extraMessage ? `
                      <tr>
                        <td style="padding:14px 0 0;vertical-align:top;">
                          <div class="label" style="font-size:13px;color:#94a3b8;font-weight:600;">Pesan</div>
                          <div style="font-size:14px;color:#0b1220;">${extraMessage}</div>
                        </td>
                      </tr>
                    ` : ''}

                  </table>
                </div>

                <!-- Footer -->
                <div style="padding:14px 24px;background:#fbfdff;border-top:1px solid #eef6ff;text-align:center;font-size:13px;color:#94a3b8;">
                  <div style="margin-bottom:6px;">Butuh bantuan? Kunjungi <a href="https://${CONFIG.domain}/support" style="color:#2563eb;">Pusat Bantuan kami</a></div>
                  <div style="font-size:11px;color:#b6c2d1;">&copy; ${new Date().getFullYear()} ${CONFIG.name} — Semua hak dilindungi.</div>
                </div>

              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
`.trim();

const mailText = `
Informasi Serial Number — ${CONFIG.name}

Terima kasih telah melakukan transaksi.

ID Transaksi : ${transactionId}
SN           : ${sn}
Produk       : ${product}
Jumlah       : ${formatCurrency(amount)}
Status       : ${status}
Tanggal      : ${formatDateTime(date)}
Metode/Target: ${method || target}

${extraMessage ? `Pesan: ${extraMessage}\n\n` : ''}
Terima kasih,
${CONFIG.domain}
`.trim();

              try {
                const info = await transporter.sendMail({
                  from: `"${CONFIG.name}" <${SMTP_USER}>`,
                  to: email,
                  subject: mailSubject,
                  html: mailHtml,
                  text: mailText
                });
                console.log(`[EMAIL SENT] ${transactionId} -> ${email}`, info.messageId);
              } catch (errMail) {
                console.error(`[EMAIL FAIL] ${transactionId}`, errMail.message);
              }

              o.trx_status = 'success';
              o.sn = sn;
              updated = true;
              console.log(`[TRANSACTION SUCCESS] Order ${o.id} trx_id=${o.trx_id}`);
            } else if (['failed', 'error', 'expired', 'cancel', 'cancelled'].includes(lowerStatus)) {
              orders = orders.filter(x => x.id !== o.id);
              updated = true;
              console.log(`[TRANSACTION REMOVED] Order ${o.id} status: ${lowerStatus}`);
            }
          }
        } catch (err) {
          console.warn(`Interval transaction check gagal [${o.id}]`, err.message);
        }
      }
    }

    if (updated) writeOrders(orders);
  } catch (err) {
    console.error('Interval transaction check error:', err);
  }
}, 5000);

app.get('/robots.txt', (req, res) => {
  const robots = `
User-agent: *
Allow: /

Sitemap: https://${CONFIG.domain}/sitemap.xml
  `.trim();

  res.type('text/plain').send(robots);
});

app.get('/sitemap.xml', (req, res) => {
  const sitemap = `
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://${CONFIG.domain}/</loc>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://${CONFIG.domain}/#provider</loc>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://${CONFIG.domain}/#provider</loc>
    <changefreq>daily</changefreq>
    <priority>0.9</priority>
  </url>
  <url>
    <loc>https://${CONFIG.domain}/#provider</loc>
    <changefreq>weekly</changefreq>
    <priority>0.8</priority>
  </url>
</urlset>
  `.trim();

  res.type('application/xml').send(sitemap);
});

// --- AUTH ROUTES ---

// Halaman Login
app.get('/login', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('login', { config: CONFIG, error: null });
});

// Proses Login
// Proses Login
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body;
    const users = readUsers();
    // Asumsi: findUserByEmail adalah fungsi yang memfilter users berdasarkan email
    const user = users.find(u => u.email === email); 

    if (!user || !bcrypt.compareSync(password, user.password)) {
        // Jika login gagal, kembalikan ke halaman login dengan error
        return res.render('login', { config: CONFIG, error: 'Email atau password salah' });
    }

    // 1. Set data user ke session
    req.session.user = { id: user.id, name: user.name, email: user.email, role: user.role };
    
    // 2. Gunakan req.session.save() untuk memastikan session tersimpan
    // sebelum melakukan redirect. Ini menyelesaikan masalah sync locals.
    req.session.save((err) => {
        if (err) {
            console.error('Gagal menyimpan session setelah login:', err);
            // Tangani error, tetapi tetap coba redirect untuk pengalaman pengguna yang lebih baik
            // jika error dianggap non-kritis (misalnya, hanya error saat menyimpan)
        }

        // 3. Lakukan redirect ke halaman utama (index.ejs)
        // Redirect ini HANYA akan terjadi setelah session dipastikan tersimpan.
        return res.redirect('/');
    });
});

// Halaman Register
app.get('/register', (req, res) => {
  if (req.session.user) return res.redirect('/');
  res.render('register', { config: CONFIG, error: null });
});

// Proses Register
app.post('/auth/register', async (req, res) => {
    const { name, email, password } = req.body;
    const users = readUsers();
    
    if (users.find(u => u.email === email)) {
        return res.render('register', { config: CONFIG, error: 'Email sudah terdaftar' });
    }

    const hashedPassword = bcrypt.hashSync(password, 10);
    
    const newUser = {
        id: uuidv4(),
        name,
        email,
        password: hashedPassword,
        balance: 0,
        role: 'user', // Role default
        type: 'free', // Type user default: free
        created_at: new Date().toISOString() // Tanggal terdaftar
    };

    users.push(newUser);
    writeUsers(users);

    return res.send(`
        <script>
            alert('Registrasi berhasil. Silakan login.');
            window.location.href = '/login';
        </script>
    `);
});
// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

// --- FITUR SALDO ---

// Halaman Topup Saldo UI Baru
app.get('/topup', async (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  
  // Ambil data user terbaru (untuk balance real-time)
  const users = readUsers();
  const currentUser = users.find(u => u.id === req.session.user.id);
  
  res.render('user-topup', { 
    config: CONFIG, 
    user: currentUser 
  });
});

// API Create Deposit Saldo (User)
app.post('/api/user/deposit-create', async (req, res) => {
  if (!req.session.user) return res.status(401).json({ ok: false, message: 'Unauthorized' });
  
  try {
    const { amount, type = 'ewallet', method = 'QRISFAST', phone } = req.body;
    if (!amount || amount < 5000) return res.status(400).json({ ok: false, message: 'Minimal Rp 5.000' });
    
    const reff_id = generateRef(12);
    
    // Request ke Atlantic (Deposit)
    const url = `${ATLANTIC_BASE}/deposit/create`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY,
      reff_id,
      nominal: amount,
      type: type, // Default type, bisa disesuaikan
      metode: method,
      phone
    }).toString();

    const resp = await axios.post(url, params, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }});
    const data = resp.data;

    if (!data.status) throw new Error(data.message || 'Gagal membuat deposit');

    // Simpan Order dengan tipe 'balance_topup'
    let orders = readOrders();
    orders.push({
      trx_type: 'balance_topup', // PENTING: pembeda dengan beli game
      id: String(data.data.id),
      user_id: req.session.user.id, // Link ke user
      nominal: amount,
      amount_received: data.data.get_balance, // Saldo yg didapat
      method: method,
      status: 'pending',
      created_at: new Date().toISOString(),
      qr_string: data.data.qr_string,
      qr_image: data.data.qr_image,
      pay_url: data.data.url
    });
    writeOrders(orders);

    res.json({ ok: true, data: data.data });

  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, message: 'Gagal memproses deposit' });
  }
});

// ROUTE BARU: cek status deposit khusus user dan auto-topup saldo saat success
app.post('/api/user/deposit-status', async (req, res) => {
  // Pastikan user login
  if (!req.session.user) return res.status(401).json({ ok: false, message: 'Unauthorized' });

  try {
    const { id } = req.body || {};
    if (!id) return res.status(400).json({ ok: false, message: 'id required' });

    // Panggil Atlantic untuk cek status deposit
    const url = `${ATLANTIC_BASE}/deposit/status`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY,
      id: String(id)
    }).toString();

    const resp = await axios.post(url, params, { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }});
    const data = resp.data || {};

    // jika API balik data, sinkronkan orders lokal
    if (data && data.data) {
      let orders = readOrders();
      // cari order yang punya id sama & trx_type 'balance_topup' & milik user saat ini
      const idx = orders.findIndex(o => String(o.id) === String(id) && (o.trx_type === 'balance_topup' || o.trx_type === 'deposit') && String(o.user_id) === String(req.session.user.id));
      
      if (idx !== -1) {
        const order = orders[idx];
        const newStatus = data.data.status || order.status || '';
        orders[idx].status = newStatus;

        // jika sudah success dan belum pernah dicredit, tambahkan saldo user
        if (String(newStatus).toLowerCase() === 'success' && !orders[idx].credited) {
          // Tentukan jumlah saldo yang diterima (prioritas: order.amount_received -> API get_balance -> order.nominal)
          const amountReceived = Number(order.amount_received || data.data.get_balance || order.get_balance || order.nominal || 0);

          if (amountReceived && amountReceived > 0) {
            // update users.json
            const users = readUsers();
            const userIndex = users.findIndex(u => String(u.id) === String(req.session.user.id));
            if (userIndex !== -1) {
              const prevBal = Number(users[userIndex].balance || 0);
              users[userIndex].balance = prevBal + amountReceived;
              writeUsers(users);

              // tandai order sudah dicredit supaya tidak duplikat
              orders[idx].credited = true;
              orders[idx].credited_at = new Date().toISOString();

              // update session user balance agar UI reflect segera
              req.session.user.balance = users[userIndex].balance;
            } else {
              console.warn('[deposit-status] user not found when crediting balance:', req.session.user.id);
            }
          } else {
            console.warn('[deposit-status] amountReceived not found or zero for order:', order.id);
          }
        }

        // hapus order non-pending/non-success sesuai policy (mirip route deposit-status)
        if (!['pending','success','processing'].includes(String(orders[idx].status).toLowerCase())) {
          // jika Anda ingin remove order, bisa lakukan orders.splice(idx,1)
          // tapi disini saya tetap menyimpan status terbaru; jika mau hapus uncomment baris berikut:
          // orders = orders.filter((x, i) => i !== idx);
        }

        // simpan perubahan orders
        writeOrders(orders);
      }
    }

    return res.json({ ok: true, data: resp.data });
  } catch (err) {
    console.error('user deposit-status error:', err && (err.response ? err.response.data : err.message));
    return res.status(500).json({ ok: false, message: 'deposit status failed', error: err.message || err });
  }
});

// ======================================================
// Cancel Deposit (User Action)
// ======================================================
app.post('/api/user/deposit-cancel', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ ok: false, message: 'Unauthorized' });
  }

  try {
    const { id } = req.body;
    if (!id) return res.status(400).json({ ok: false, message: 'Missing deposit ID' });

    // Kirim request pembatalan ke Atlantic
    const url = `${ATLANTIC_BASE}/deposit/cancel`;
    const params = new URLSearchParams({
      api_key: ATLANTIC_KEY,
      id
    }).toString();

    const resp = await axios.post(url, params, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" }
    });

    // Hapus dari orders.json
    let orders = readOrders();
    orders = orders.filter(o => String(o.id) !== String(id));
    writeOrders(orders);

    res.json({
      ok: true,
      message: 'Deposit cancelled successfully',
      data: resp.data
    });

  } catch (err) {
    console.error("deposit-cancel user error:", err.response ? err.response.data : err.message);

    res.status(500).json({
      ok: false,
      message: "Failed to cancel deposit",
      error: err.message
    });
  }
});

// =======================================================
// GET PROFIL USER (untuk update saldo realtime)
// =======================================================
app.get('/api/user/profile-data', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ ok: false, message: 'Unauthorized' });
    }

    try {
        const users = readUsers();
        // Asumsi req.session.user.id sudah benar
        const user = users.find(u => u.id === req.session.user.id);

        if (!user) {
            return res.status(404).json({ ok: false, message: 'User not found' });
        }

        return res.json({
            ok: true,
            balance: user.balance,
            name: user.name,
            email: user.email,             // Ditambahkan
            role: user.role || 'user',     // Ditambahkan (dengan fallback)
            type: user.type || 'free',     // Ditambahkan (dengan fallback)
            created_at: user.created_at,   // Ditambahkan (Tanggal Terdaftar)
            id: user.id
        });
        
    } catch (err) {
        console.error("Error /profile-data:", err);
        return res.status(500).json({ ok: false, message: 'Server error' });
    }
});

app.get('/account', (req, res) => {
    if (!req.session.user) return res.redirect('/login');
  
    const users = readUsers();
    // Cari data user terbaru
    const user = users.find(u => u.id === req.session.user.id);
    
    if (!user) {
        // Jika user tidak ditemukan (error), hapus sesi dan redirect ke login
        req.session.destroy(() => {
            res.redirect('/login');
        });
        return;
    }

    res.render('user-account', {
        user: user, // user berisi: id, name, email, balance, dll.
        config: CONFIG, // Pastikan 'config' tersedia di scope ini
        pageTitle: 'Akun Saya'
    });
});

// Endpoint untuk mengubah kata sandi
app.post('/api/user/change-password', async (req, res) => {
	if (!req.session.user) return res.redirect('/login');
	
    try {
        // Ambil data dari body request
        const { old_password, new_password } = req.body;
        const userId = req.session.user.id;

        // Validasi input
        if (!old_password || !new_password) {
            return res.status(400).json({ ok: false, message: 'Harap isi kata sandi lama dan baru.' });
        }
        
        if (new_password.length < 6) {
            return res.status(400).json({ ok: false, message: 'Kata sandi baru minimal 6 karakter.' });
        }
        
        // --- 1. Ambil Data User ---
        // Ganti dengan metode Anda membaca semua user
        const users = readUsers(); // Contoh fungsi yang Anda miliki
        const userIndex = users.findIndex(u => u.id === userId);

        if (userIndex === -1) {
            // Jika user tidak ditemukan, hapus sesi dan kirim error
            req.session.destroy(() => res.status(404).json({ ok: false, message: 'Sesi user tidak valid. Silakan login kembali.' }));
            return;
        }

        const user = users[userIndex];

        // --- 2. Verifikasi Kata Sandi Lama ---
        // Asumsi: Password user tersimpan dalam bentuk hash di user.password
        const isMatch = await bcrypt.compare(old_password, user.password);
        if (!isMatch) {
            return res.status(401).json({ ok: false, message: 'Kata sandi lama salah. Silakan coba lagi.' });
        }
        
        // --- 3. Hash Kata Sandi Baru ---
        const salt = await bcrypt.genSalt(10);
        const hashed_password = await bcrypt.hash(new_password, salt);

        // --- 4. Update dan Simpan ---
        users[userIndex].password = hashed_password;
        // Ganti dengan metode Anda menyimpan semua user
        writeUsers(users); // Contoh fungsi yang Anda miliki
        
        // Kirim respons sukses
        res.json({ ok: true, message: 'Kata sandi berhasil diubah.' });

    } catch (error) {
        console.error('Error changing password:', error);
        res.status(500).json({ ok: false, message: 'Terjadi kesalahan internal pada server.' });
    }
});

// Route untuk Validasi Login dan Ambil Saldo
app.get('/api/user/balance-status', async (req, res) => {
    // Memastikan pengguna sudah login
    if (!req.session.user || !req.session.user.email) {
        return res.json({ 
            ok: true, // Beri status 'ok: true' agar frontend tahu API berfungsi
            is_logged_in: false, 
            message: 'Pengguna belum login.', 
            balance: 0 
        });
    }

    try {
        // Asumsi: findUserByEmail tersedia dan dapat mengambil data user lengkap (termasuk 'balance')
        const user = findUserByEmail(req.session.user.email); 
        const currentBalance = (user && user.balance) ? Number(user.balance) : 0;
        
        return res.json({
            ok: true,
            is_logged_in: true,
            name: req.session.user.name,
            balance: currentBalance,
            message: 'Saldo berhasil dimuat.'
        });
    } catch (err) {
        console.error('Error fetching balance status:', err);
        return res.status(500).json({ 
            ok: false, 
            is_logged_in: false,
            message: 'Terjadi kesalahan saat memuat saldo.' 
        });
    }
});

app.use((req, res, next) => {
  const parts = req.path.split('/').filter(Boolean);

  if (parts.length === 2) {
    return next(); 
  }

  return res.redirect('/');
});

app.listen(SERVER_PORT, SERVER_HOST, () => {
  console.log(`Server running on http://${SERVER_HOST}:${SERVER_PORT} (PORT=${SERVER_PORT})`);
});