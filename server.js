const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const pdfParse = require('pdf-parse');

const app = express();
const PORT = process.env.PORT || 3000;

// Basit JWT sırrı (ileride .env'ye taşınabilir)
const JWT_SECRET = 'cok-gizli-bir-anahtar-degistirilecek';

// Klasörler
const DATA_DIR = path.join(__dirname, 'data');
const CANDIDATES_FILE = path.join(DATA_DIR, 'candidates.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const QUERIES_FILE = path.join(DATA_DIR, 'queries.json');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const SGK_DIR = path.join(UPLOAD_DIR, 'sgk');

let candidates = {};
let users = {};
let queries = []; // İşveren sorgu geçmişi

// Ortak klasör oluşturma
function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

// Verileri yükleme
function loadCandidates() {
  try {
    ensureDir(DATA_DIR);
    if (fs.existsSync(CANDIDATES_FILE)) {
      const raw = fs.readFileSync(CANDIDATES_FILE, 'utf8');
      candidates = JSON.parse(raw);
      console.log('Aday verisi yüklendi. Kayıt sayısı:', Object.keys(candidates).length);
    } else {
      candidates = {};
      console.log('Aday veri dosyası yok, boş başlandı.');
    }
  } catch (err) {
    console.error('Aday verisi okunurken hata:', err);
    candidates = {};
  }
}

function saveCandidates() {
  try {
    ensureDir(DATA_DIR);
    fs.writeFileSync(CANDIDATES_FILE, JSON.stringify(candidates, null, 2), 'utf8');
  } catch (err) {
    console.error('Aday verisi yazılırken hata:', err);
  }
}

function loadUsers() {
  try {
    ensureDir(DATA_DIR);
    if (fs.existsSync(USERS_FILE)) {
      const raw = fs.readFileSync(USERS_FILE, 'utf8');
      users = JSON.parse(raw);
      console.log('Kullanıcı verisi yüklendi. Kullanıcı sayısı:', Object.keys(users).length);
    } else {
      users = {};
      console.log('Kullanıcı veri dosyası yok, boş başlandı.');
    }
  } catch (err) {
    console.error('Kullanıcı verisi okunurken hata:', err);
    users = {};
  }
}

function saveUsers() {
  try {
    ensureDir(DATA_DIR);
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
  } catch (err) {
    console.error('Kullanıcı verisi yazılırken hata:', err);
  }
}

function loadQueries() {
  try {
    ensureDir(DATA_DIR);
    if (fs.existsSync(QUERIES_FILE)) {
      const raw = fs.readFileSync(QUERIES_FILE, 'utf8');
      queries = JSON.parse(raw);
      console.log('Sorgu verisi yüklendi. Sorgu sayısı:', queries.length);
    } else {
      queries = [];
      console.log('Sorgu veri dosyası yok, boş başlandı.');
    }
  } catch (err) {
    console.error('Sorgu verisi okunurken hata:', err);
    queries = [];
  }
}

function saveQueries() {
  try {
    ensureDir(DATA_DIR);
    fs.writeFileSync(QUERIES_FILE, JSON.stringify(queries, null, 2), 'utf8');
  } catch (err) {
    console.error('Sorgu verisi yazılırken hata:', err);
  }
}

// Klasörleri hazırla
ensureDir(DATA_DIR);
ensureDir(UPLOAD_DIR);
ensureDir(SGK_DIR);

// Sunucu açılırken verileri yükle
loadCandidates();
loadUsers();
loadQueries();

// 🚨 Her durumda varsayılan admin hesabını garanti altına al
(function ensureDefaultAdmin() {
  const email = 'admin@kadis.local';
  const password = 'Kadis!123';
  const passwordHash = bcrypt.hashSync(password, 10);

  // admin@kadis.local hesabını her seferinde bu bilinen bilgilerle güncelliyoruz
  users[email.toLowerCase()] = {
    email: email.toLowerCase(),
    passwordHash,
    role: 'admin',
    createdAt: new Date().toISOString(),
    note: 'Her açılışta güncellenen varsayılan admin hesabı'
  };

  saveUsers();
  console.log('Varsayılan admin hazır: admin@kadis.local / Kadis!123');
})();

// Fotoğraf upload ayarları (multer)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, UPLOAD_DIR);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname) || '';
    const unique = Date.now() + '-' + crypto.randomBytes(3).toString('hex');
    cb(null, unique + ext);
  }
});

const upload = multer({ storage });
// SGK PDF upload ayarları (sadece PDF)
const sgkStorage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, SGK_DIR);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname) || '.pdf';
    const unique = Date.now() + '-' + crypto.randomBytes(3).toString('hex');
    cb(null, unique + ext);
  }
});

function pdfFileFilter(req, file, cb) {
  if (file.mimetype !== 'application/pdf') {
    return cb(new Error('Sadece PDF dosyası yüklenebilir.'), false);
  }
  cb(null, true);
}

const uploadSgk = multer({ storage: sgkStorage, fileFilter: pdfFileFilter });

// SGK PDF analiz fonksiyonu (MVP)
async function analyzeSgkPdf(filePath) {
  const buf = fs.readFileSync(filePath);
  const data = await pdfParse(buf);

  const text = data.text || '';
  const metadata = data.info || {};

  let score = 100;
  const notes = [];

  // SGK hizmet dökümü format kontrolü (çok basit)
  if (!/HİZMET DÖKÜMÜ/i.test(text) && !/Sosyal Güvenlik Kurumu/i.test(text)) {
    score -= 40;
    notes.push('Metin SGK hizmet dökümü formatına benzemiyor.');
  }

  // Toplam prim günü yakalama (örnek)
  let totalPrimDays = '';
  const primMatch = text.match(/Toplam\s+Prim\s+Gün(?:ü|u)\s*:\s*(\d+)/i);
  if (primMatch) {
    totalPrimDays = primMatch[1];
  } else {
    score -= 20;
    notes.push('Toplam prim günü alanı bulunamadı.');
  }

  // Son çalışılan şirket unvanını yakalama (örnek)
  let lastCompany = '';
  const companyMatch = text.match(/İşveren\s+Unvan[ıi]\s*:\s*(.+)/i);
  if (companyMatch) {
    lastCompany = companyMatch[1].trim();
  } else {
    notes.push('Son işveren unvanı net tespit edilemedi.');
  }

  // Metadata kontrolü: oluşturma ve değiştirme tarihleri farklı mı?
  if (metadata.ModDate && metadata.CreationDate && metadata.ModDate !== metadata.CreationDate) {
    score -= 20;
    notes.push('PDF, oluşturulduktan sonra değiştirilmiş görünüyor (metadata).');
  }

  if (score < 0) score = 0;

  let status = 'suspected';
  if (score >= 75) status = 'verified';
  else if (score >= 40) status = 'pending';
  else status = 'suspected';

  return {
    status,
    score,
    parsed: {
      totalPrimDays,
      lastCompany
    },
    notes: notes.join(' | ')
  };
}


// Orta katmanlar
app.use(cors());
app.use(express.json());

// 🔒 HTTP → HTTPS zorunlu yönlendirme (özellikle Render + custom domain için)
app.use((req, res, next) => {
  // x-forwarded-proto = Render / proxy arkası gerçek protokol
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    return res.redirect('https://' + req.headers.host + req.url);
  }
  next();
});

app.use('/uploads', express.static('uploads'));

// ---- Ana sayfa route'u (Landing Page) ----
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

// Statik dosyalar
app.use(express.static('public'));

// ---- JWT doğrulama middleware ----
function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'Token gerekli.' });

  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token bulunamadı.' });

  jwt.verify(token, JWT_SECRET, (err, userData) => {
    if (err) return res.status(403).json({ message: 'Geçersiz token.' });
    req.user = userData; // { email, role }
    next();
  });
}

// ---- Yardımcı fonksiyon ----
function generateVerificationCode() {
  return crypto.randomBytes(3).toString('hex').toUpperCase();
}

// 7 gün sonrasını hesapla
function getExpiryDateISO() {
  const now = new Date();
  const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  return expires.toISOString();
}

// ========================
// AUTH HANDLER FONKSİYONLARI
// ========================

// Kayıt handler
function registerHandler(req, res) {
  const { email, password, role } = req.body;

  if (!email || !password || !role) {
    return res.status(400).json({ message: 'Email, şifre ve rol zorunludur.' });
  }

  // ❗ Artık admin rolü kayıt ekranından verilemez
  if (role === 'admin') {
    return res.status(403).json({ message: 'Admin rolü son kullanıcı kaydına kapalıdır.' });
  }

  if (!['candidate', 'employer'].includes(role)) {
    return res.status(400).json({ message: 'Rol sadece candidate veya employer olabilir.' });
  }

  const normalizedEmail = email.toLowerCase();

  if (users[normalizedEmail]) {
    return res.status(409).json({ message: 'Bu email ile kullanıcı zaten kayıtlı.' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);

  users[normalizedEmail] = {
    email: normalizedEmail,
    passwordHash,
    role,
    createdAt: new Date().toISOString()
  };

  saveUsers();

  return res.json({ message: 'Kullanıcı başarıyla oluşturuldu.' });
}

// Login handler
function loginHandler(req, res) {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: 'Email ve şifre zorunludur.' });
  }

  const normalizedEmail = email.toLowerCase();
  const user = users[normalizedEmail];

  if (!user) {
    return res.status(401).json({ message: 'Geçersiz email veya şifre.' });
  }

  const isMatch = bcrypt.compareSync(password, user.passwordHash);
  if (!isMatch) {
    return res.status(401).json({ message: 'Geçersiz email veya şifre.' });
  }

  const token = jwt.sign(
    { email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '2h' }
  );

  return res.json({
    message: 'Giriş başarılı.',
    token,
    role: user.role
  });
}

// ---- AUTH: Eski yollar (/api/auth/...) ----
app.post('/api/auth/register', registerHandler);
app.post('/api/auth/login', loginHandler);

// ---- AUTH: Yeni yollar (/api/...) – FRONTEND BUNLARI KULLANIYOR ----
app.post('/api/register', registerHandler);
app.post('/api/login', loginHandler);

// ---- Profil endpoint'i ----
app.get('/api/profile', authMiddleware, (req, res) => {
  const user = users[req.user.email];
  if (!user) {
    return res.status(404).json({ message: 'Kullanıcı bulunamadı.' });
  }
  return res.json({
    email: user.email,
    role: user.role,
    createdAt: user.createdAt
  });
});

// ---- Aday oluşturma (sadece candidate) ----
app.post('/api/candidates', authMiddleware, upload.single('photo'), (req, res) => {
  if (req.user.role !== 'candidate') {
    return res.status(403).json({ message: 'Sadece aday rolü bu işlemi yapabilir.' });
  }

  const {
    fullName,
    email,
    nationalId,
    totalPrimDays,
    lastCompany,
    position,
    experience
  } = req.body;

  if (!fullName || !email) {
    return res.status(400).json({ message: 'İsim ve e-posta zorunludur.' });
  }

  const ownerEmail = req.user.email;

  // Eski kayıtları arşivle
  Object.entries(candidates).forEach(([c, cand]) => {
    if (cand.ownerEmail === ownerEmail) {
      cand.isArchived = true;
      cand.archivedAt = new Date().toISOString();
    }
  });

  // Yeni kod + tarih + 7 gün geçerlilik
  const code = generateVerificationCode();
  const createdAt = new Date().toISOString();
  const expiresAt = getExpiryDateISO();
  const photoFilename = req.file ? req.file.filename : '';

    candidates[code] = {
    fullName,
    email,
    nationalId: nationalId || '',
    totalPrimDays: totalPrimDays || '',
    lastCompany: lastCompany || '',
    position: position || '',
    experience: experience || '',
    photoFilename,
    createdAt,
    expiresAt,           // 🔥 7 gün sonra bitecek
    ownerEmail: ownerEmail,
    isArchived: false,
    sgkVerification: {
      status: 'none',        // 'none' | 'pending' | 'verified' | 'suspected'
      score: 0,
      filePath: '',
      parsed: {
        totalPrimDays: '',
        lastCompany: ''
      },
      checkedAt: null,
      notes: ''
    }
  };

  saveCandidates();

  console.log('Yeni aday kaydı:', code, candidates[code]);

  return res.json({
    message: 'Aday başarıyla oluşturuldu. Önceki KADİS kodlarınız geçersiz hale getirildi.',
    code,
    expiresAt           // front-end'e de bildiriyoruz
  });
});

// Aday SGK Hizmet Dökümü yükleme & analiz
app.post('/api/candidates/sgk-upload', authMiddleware, uploadSgk.single('sgkPdf'), async (req, res) => {
  try {
    if (req.user.role !== 'candidate') {
      return res.status(403).json({ message: 'Bu işlemi sadece aday rolü yapabilir.' });
    }

    if (!req.file) {
      return res.status(400).json({ message: 'SGK hizmet dökümü PDF dosyası gereklidir.' });
    }

    const filePath = req.file.path;
    const ownerEmail = req.user.email;

    // Son (aktif) aday kaydını bul
    const activeCodes = Object.entries(candidates)
      .filter(([code, cand]) => cand.ownerEmail === ownerEmail && !cand.isArchived)
      .sort((a, b) => (a[1].createdAt < b[1].createdAt ? 1 : -1));

    if (activeCodes.length === 0) {
      return res.status(404).json({ message: 'Önce bir KADİS aday kaydı oluşturmanız gerekiyor.' });
    }

    const [code, cand] = activeCodes[0];

    // PDF analizini yap
    const analysis = await analyzeSgkPdf(filePath);

    // Aday kaydını güncelle
    cand.sgkVerification = {
      status: analysis.status,
      score: analysis.score,
      filePath: filePath.replace(__dirname, ''),
      parsed: analysis.parsed,
      checkedAt: new Date().toISOString(),
      notes: analysis.notes
    };

    // Eğer doğrulandıysa, parsed verileri profile da yaz
    if (analysis.status === 'verified') {
      if (analysis.parsed.totalPrimDays) {
        cand.totalPrimDays = analysis.parsed.totalPrimDays;
      }
      if (analysis.parsed.lastCompany) {
        cand.lastCompany = analysis.parsed.lastCompany;
      }
    }

    saveCandidates();

    return res.json({
      message: 'SGK hizmet dökümü analiz edildi.',
      code,
      sgkVerification: cand.sgkVerification
    });

  } catch (err) {
    console.error('SGK upload / analiz hatası:', err);
    return res.status(500).json({ message: 'SGK dosyası analiz edilirken hata oluştu.' });
  }
});

// ---- Kod ile aday sorgulama (sadece employer) ----
app.get('/api/candidates/:code', authMiddleware, (req, res) => {
  if (req.user.role !== 'employer') {
    return res.status(403).json({ message: 'Sadece işveren rolü aday sorgulayabilir.' });
  }

  const { code } = req.params;
  const upperCode = code.toUpperCase();

  const candidate = candidates[upperCode];

  if (!candidate) {
    return res.status(404).json({ message: 'Bu KADİS koduna ait aday bulunamadı.' });
  }

  // Önce arşiv kontrolü
  if (candidate.isArchived) {
    return res.status(410).json({
      message: 'Bu KADİS kodunun geçerliliği sona ermiştir (yeni bir kod oluşturulmuş). Lütfen adaydan güncel bir KADİS kodu isteyin.'
    });
  }

  // Sonra süre kontrolü (7 gün)
  if (candidate.expiresAt) {
    const now = new Date();
    const exp = new Date(candidate.expiresAt);
    if (exp < now) {
      return res.status(410).json({
        message: `Bu KADİS kodunun süresi dolmuştur (geçerlilik bitişi: ${candidate.expiresAt}). Lütfen adaydan yeni bir KADİS kodu isteyin.`
      });
    }
  }

  queries.push({
    employerEmail: req.user.email,
    code: upperCode,
    candidateFullName: candidate.fullName,
    lookedAtAt: new Date().toISOString()
  });
  saveQueries();

  return res.json(candidate);
});

// ---- Adayın kendi aktif kayıtları ----
app.get('/api/my-candidates', authMiddleware, (req, res) => {
  if (req.user.role !== 'candidate') {
    return res.status(403).json({ message: 'Sadece aday rolü bu listeyi görebilir.' });
  }

  const list = Object.entries(candidates)
    .filter(([code, cand]) => cand.ownerEmail === req.user.email && !cand.isArchived)
    .map(([code, cand]) => ({
      code,
      fullName: cand.fullName,
      email: cand.email,
      position: cand.position,
      totalPrimDays: cand.totalPrimDays || '',
      lastCompany: cand.lastCompany || '',
      createdAt: cand.createdAt,
      expiresAt: cand.expiresAt || null
    }))
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));

  return res.json(list);
});

// ---- İşverenin kendi sorgu geçmişi ----
app.get('/api/my-queries', authMiddleware, (req, res) => {
  if (req.user.role !== 'employer') {
    return res.status(403).json({ message: 'Sadece işveren rolü bu listeyi görebilir.' });
  }

  const list = queries
    .filter(q => q.employerEmail === req.user.email)
    .sort((a, b) => (a.lookedAtAt < b.lookedAtAt ? 1 : -1));

  return res.json(list);
});

// ===================
//  ADMIN ENDPOINTLERİ
// ===================
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Bu işlemi sadece admin yapabilir.' });
  }
  next();
}

app.get('/api/admin/overview', authMiddleware, requireAdmin, (req, res) => {
  const totalCandidates = Object.keys(candidates).length;
  const activeCandidates = Object.values(candidates).filter(c => !c.isArchived).length;
  const archivedCandidates = totalCandidates - activeCandidates;

  const usersByRole = { candidate: 0, employer: 0, admin: 0 };
  Object.values(users).forEach(u => {
    if (u.role === 'candidate') usersByRole.candidate++;
    else if (u.role === 'employer') usersByRole.employer++;
    else if (u.role === 'admin') usersByRole.admin++;
  });

  res.json({
    totalCandidates,
    activeCandidates,
    archivedCandidates,
    usersByRole,
    totalQueries: queries.length
  });
});

app.get('/api/admin/candidates', authMiddleware, requireAdmin, (req, res) => {
  const list = Object.entries(candidates)
    .map(([code, cand]) => ({
      code,
      ...cand
    }))
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  res.json(list);
});

app.get('/api/admin/users', authMiddleware, requireAdmin, (req, res) => {
  const list = Object.values(users)
    .map(u => ({
      email: u.email,
      role: u.role,
      createdAt: u.createdAt
    }))
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
  res.json(list);
});

app.get('/api/admin/queries', authMiddleware, requireAdmin, (req, res) => {
  const list = queries
    .slice()
    .sort((a, b) => (a.lookedAtAt < b.lookedAtAt ? 1 : -1));
  res.json(list);
});

// ---- Sunucuyu başlat ----
app.listen(PORT, () => {
  console.log(`Sunucu çalışıyor: http://localhost:${PORT}`);
});
