const express = require('express');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const DB_PATH = path.join(__dirname, 'data', 'db.json');
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_please_change';

// Database - her istekte dosyadan oku (güncellemeler anında yansısın)
let memoryDB = null;
let fileWriteFailed = false; // Dosya yazma hatası kontrolü (Hostingler için)

function loadDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    return JSON.parse(raw);
  } catch (e) {
    console.error('[DB] Error reading db.json:', e.message);
    return { users: [], keys: [], logs: [], config: { maxDays: 30, cheatStatus: 'SAFE', announcement: 'Sisteme Hoşgeldiniz!' } };
  }
}

function readDB() {
  // YAYINDA HATA DÜZELTMESİ: Disk yerine her zaman RAM'deki güncel veriyi kullan.
  // Bu sayede oluşturulan kullanıcılar anında silinmez.
  if (memoryDB) return memoryDB;

  memoryDB = loadDB();
  // Config objesi yoksa varsayılanları ata (Hata önleyici)
  if (!memoryDB.config) memoryDB.config = { maxDays: 30, cheatStatus: 'SAFE', maxKeyCount: 100 };
  if (!memoryDB.logs) memoryDB.logs = [];
  if (!memoryDB.config.announcement) memoryDB.config.announcement = 'Sisteme Hoşgeldiniz!';
  if (!memoryDB.securityAlerts) memoryDB.securityAlerts = []; // Quartz için özel uyarılar
  return memoryDB;
}

function filterKeysForUser(db, username, userRole) {
  // Kurucular HERŞEYİ görür, diğerleri sadece kendi oluşturduklarını
  if (userRole === 'founder') return db.keys;
  return db.keys.filter(k => (k.createdBy || '').toLowerCase() === (username || '').toLowerCase());
}

function findUser(db, username){
  if (!username) return null;
  const q = username.toLowerCase().trim();
  return db.users.find(u => (u.username||'').toLowerCase().trim() === q);
}

function getUserLoginTime(userRole) {
  // Login session duration for each role (in hours)
  // founders: 24h, admins: 12h, managers: 8h
  switch(userRole) {
    case 'founder': return 24 * 60 * 60; // 24 hours
    case 'admin': return 12 * 60 * 60;  // 12 hours
    case 'manager': return 8 * 60 * 60; // 8 hours
    default: return 12 * 60 * 60; // 12 hours default
  }
}

function writeDB(db) {
  memoryDB = db;
  // Try to write to file (works on local, may fail on Vercel)
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
    console.log('[DB] Saved to file');
    fileWriteFailed = false;
  } catch (e) {
    console.log('[DB] File write unsupported (Vercel env), using memory only:', e.message);
    fileWriteFailed = true;
  }
}

function ensureHashes() {
  const db = readDB();
  let changed = false;
  
  // --- YAYINDA ŞİFRE SORUNU ÇÖZÜMÜ ---
  // Quartz kullanıcısının şifresini zorla "1410" yap (db.json güncellenmediyse diye)
  const quartz = findUser(db, 'quartz');
  if (quartz) {
    // Eğer şifre 1410 değilse güncelle
    if (!bcrypt.compareSync('1410', quartz.passwordHash)) {
      quartz.passwordHash = bcrypt.hashSync('1410', 10);
      changed = true;
      console.log('[AUTO-FIX] Quartz şifresi "1410" olarak sabitlendi.');
    }
  }

  // Axentra ve Cardcins kullanıcılarını oluştur veya şifrelerini 123 yap
  ['Axentra', 'Cardcins'].forEach(name => {
    let u = findUser(db, name);
    if (!u) {
      u = { id: uuidv4(), username: name, role: 'founder', displayName: `${name} (Kurucu)`, passwordHash: bcrypt.hashSync('123', 10) };
      db.users.push(u);
      changed = true;
      console.log(`[AUTO-FIX] ${name} kullanıcısı oluşturuldu (Şifre: 123).`);
    } else if (!bcrypt.compareSync('123', u.passwordHash)) {
      u.passwordHash = bcrypt.hashSync('123', 10);
      changed = true;
      console.log(`[AUTO-FIX] ${name} şifresi "123" olarak sabitlendi.`);
    }
  });
  // ------------------------------------

  db.users.forEach(u => {
    // passwordPlain varsa hashle (şifre sıfırlama için)
    if (u.passwordPlain) {
      u.passwordHash = bcrypt.hashSync(u.passwordPlain, 10);
      delete u.passwordPlain;
      changed = true;
    } else if (!u.passwordHash) {
      u.passwordHash = bcrypt.hashSync('123', 10); // varsayılan
      changed = true;
    }
  });
  if (changed) writeDB(db);
}

ensureHashes();

// Eski keylere createdByRole ekle (yoksa)
function ensureKeyCreatorRoles() {
  const db = readDB();
  let changed = false;
  db.keys.forEach(k => {
    if (!k.createdByRole && k.createdBy) {
      const creator = findUser(db, k.createdBy);
      k.createdByRole = creator ? (creator.role === 'admin' ? 'Admin' : creator.role === 'manager' ? 'Yönetici' : 'Kurucu') : 'Bilinmiyor';
      changed = true;
    }
  });
  if (changed) writeDB(db);
}
ensureKeyCreatorRoles();

// Loglama Yardımcı Fonksiyonu
function logAction(db, username, action, details) {
  if (!db.logs) db.logs = [];
  const log = { id: uuidv4(), timestamp: Date.now(), username, action, details };
  db.logs.unshift(log); // En başa ekle
  if (db.logs.length > 200) db.logs = db.logs.slice(0, 200); // Son 200 logu tut
  // writeDB burada çağrılmaz, çağıran fonksiyon kaydeder
}

// GÜVENLİK KONTROLÜ: Quartz Harici Kurucular İçin Limit
function checkFounderSafety(db, user, daysRequested) {
  // Quartz ise limit yok
  if (user.username.toLowerCase() === 'quartz') return { safe: true };

  // Limit 365 gün (Key oluşturma limiti)
  if (daysRequested <= 365) return { safe: true };

  // Limit aşıldı, uyarı ver
  user.warnings = (user.warnings || 0) + 1;
  
  if (user.warnings >= 3) {
    // 3. Uyarı: BAN
    const newPass = uuidv4().substring(0, 12);
    user.passwordHash = bcrypt.hashSync(newPass, 10);
    user.warnings = 0; // Resetle ki döngüye girmesin (zaten giremez şifre değişti)
    
    if (!db.securityAlerts) db.securityAlerts = [];
    db.securityAlerts.unshift({
      id: uuidv4(),
      targetUser: user.username,
      newPassword: newPass,
      reason: `YETKİ AŞIMI (3. İHLAL): ${daysRequested} gün işlem yapmaya çalıştı.`,
      timestamp: Date.now()
    });
    return { safe: false, banned: true };
  }

  return { safe: false, banned: false, warningCount: user.warnings };
}

// GÜVENLİK KONTROLÜ: Quartz Harici Kurucular İçin Kullanıcı Limiti (Admin/Yönetici atarken)
function checkFounderUserLimitSafety(db, user, valueRequested, type) {
  // Quartz ise limit yok
  if (user.username.toLowerCase() === 'quartz') return { safe: true };

  // Kullanıcıya verilebilecek maksimum süre/adet: 30
  if (valueRequested <= 30) return { safe: true };

  // Limit aşıldı, uyarı ver
  user.warnings = (user.warnings || 0) + 1;
  
  if (user.warnings >= 3) {
    // 3. Uyarı: BAN
    const newPass = uuidv4().substring(0, 12);
    user.passwordHash = bcrypt.hashSync(newPass, 10);
    user.warnings = 0;
    
    if (!db.securityAlerts) db.securityAlerts = [];
    db.securityAlerts.unshift({
      id: uuidv4(),
      targetUser: user.username,
      newPassword: newPass,
      reason: `YETKİ AŞIMI (KULLANICI LİMİTİ): ${valueRequested} ${type} yetki vermeye çalıştı.`,
      timestamp: Date.now()
    });
    return { safe: false, banned: true };
  }

  return { safe: false, banned: false, warningCount: user.warnings };
}

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true })); // C++ Loaderlar için form-data desteği

app.use(express.static(path.join(__dirname, 'public')));

function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'Unauthorized' });
  const parts = auth.split(' ');
  if (parts.length !== 2) return res.status(401).json({ error: 'Unauthorized' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Debug: sunucunun okuduğu DB'yi kontrol et
app.get('/api/debug-db', (req, res) => {
  const db = readDB();
  res.json({
    dbPath: DB_PATH,
    userCount: db.users.length,
    usernames: db.users.map(u => u.username),
    quartzExists: !!findUser(db, 'quartz'),
  });
});

app.post('/api/login', (req, res) => {
  const username = req.body && (req.body.username || '').trim();
  const password = req.body && req.body.password ? req.body.password.toString().trim() : '';
  if (!username || !password) {
    return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli' });
  }
  console.log('[LOGIN] Attempting login with username:', username);
  const db = readDB();
  const user = findUser(db, username);
  if (!user) {
    console.log('[LOGIN] User not found:', username, '| Users:', db.users.map(u => u.username));
    return res.status(400).json({ error: 'Geçersiz kullanıcı veya şifre' });
  }
  if (!user.passwordHash) {
    console.log('[LOGIN] User has no passwordHash!');
    return res.status(400).json({ error: 'Geçersiz kullanıcı veya şifre' });
  }
  const passwordMatch = bcrypt.compareSync(password, user.passwordHash);
  console.log('[LOGIN] Password match for', username, ':', passwordMatch);
  if (!passwordMatch) {
    // Şifre yanlışsa loga yaz
    console.log('[LOGIN] Invalid password for', username);
    return res.status(400).json({ error: 'Geçersiz kullanıcı veya şifre' });
  }

  // Hesap Süresi Kontrolü (Account Expiry Check)
  if (user.accountExpiresAt && Date.now() > user.accountExpiresAt) {
    console.log('[LOGIN] Account expired for', username);
    return res.status(403).json({ error: 'Hesap süreniz dolmuştur. Lütfen yönetici ile iletişime geçin.' });
  }
  
  // Bakım Modu Kontrolü
  if (db.config.maintenance && user.role !== 'founder') {
    console.log('[LOGIN] Maintenance block for', username);
    return res.status(503).json({ error: 'Sistem şu anda bakımda. Lütfen daha sonra tekrar deneyin.' });
  }

  const loginDuration = getUserLoginTime(user.role);
  const tokenPayload = { id: user.id, username: user.username, role: user.role, loginDuration, canRevoke: !!user.canRevoke, maxDays: user.maxDays || null, maxKeys: user.maxKeys || null };
  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: loginDuration });
  logAction(db, username, 'LOGIN', 'Kullanıcı giriş yaptı');
  writeDB(db);
  console.log('[LOGIN] Successful login for', username);
  res.json({ token, user: tokenPayload });
});

app.get('/api/config', authMiddleware, (req, res) => {
  const db = readDB();
  const config = db.config || {};
  res.json({ maxDays: config.maxDays, maxKeyCount: config.maxKeyCount || 100, cheatStatus: config.cheatStatus || 'SAFE', announcement: config.announcement, maintenance: !!config.maintenance });
});

// Mevcut kullanıcı bilgisi (token güncel olmasa bile DB'den alır)
app.get('/api/me', authMiddleware, (req, res) => {
  const db = readDB();
  const user = findUser(db, req.user.username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    username: user.username,
    role: user.role,
    canRevoke: !!user.canRevoke,
    maxDays: user.maxDays || null,
    maxKeys: user.maxKeys || null,
    warnings: user.warnings || 0
  });
});

app.post('/api/set-max-duration', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const { maxDays } = req.body;
  if (typeof maxDays !== 'number' || maxDays < 1 || maxDays > 365) return res.status(400).json({ error: 'maxDays must be number 1-365' });
  const db = readDB();
  db.config.maxDays = maxDays;
  if (!db.config.maxKeyCount) db.config.maxKeyCount = 100;
  writeDB(db);
  res.json({ ok: true, maxDays, maxKeyCount: db.config.maxKeyCount });
});

app.post('/api/update-user-max-days', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const { username, maxDays } = req.body;
  if (!username || typeof maxDays !== 'number' || maxDays < 1 || maxDays > 3650) 
    return res.status(400).json({ error: 'Invalid username or maxDays (1-3650)' });
  const db = readDB();
  const user = findUser(db, username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.role === 'founder') return res.status(403).json({ error: 'Cannot change founder maxDays' });
  
  // GÜVENLİK KONTROLÜ
  const requestingUser = findUser(db, req.user.username);
  const safety = checkFounderUserLimitSafety(db, requestingUser, maxDays, 'gün');
  if (!safety.safe) {
    writeDB(db); // Uyarıyı kaydet
    if (safety.banned) return res.status(403).json({ error: 'ILLEGAL_OPERATION', message: '3. İHLAL TESPİT EDİLDİ. HESABINIZA EL KONULDU.' });
    return res.status(400).json({ error: `Yetkinizi aşıyorsunuz! 3 denemede hesabınız bloke olup Quartz'a bildirilecektir. Uyarı: ${safety.warningCount}/3` });
  }

  user.maxDays = maxDays;
  writeDB(db);
  console.log('[UpdateMax]', username, 'maxDays set to', maxDays);
  res.json({ ok: true, username, maxDays });
});

app.post('/api/update-user-max-keys', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const { username, maxKeys } = req.body;
  if (!username || typeof maxKeys !== 'number' || maxKeys < 1 || maxKeys > 10000) 
    return res.status(400).json({ error: 'Invalid username or maxKeys (1-10000)' });
  const db = readDB();
  const user = findUser(db, username);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (user.role === 'founder') return res.status(403).json({ error: 'Cannot change founder maxKeys' });
  
  // GÜVENLİK KONTROLÜ (YENİ EKLENDİ)
  const requestingUser = findUser(db, req.user.username);
  const safety = checkFounderUserLimitSafety(db, requestingUser, maxKeys, 'adet');
  if (!safety.safe) {
    writeDB(db); // Uyarıyı kaydet
    if (safety.banned) return res.status(403).json({ error: 'ILLEGAL_OPERATION', message: '3. İHLAL TESPİT EDİLDİ. HESABINIZA EL KONULDU.' });
    return res.status(400).json({ error: `Yetkinizi aşıyorsunuz! 3 denemede hesabınız bloke olup Quartz'a bildirilecektir. Uyarı: ${safety.warningCount}/3` });
  }

  user.maxKeys = maxKeys;
  writeDB(db);
  console.log('[UpdateMaxKeys]', username, 'maxKeys set to', maxKeys);
  res.json({ ok: true, username, maxKeys });
});

app.post('/api/users', authMiddleware, (req, res) => {
  const creatorRole = req.user.role;
  if (creatorRole !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const { username, role, accountDuration } = req.body;
  const password = req.body.password ? req.body.password.toString().trim() : '';
  const canRevoke = !!req.body.canRevoke;
  const maxDays = req.body.maxDays !== undefined ? Number(req.body.maxDays) : undefined;
  const maxKeys = req.body.maxKeys !== undefined ? Number(req.body.maxKeys) : undefined;
  
  if (!username || !password || !role) return res.status(400).json({ error: 'Missing fields' });
  // Only allow creating 'admin' or 'manager' roles via UI (founders can remain special via manual seed)
  const allowedNewRoles = ['admin', 'manager'];
  // QUARTZ ÖZEL: Sadece Quartz 'founder' oluşturabilir
  const isQuartz = (req.user.username || '').trim().toLowerCase() === 'quartz';
  if (isQuartz) allowedNewRoles.push('founder');
  
  if (!allowedNewRoles.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  const db = readDB();
  
  // GÜVENLİK KONTROLÜ: Hesap Süresi (Quartz harici için)
  if (accountDuration) {
    const requestingUser = findUser(db, req.user.username);
    const safety = checkFounderUserLimitSafety(db, requestingUser, accountDuration, 'gün (hesap süresi)');
    if (!safety.safe) {
      writeDB(db);
      if (safety.banned) return res.status(403).json({ error: 'ILLEGAL_OPERATION', message: '3. İHLAL TESPİT EDİLDİ. HESABINIZA EL KONULDU.' });
      return res.status(400).json({ error: `Yetkinizi aşıyorsunuz! 3 denemede hesabınız bloke olup Quartz'a bildirilecektir. Uyarı: ${safety.warningCount}/3` });
    }
  }

  // GÜVENLİK KONTROLÜ: Yeni kullanıcı oluştururken maxDays limiti (Quartz harici için)
  if (maxDays) {
    const requestingUser = findUser(db, req.user.username);
    const safety = checkFounderUserLimitSafety(db, requestingUser, maxDays, 'gün');
    if (!safety.safe) {
      writeDB(db);
      if (safety.banned) return res.status(403).json({ error: 'ILLEGAL_OPERATION', message: '3. İHLAL TESPİT EDİLDİ. HESABINIZA EL KONULDU.' });
      return res.status(400).json({ error: `Yetkinizi aşıyorsunuz! 3 denemede hesabınız bloke olup Quartz'a bildirilecektir. Uyarı: ${safety.warningCount}/3` });
    }
  }

  // GÜVENLİK KONTROLÜ: Yeni kullanıcı oluştururken maxKeys limiti (Quartz harici için)
  if (maxKeys) {
    const requestingUser = findUser(db, req.user.username);
    const safety = checkFounderUserLimitSafety(db, requestingUser, maxKeys, 'adet');
    if (!safety.safe) {
      writeDB(db);
      if (safety.banned) return res.status(403).json({ error: 'ILLEGAL_OPERATION', message: '3. İHLAL TESPİT EDİLDİ. HESABINIZA EL KONULDU.' });
      return res.status(400).json({ error: `Yetkinizi aşıyorsunuz! 3 denemede hesabınız bloke olup Quartz'a bildirilecektir. Uyarı: ${safety.warningCount}/3` });
    }
  }

  const existingUser = findUser(db, username);
  if (existingUser) {
    // QUARTZ ÖZEL: Eğer kullanıcı zaten varsa ve Quartz işlem yapıyorsa, kullanıcıyı güncelle/sıfırla
    if (isQuartz) {
      if(password) existingUser.passwordHash = bcrypt.hashSync(password, 10);
      existingUser.role = role;
      const roleDisplay = role === 'founder' ? 'Kurucu' : (role === 'admin' ? 'Admin' : 'Yönetici');
      existingUser.displayName = `${username} (${roleDisplay})`;
      if (typeof maxDays === 'number') existingUser.maxDays = maxDays;
      if (typeof maxKeys === 'number') existingUser.maxKeys = maxKeys;
      if (typeof accountDuration === 'number') existingUser.accountExpiresAt = Date.now() + accountDuration * 24 * 60 * 60 * 1000;
      existingUser.warnings = 0; // Blokeyi/Uyarıları kaldır
      logAction(db, req.user.username, 'RESET_USER', `Kullanıcı sıfırlandı/güncellendi: ${username}`);
      writeDB(db);
      return res.json({ ok: true, message: 'Kullanıcı güncellendi.' });
    }
    return res.status(400).json({ error: 'User exists' });
  }

  const passwordHash = bcrypt.hashSync(password, 10);
  const id = uuidv4();
  const roleDisplay = role === 'founder' ? 'Kurucu' : (role === 'admin' ? 'Admin' : 'Yönetici');
  const newUser = { id, username, passwordHash, role, displayName: `${username} (${roleDisplay})` };
  if (typeof maxDays === 'number' && !Number.isNaN(maxDays) && maxDays >= 1 && maxDays <= 3650) newUser.maxDays = maxDays;
  if (typeof maxKeys === 'number' && !Number.isNaN(maxKeys) && maxKeys >= 1 && maxKeys <= 10000) newUser.maxKeys = maxKeys;
  if (typeof accountDuration === 'number' && accountDuration > 0) newUser.accountExpiresAt = Date.now() + accountDuration * 24 * 60 * 60 * 1000;
  // only allow setting canRevoke via founder when creating managers or admins
  if (role === 'manager' || role === 'admin') newUser.canRevoke = !!canRevoke;
  db.users.push(newUser);
  logAction(db, req.user.username, 'CREATE_USER', `Yeni kullanıcı oluşturuldu: ${username} (${role})`);
  writeDB(db);
  res.json({ ok: true });
});
  // list users (founder only)
  app.get('/api/users', authMiddleware, (req, res) => {
    if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
    const db = readDB();
    const users = db.users.map(u => ({ id: u.id, username: u.username, role: u.role, displayName: u.displayName, canRevoke: !!u.canRevoke, maxDays: u.maxDays || null, maxKeys: u.maxKeys || null }));
    res.json({ users });
  });

  // reset password for a user (founder only)
  app.post('/api/reset-password', authMiddleware, (req, res) => {
      const { username } = req.body;
      const newPassword = req.body.newPassword ? req.body.newPassword.toString().trim() : '';
      if (!username || !newPassword) return res.status(400).json({ error: 'Missing fields' });
      const db = readDB();
      const target = findUser(db, username);
      if (!target) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
      
      // only founders can perform resets
      if (req.user.role !== 'founder') return res.status(403).json({ error: 'Yetkiniz yok' });
      
      // Quartz check: Sadece Quartz diğer kurucuların şifresini değiştirebilir
      const isQuartz = req.user.username.toLowerCase() === 'quartz';
      if (target.role === 'founder' && !isQuartz) return res.status(403).json({ error: 'Kurucuların şifresi değiştirilemez' });
      
      target.passwordHash = bcrypt.hashSync(newPassword, 10);
      if (target.warnings) target.warnings = 0; // Uyarıları sıfırla (Blokeyi kaldır)
      
      logAction(db, req.user.username, 'RESET_PASS', `${username} şifresi sıfırlandı`);
      writeDB(db);
      return res.json({ ok: true });
  });

  // set revoke permission for a user (founder only)
  app.post('/api/set-revoke-permission', authMiddleware, (req, res) => {
    if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
    const { username, canRevoke } = req.body;
    if (!username || typeof canRevoke !== 'boolean') return res.status(400).json({ error: 'Missing or invalid fields' });
    const db = readDB();
    const user = findUser(db, username);
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    if (user.role === 'founder') return res.status(403).json({ error: 'Kurucuların yetkisi değiştirilemez' });
    user.canRevoke = canRevoke;
    writeDB(db);
    res.json({ ok: true, username: user.username, canRevoke: !!user.canRevoke });
  });

  // revoke (delete) a key (founder or admin)
  app.post('/api/revoke-key', authMiddleware, (req, res) => {
    // allow if founder OR admin OR manager with canRevoke
    const db = readDB();
    const requestingUser = findUser(db, req.user.username) || {};
    const allowed = (requestingUser.role === 'founder') || (requestingUser.role === 'admin') || (requestingUser.role === 'manager' && requestingUser.canRevoke);
    if (!allowed) return res.status(403).json({ error: 'Forbidden' });
    const { id } = req.body;
    if (!id) return res.status(400).json({ error: 'Missing id' });
    const idx = db.keys.findIndex(k => k.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Key not found' });
    db.keys.splice(idx, 1);
    logAction(db, req.user.username, 'REVOKE_KEY', `Key silindi/iptal edildi`);
    writeDB(db);
    res.json({ ok: true });
  });

  // delete a user (founder only, cannot delete founders)
  app.post('/api/delete-user', authMiddleware, (req, res) => {
    if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Missing username' });
    const db = readDB();
    const user = findUser(db, username);
    if (!user) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    if (user.role === 'founder') return res.status(403).json({ error: 'Kurucu hesapları silinemez' });
    db.users = db.users.filter(u=>u.id !== user.id);
    logAction(db, req.user.username, 'DELETE_USER', `Kullanıcı silindi: ${username}`);
    writeDB(db);
    res.json({ ok: true });
  });

app.post('/api/generate-key', authMiddleware, (req, res) => {
  const allowedRoles = ['founder', 'manager', 'admin'];
  if (!allowedRoles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  const { days, platform, maxDevices, note, prefix } = req.body;
  const count = Math.max(1, Math.min(50, Number(req.body.count) || 1)); // Min 1, Max 50
  const db = readDB();
  // determine per-user allowed maximum: founders unlimited, otherwise use user's maxDays if set, else global config
  const requestingUser = findUser(db, req.user.username) || {};
  const maxForUser = requestingUser.role === 'founder' ? 3650 : (typeof requestingUser.maxDays === 'number' && requestingUser.maxDays > 0 ? requestingUser.maxDays : (db.config.maxDays || 30));
  
  // --- ESKİ GÜVENLİK PROTOKOLÜ (Yedek) ---
  // Normal adminler için 365 gün sınırı
  if (req.user.role !== 'founder' && days > 365) {
    const newPass = uuidv4().substring(0, 12);
    requestingUser.passwordHash = bcrypt.hashSync(newPass, 10); // Şifreyi değiştir
    
    // Quartz için uyarı oluştur
    if (!db.securityAlerts) db.securityAlerts = [];
    db.securityAlerts.unshift({
      id: uuidv4(),
      targetUser: req.user.username,
      newPassword: newPass,
      reason: `YETKİ AŞIMI: ${days} günlük key üretmeye çalıştı.`,
      timestamp: Date.now()
    });
    
    logAction(db, 'SİSTEM', 'SECURITY_BAN', `${req.user.username} yetki aşımı yaptı. Şifresi değiştirildi.`);
    writeDB(db);
    return res.status(403).json({ error: 'ILLEGAL_OPERATION', message: 'YETKİ AŞIMI TESPİT EDİLDİ. HESABINIZA EL KONULDU.' });
  }

  // --- YENİ GÜVENLİK PROTOKOLÜ: QUARTZ HARİCİ KURUCULAR (365 GÜN) ---
  if (req.user.role === 'founder') {
    const safety = checkFounderSafety(db, requestingUser, days);
    if (!safety.safe) {
      writeDB(db);
      if (safety.banned) return res.status(403).json({ error: 'ILLEGAL_OPERATION', message: '3. İHLAL TESPİT EDİLDİ. HESABINIZA EL KONULDU.' });
      return res.status(400).json({ error: `Yetkinizi aşıyorsunuz! 3 denemede hesabınız bloke olup Quartz'a bildirilecektir. Uyarı: ${safety.warningCount}/3` });
    }
  }

  if (typeof days !== 'number' || days < 1 || days > maxForUser) {
    const source = (requestingUser.maxDays ? 'Kurucu' : 'Sistem');
    return res.status(400).json({ error: `${source} maksimum ${maxForUser} gün belirlemiş` });
  }
  
  // Check max key count per user
  const userKeysCount = db.keys.filter(k => k.createdBy === req.user.username).length;
  const maxKeysForUser = requestingUser.role === 'founder' ? 10000 : (typeof requestingUser.maxKeys === 'number' && requestingUser.maxKeys > 0 ? requestingUser.maxKeys : (db.config.maxKeyCount || 100));
  if (userKeysCount + count > maxKeysForUser) {
    return res.status(400).json({ error: `Limit aşımı! Kalan hakkınız: ${maxKeysForUser - userKeysCount}, İstenen: ${count}` });
  }
  
  const createdKeys = [];
  for (let i = 0; i < count; i++) {
    const rand = () => Math.random().toString(36).substring(2, 14).toUpperCase();
    const keyPrefix = (prefix && prefix.trim()) ? prefix.trim().toUpperCase() : 'KAPLANVIP';
    const key = `${keyPrefix}-${days}DAY-${rand()}`;
    const now = Date.now();
    const expiresAt = now + days * 24 * 60 * 60 * 1000;
    const creatorRole = requestingUser.role === 'admin' ? 'Admin' : (requestingUser.role === 'manager' ? 'Yönetici' : 'Kurucu');
    const entry = { id: uuidv4(), key, days, platform: platform || 'ANDROID', maxDevices: maxDevices || 1, hwid: null, note: note || '', createdBy: req.user.username, createdByRole: creatorRole, createdAt: now, expiresAt };
    db.keys.push(entry);
    createdKeys.push(entry);
  }
  
  logAction(db, req.user.username, 'GENERATE_KEY', `${count} adet ${days} günlük key oluşturuldu (${platform || 'ANDROID'})`);
  writeDB(db);
  res.json({ ok: true, keys: createdKeys });
});

// update current user's username/password
app.post('/api/update-me', authMiddleware, (req, res) => {
  // Sadece kurucular kendi profilini güncelleyebilir
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Bu işlem sadece kuruculara özeldir.' });

  const { newUsername, newPassword } = req.body;
  const db = readDB();
  const me = findUser(db, req.user.username);
  if (!me) return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
  if (newUsername){
    const exists = findUser(db, newUsername);
    if (exists && exists.id !== me.id) return res.status(400).json({ error: 'Kullanıcı adı zaten var' });
    me.username = newUsername;
  }
  if (newPassword){
    me.passwordHash = bcrypt.hashSync(newPassword.toString().trim(), 10);
  }
  logAction(db, req.user.username, 'UPDATE_PROFILE', `Profil güncellendi`);
  writeDB(db);
  const tokenPayload = { id: me.id, username: me.username, role: me.role, canRevoke: !!me.canRevoke, maxDays: me.maxDays || null, maxKeys: me.maxKeys || null };
  const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '12h' });
  res.json({ ok: true, token, user: tokenPayload });
});

app.get('/api/keys', authMiddleware, (req, res) => {
  const db = readDB();
  const filteredKeys = filterKeysForUser(db, req.user.username, req.user.role);
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.json({ keys: filteredKeys });
});

// --- YENİ ÖZELLİKLER: Sistem Yönetimi (Kurucu) ---

// İstatistikler
app.get('/api/admin/stats', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const db = readDB();
  const now = Date.now();
  const expiredCount = db.keys.filter(k => k.expiresAt < now).length;
  res.json({ expiredCount, totalKeys: db.keys.length, totalUsers: db.users.length });
});

// Key Notunu Güncelle
app.post('/api/update-key-note', authMiddleware, (req, res) => {
  const allowedRoles = ['founder', 'manager', 'admin'];
  if (!allowedRoles.includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  const { id, note } = req.body;
  if (!id) return res.status(400).json({ error: 'Missing id' });
  const db = readDB();
  const key = db.keys.find(k => k.id === id);
  if (!key) return res.status(404).json({ error: 'Key not found' });
  // Sadece kendi keyini düzenleyebilir (mevcut mantığa göre)
  if ((key.createdBy || '').toLowerCase() !== (req.user.username || '').toLowerCase()) return res.status(403).json({ error: 'Bu key size ait değil' });
  key.note = note || '';
  writeDB(db);
  res.json({ ok: true });
});

// Dashboard Grafiği ve Sistem Verileri
app.get('/api/admin/dashboard-data', authMiddleware, (req, res) => {
  if (!['founder', 'manager', 'admin'].includes(req.user.role)) return res.status(403).json({ error: 'Forbidden' });
  const db = readDB();
  
  // Son 7 günün grafiği
  const labels = [];
  const data = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dateStr = d.toISOString().split('T')[0]; // YYYY-MM-DD
    labels.push(dateStr);
    // O gün oluşturulan key sayısı
    const count = db.keys.filter(k => new Date(k.createdAt).toISOString().startsWith(dateStr)).length;
    data.push(count);
  }

  // Sistem Sağlığı
  const uptime = process.uptime(); // saniye cinsinden
  const memory = process.memoryUsage().rss / 1024 / 1024; // MB cinsinden

  res.json({ chart: { labels, data }, system: { uptime, memory: Math.round(memory) } });
});

// Süresi dolanları temizle
app.post('/api/clean-expired', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const db = readDB();
  const now = Date.now();
  const initial = db.keys.length;
  db.keys = db.keys.filter(k => k.expiresAt > now);
  const deleted = initial - db.keys.length;
  logAction(db, req.user.username, 'CLEAN_EXPIRED', `${deleted} adet süresi dolmuş key temizlendi`);
  writeDB(db);
  res.json({ ok: true, deleted });
});

// Hile Durumu Güncelle
app.post('/api/set-status', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const { status } = req.body;
  const db = readDB();
  if (!db.config) db.config = {};
  db.config.cheatStatus = status;
  logAction(db, req.user.username, 'STATUS_CHANGE', `Hile durumu değiştirildi: ${status}`);
  console.log('[Status] Updated to:', status);
  writeDB(db);
  res.json({ ok: true, status });
});

// Duyuru Güncelle
app.post('/api/set-announcement', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const { text } = req.body;
  const db = readDB();
  if (!db.config) db.config = {};
  db.config.announcement = text;
  writeDB(db);
  res.json({ ok: true, text });
});

// Bakım Modu Güncelle
app.post('/api/set-maintenance', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const { enabled } = req.body;
  const db = readDB();
  if (!db.config) db.config = {};
  db.config.maintenance = !!enabled;
  writeDB(db);
  res.json({ ok: true, maintenance: db.config.maintenance });
});

// Herkese Açık Durum Bilgisi (Login ekranı için)
app.get('/api/status', (req, res) => {
  const db = readDB();
  const config = db.config || {};
  res.json({ cheatStatus: config.cheatStatus || 'SAFE', announcement: config.announcement });
});

// API Bağlantı Testi (Tarayıcıdan girilince çalışıp çalışmadığını görmek için)
app.get('/connect', (req, res) => {
  res.send('Kaplan Loader VIP API Bağlantı Noktası Aktif. Loader yazılımınız bu adrese POST isteği atmalıdır.');
});

// --- HİLE YAZILIMI BAĞLANTI NOKTASI (CLIENT API) ---
app.post(['/api/client/login', '/connect'], (req, res) => {
  const { key, hwid } = req.body;
  // Basit validasyon
  if (!key || !hwid) return res.status(400).json({ success: false, message: 'Key ve HWID gerekli' });

  const db = readDB();
  const keyEntry = db.keys.find(k => k.key === key);

  if (!keyEntry) {
    console.log(`[CLIENT-API] Başarısız Giriş: Geçersiz Key (${key})`);
    return res.json({ success: false, message: 'Geçersiz Key' });
  }

  const now = Date.now();
  if (keyEntry.expiresAt < now) {
    console.log(`[CLIENT-API] Başarısız Giriş: Süresi Dolmuş (${key})`);
    return res.json({ success: false, message: 'Key süresi dolmuş' });
  }

  // HWID Kontrolü
  if (!keyEntry.hwid) {
    // İlk kullanım: HWID'yi kilitle
    keyEntry.hwid = hwid;
    writeDB(db);
  } else if (keyEntry.hwid !== hwid) {
    console.log(`[CLIENT-API] Başarısız Giriş: HWID Uyuşmazlığı (${key})`);
    return res.json({ success: false, message: 'Hatalı HWID! Bu key başka bir cihaza kilitli.' });
  }

  // Başarılı Giriş
  console.log(`[CLIENT-API] Başarılı Giriş: ${key} | HWID: ${hwid}`);
  logAction(db, 'CLIENT', 'CLIENT_LOGIN', `Key girişi: ${key}`);
  res.json({
    success: true,
    message: 'Giriş başarılı',
    expiresAt: keyEntry.expiresAt,
    daysLeft: Math.ceil((keyEntry.expiresAt - now) / (1000 * 60 * 60 * 24)),
    cheatStatus: db.config.cheatStatus || 'SAFE'
  });
});

// HWID Sıfırla
app.post('/api/reset-hwid', authMiddleware, (req, res) => {
  // Admin, Manager, Founder yapabilir
  const { id } = req.body;
  const db = readDB();
  const key = db.keys.find(k => k.id === id);
  if (!key) return res.status(404).json({ error: 'Key not found' });
  
  key.hwid = null; // HWID'yi null yaparak sıfırla
  logAction(db, req.user.username, 'RESET_HWID', `HWID sıfırlandı: ${key.key}`);
  writeDB(db);
  res.json({ ok: true });
});

// Logları Getir
app.get('/api/logs', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const db = readDB();
  res.json({ logs: db.logs || [] });
});

// --- GÜVENLİK UYARILARI (Tüm Kurucular) ---

app.get('/api/owner/alerts', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const db = readDB();
  res.json({ alerts: db.securityAlerts || [] });
});

app.post('/api/owner/dismiss-alert', authMiddleware, (req, res) => {
  if (req.user.role !== 'founder') return res.status(403).json({ error: 'Forbidden' });
  const { id } = req.body;
  const db = readDB();
  if (db.securityAlerts) {
    db.securityAlerts = db.securityAlerts.filter(a => a.id !== id);
    writeDB(db);
  }
  res.json({ ok: true });
});

// Health check endpoint 
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', server: 'running', time: new Date().toISOString() });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server listening on http://0.0.0.0:${PORT}`);
  console.log(`Access from this machine: http://localhost:${PORT}`);
});
