#!/usr/bin/env node
/**
 * Şifreleri sıfırla - Bu scripti çalıştır, sonra sunucuyu yeniden başlat.
 * npm start çalışırken ÖNCE sunucuyu durdur (Ctrl+C), sonra: node sifre-sifirla.js
 * Ardından: npm start
 */
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');

const DB_PATH = path.join(__dirname, 'data', 'db.json');
const db = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));

// quartz=1410, diğerleri=123
const passwords = { quartz: '1410', lowen: '123', mor: '123', cardcins: '123', testo: '123', axentra: '123' };

db.users.forEach(u => {
  const pass = passwords[u.username.toLowerCase()] || '123';
  u.passwordHash = bcrypt.hashSync(pass, 10);
  delete u.passwordPlain;
});

fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
console.log('✓ Şifreler sıfırlandı!');
console.log('  quartz → 1410');
console.log('  lowen, mor, cardcins, testo → 123');
console.log('');
console.log('Şimdi sunucuyu başlat: npm start');
