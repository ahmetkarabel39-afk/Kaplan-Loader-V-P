@echo off
title Dosya Tamir Edici
cls
echo [BILGI] Eksik 'package.json' dosyasi olusturuluyor...

(
echo {
echo   "name": "key-panel",
echo   "version": "0.1.0",
echo   "private": true,
echo   "main": "server.js",
echo   "scripts": {
echo     "start": "node server.js",
echo     "reset": "node sifre-sifirla.js"
echo   },
echo   "dependencies": {
echo     "bcryptjs": "^2.4.3",
echo     "cors": "^2.8.5",
echo     "express": "^4.18.2",
echo     "jsonwebtoken": "^9.0.0",
echo     "uuid": "^9.0.0"
echo   }
echo }
) > package.json

echo.
echo [BASARILI] Dosya olusturuldu.
echo Simdi baslatma dosyasini (siteyi-ac.bat veya baslat.bat) tekrar calistirabilirsin.
echo.
pause