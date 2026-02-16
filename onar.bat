@echo off
title Key Panel Tamir Araci
color 0e
cls
echo ==========================================
echo   KEY PANEL - HATA DUZELTME VE KURULUM
echo ==========================================
echo.
echo 1. Eski moduller temizleniyor...
if exist node_modules rmdir /s /q node_modules
if exist package-lock.json del /f /q package-lock.json

echo.
echo 2. NPM onbellegi temizleniyor...
call npm cache clean --force

echo.
echo 3. Moduller sifirdan yukleniyor (Bu biraz surebilir)...
call npm install

echo.
echo ==========================================
echo   ISLEM TAMAMLANDI!
echo ==========================================
echo.
echo Lutfen simdi 'baslat.bat' dosyasini tekrar calistir.
echo.
pause