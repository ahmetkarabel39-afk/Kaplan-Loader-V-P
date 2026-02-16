# Key Panel (test)

Basit test paneli — kurucu kullanıcıları ve key üretimi gösterir.

Başlamak için:

```powershell
cd C:\Users\Deniz\hile\workspace\key-panel
npm install
npm start

# sonra tarayıcıda http://localhost:3000 aç
```

Test kullanıcıları:
- kullanıcı: `kurucu` şifre: `kurucu123` (display: @QUARTZ)
- kullanıcı: `kurucu2` şifre: `kurucu123` (display: @CARDCINS)
Test kullanıcıları:
- kullanıcı: `QUARTZ` şifre: `1234` (display: @QUARTZ)
- kullanıcı: `CARDCINS` şifre: `1234` (display: @CARDCINS)

Notlar:
- İlk çalıştırmada `data/db.json` içindeki `passwordPlain` alanları sunucu tarafından hashlenip saklanır.
- Founder (`founder`) rolü tüm yetkilere sahiptir. `founder` yeni kullanıcı ekleyebilir ve maksimum süreyi değiştirebilir.

## Yayına Alma (Deployment)

### 🌍 DÜNYAYA AÇILMA (Herkese Açık Link)

Bu panel `db.json` dosyasını veritabanı olarak kullandığı için, verilerin silinmemesi adına **kendi bilgisayarınızda** çalıştırıp `ngrok` ile dışarı açmanız en iyi yöntemdir.

**Adım 1: Sunucuyu Başlatın**
- Klasördeki `baslat.bat` dosyasına çift tıklayın.

**Adım 2: Link Oluşturun**
- Yeni bir terminal (CMD veya PowerShell) açın.
- Şu komutu yapıştırıp Enter'a basın:
  ```powershell
  npx ngrok http 3000
  ```
- Ekranda çıkan `Forwarding` karşısındaki `https://....ngrok-free.app` linkini kopyalayın.
- **Bu linki kime atarsanız atın, panelinize girebilir!** (Bilgisayarınız açık olduğu sürece).
