# Dosya Böl — Yapımcı: Yaser Sayıcı

Bağımsız C++20/Qt6 uygulaması: dosya **veya klasör** bölme, kayıpsız zlib sıkıştırma (0/1–9), isteğe bağlı **şifreleme**, SHA-256 doğrulama, birleştirme ve **gömülebilir çözücü exe**. Gece/gündüz teması, iptal ve ilerleme çubuğu vardır.

## Neler var

- **Dosya veya klasör bölme.** Klasör bölünürken alt klasörler, boş klasörler, gizli dosyalar ve değişiklik tarihleri korunur. Sembolik bağlar atlanır (sayısı özette yazılır).
- **Şifreli / şifresiz bölme.** Şifre açıksa: PBKDF2-HMAC-SHA256 (200.000 tur) ile anahtar türetilir, her blok ChaCha20 ile şifrelenir ve HMAC-SHA256 ile doğrulanır. Dosya adları ve klasör yapısı da şifrelenir. Yanlış şifre veri yazılmadan hemen reddedilir.
- **Çözücü exe (`DosyaBolCozucu.exe`).** Qt gerektirmeyen küçük bağımsız programdır.
  - *Klasöre kopyala:* bölme bitince çıkış klasörüne çözücü de konur; parçalar ile aynı klasörde çift tıklanınca arşivi açar.
  - *Parçaların başına göm:* çözücü ilk parçanın veya her parçanın başına eklenir. Bu parçalar `.part000001.exe` adını alır ve çift tıklanınca kendi kendini açar. Parça boyutu sınırı çözücü dahil uygulanır.
- **Her parçadan açılır.** Arşivi bulmak için dosya adı değil parçanın içindeki kimlik kullanılır; parçalardan herhangi biri seçilebilir. Eksik parça numaraları açıkça bildirilir.
- **Güvenli çıkarma.** Var olan dosyaların üzerine yazılmaz; hata veya iptalde yarım dosya bırakılmaz; `..`, mutlak yol ve Windows'ta sorunlu adlar reddedilir. Bozulma olursa hangi parçanın bozuk olduğu söylenir.
- **Eski biçim.** Önceki sürümün `.dbmanifest.json` dosyaları hâlâ doğrulanabilir ve birleştirilebilir.

## Kullanım

**Böl** sekmesinde dosya veya klasörü, çıkış klasörünü, en büyük parça boyutunu seçin; isteğe bağlı sıkıştırma, şifre ve çözücü seçeneklerini ayarlayın.
**Birleştir / Doğrula** sekmesinde herhangi bir parçayı seçin; durum satırı kaç parça bulunduğunu ve şifreli olup olmadığını gösterir. Şifre girmeden doğrulama yalnızca parça SHA-256 değerlerini denetler.

Çözücü komut satırı: `DosyaBolCozucu [parça_veya_klasör] [--cikis klasör] [--dogrula]`. Parametresiz çift tıklanırsa kendi klasöründeki parçaları bulur, gerekirse şifre ve çıkış klasörünü sorar (varsayılan: `Cozulen`).

## Biçim özeti (DOSYA-BOL-2)

`[çözücü (ops.)] [başlık 64B] [dilim] [kuyruk 64B]`. Dilimler art arda eklenince blok akışı çıkar; bloklar (≤1 MiB) sıkıştırılır (kazanç varsa), şifrelenir ve etiketlenir. Akışın içinde dosya listesi, dosya verileri ve tüm verinin SHA-256 değeri bulunur. Kuyruk, parçanın kendi SHA-256 değerini ve "son parça" bayrağını taşır. Ortak okuyucu `src/common/dbcore.h` içindedir (uygulama ve çözücü aynı kodu kullanır).

## Derleme

GitHub: tüm dosyaları repository köküne yükleyin → Actions → **Dosya Bol Windows EXE** → **Run workflow**. Testler geçerse artifact altında `DosyaBol.exe` ve `DosyaBolCozucu.exe` içeren ZIP oluşur. İki exe **aynı klasörde** durmalıdır.

Yerel: `cmake -S . -B build -DBUILD_TESTING=ON && cmake --build build && ctest --test-dir build --output-on-failure`.

## Notlar

- Gömülü çözücülü `.exe` parçalar bazı antivirüs/SmartScreen sistemlerinde uyarı verebilir (kendi kendini açan arşivlerde yaygındır). Uyarı çıkarsa çözücüyü gömmeden, yalnızca klasöre kopyalama seçeneğini kullanın.
- Sıkıştırılmış ZIP/MP4/JPG dosyaları küçülmez; bu durumda bloklar ham saklanır, boyut yalnızca başlık kadar artar.
- Şifre kurtarılamaz. Şifreli arşivde bir blok bozulursa o blok açılmaz.
- Linux (g++/Qt 6.4) üzerinde tüm testler geçti. Windows/MSVC derlemesi bu çalışma ortamında doğrulanmadı; GitHub Actions sonucu gerçek doğrulamadır.
