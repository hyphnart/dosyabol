# Dosya Böl — Yapımcı: Yaser Sayıcı

Bağımsız C++20/Qt6 uygulaması. Yalnızca dosya bölme, kayıpsız zlib sıkıştırma (0/1–9), JSON manifest, birleştirme ve SHA-256 doğrulama içerir. Gece/gündüz teması, iptal ve ilerleme çubuğu vardır. Debugger, analiz ve BinaryLab bağımlılıkları yoktur.

Kullanım: **Dosya Böl** sekmesinde dosya, çıkış klasörü, KiB/MiB/GiB cinsinden parça boyutu ve isteğe bağlı sıkıştırmayı seçin. **Birleştir / Doğrula** sekmesinde `.dbmanifest.json` dosyasını seçerek parçaları doğrulayın veya yeniden oluşturun. Manifest ve `.part000001` benzeri tüm parçaları birlikte saklayın.

Yeni `DOSYA-BOL-1` manifesti uygulamaya özgüdür; parçalar tek başına ZIP dosyası değildir. Eski BinaryLab manifestleriyle otomatik uyum iddiası yoktur. Sıkıştırılabilmeyen dosyaların boyutu artabilir. Var olan çıkış dosyalarının üzerine yazılmaz.

GitHub: tüm dosyaları repository köküne yükleyin → Actions → **Dosya Bol Windows EXE** → **Run workflow**. Testler geçerse artifact altında ZIP paketli Windows EXE oluşur.

Yerel: `cmake -S . -B build -DBUILD_TESTING=ON && cmake --build build && ctest --test-dir build --output-on-failure`.

Windows/MSVC derlemesi bu çalışma ortamında doğrulanmadı; GitHub Actions sonucu gerçek doğrulamadır.
