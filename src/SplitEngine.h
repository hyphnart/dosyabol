#pragma once
#include <QString>
#include <QStringList>
#include <functional>
#include <atomic>

// Yeni (DOSYA-BOL-2) bölme ayarları. Kaynak bir dosya veya klasör olabilir.
struct PackOptions {
    QString source;               // bölünecek dosya veya klasör
    QString outFolder;            // parçaların yazılacağı klasör
    qint64 partSize = 100LL * 1024 * 1024;  // en büyük parça dosyası boyutu (çözücü dahil)
    int compression = 6;          // 0 = sıkıştırma yok, 1-9 = zlib seviyesi
    QString password;             // boş = şifresiz; dolu = ChaCha20 + HMAC-SHA256
    bool copyDecoder = true;      // çözücü exe'yi çıkış klasörüne de kopyala
    bool embedDecoder = false;    // çözücü exe'yi parçaların başına göm
    bool embedEveryPart = false;  // true: her parçaya, false: yalnızca ilk parçaya
    QString decoderPath;          // boşsa uygulamanın yanındaki DosyaBolCozucu kullanılır
};

struct ArchiveSummary {
    bool valid = false;       // dosya tanındı
    bool legacy = false;      // eski manifest biçimi
    bool complete = false;    // tüm parçalar mevcut
    bool encrypted = false;
    QString text;             // kullanıcıya gösterilecek özet
};

class SplitEngine {
public:
    using Progress = std::function<void(qint64,qint64)>;

    // ---- Eski biçim (DOSYA-BOL-1, .dbmanifest.json): geriye dönük uyumluluk
    static bool split(const QString &source,const QString &folder,qint64 chunkSize,int compression,
                      const Progress &progress,std::atomic_bool &cancel,QString &error);
    static bool join(const QString &manifest,const QString &folder,const Progress &progress,
                     std::atomic_bool &cancel,QString &error);
    static bool verify(const QString &manifest,const Progress &progress,
                       std::atomic_bool &cancel,QString &error);

    // ---- Yeni biçim (DOSYA-BOL-2): dosya/klasör, şifre, gömülü çözücü
    static QString defaultDecoderPath();
    static bool pack(const PackOptions &options,const Progress &progress,std::atomic_bool &cancel,
                     QString &error,QString *summary=nullptr);
    // part: herhangi bir parça dosyası (veya eski .dbmanifest.json). needPassword: şifre eksik/yanlışsa true olur.
    static bool unpack(const QString &part,const QString &folder,const QString &password,const Progress &progress,
                       std::atomic_bool &cancel,QString &error,QString *summary=nullptr,bool *needPassword=nullptr);
    // Şifre verilmezse yalnızca parça SHA-256 değerleri; verilirse (veya şifresizse) tüm içerik doğrulanır.
    static bool check(const QString &part,const QString &password,const Progress &progress,
                      std::atomic_bool &cancel,QString &error,QString *summary=nullptr,bool *needPassword=nullptr);
    static ArchiveSummary inspect(const QString &part);
};
