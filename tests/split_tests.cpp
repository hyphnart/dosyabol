#include "SplitEngine.h"
#include "common/dbcore.h"
#include <QCoreApplication>
#include <QDir>
#include <QDirIterator>
#include <QFile>
#include <QMap>
#include <QProcess>
#include <QRandomGenerator>
#include <QTemporaryDir>
#include <QDebug>
#include <atomic>

#ifndef DOSYABOL_STUB_PATH
#define DOSYABOL_STUB_PATH ""
#endif

static int g_fails = 0;
#define CHECK(cond) do { if(!(cond)) { qCritical("BAŞARISIZ satır %d: %s", __LINE__, #cond); ++g_fails; } } while(0)
#define CHECK_MSG(cond, msg) do { if(!(cond)) { qCritical("BAŞARISIZ satır %d: %s  [%s]", __LINE__, #cond, qPrintable(msg)); ++g_fails; } } while(0)

static QByteArray makeData(int size, int seed, bool compressible) {
    QRandomGenerator g{quint32(seed)};
    QByteArray b(size, 0);
    for (int i = 0; i < size; ++i) b[i] = compressible ? char('a' + (i / 7 + g.bounded(3)) % 5) : char(g.bounded(256));
    return b;
}
static bool writeFile(const QString &path, const QByteArray &data) {
    QDir().mkpath(QFileInfo(path).absolutePath());
    QFile f(path);
    return f.open(QIODevice::WriteOnly) && f.write(data) == data.size();
}
static QByteArray readFile(const QString &path) { QFile f(path); return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray("<yok>"); }

// Klasör ağacını {göreli yol -> içerik ("<dizin>" klasörler için)} olarak okur.
static QMap<QString, QByteArray> snapshot(const QString &root) {
    QMap<QString, QByteArray> m;
    QDirIterator it(root, QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden, QDirIterator::Subdirectories);
    const QDir base(root);
    while (it.hasNext()) {
        it.next();
        const QString rel = base.relativeFilePath(it.filePath());
        m[rel] = it.fileInfo().isDir() ? QByteArray("<dizin>") : readFile(it.filePath());
    }
    return m;
}
static QStringList partFiles(const QString &dir) {
    QStringList l = QDir(dir).entryList({"*.part*"}, QDir::Files, QDir::Name);
    l.erase(std::remove_if(l.begin(), l.end(), [](const QString &s) { return s.endsWith(".dbtmp"); }), l.end());
    return l;
}
static bool dirIsEmpty(const QString &dir) { return !QDir(dir).exists() || QDir(dir).entryList(QDir::AllEntries | QDir::NoDotAndDotDot | QDir::Hidden).isEmpty(); }

static std::atomic_bool cancelFlag{false};
static SplitEngine::Progress noProgress;

static bool packFile(const QString &src, const QString &out, qint64 part, int level, const QString &pw, QString &err,
                     bool copyDec = false, bool embed = false, bool every = false, QString *summary = nullptr) {
    PackOptions o;
    o.source = src; o.outFolder = out; o.partSize = part; o.compression = level; o.password = pw;
    o.copyDecoder = copyDec; o.embedDecoder = embed; o.embedEveryPart = every; o.decoderPath = DOSYABOL_STUB_PATH;
    cancelFlag = false;
    return SplitEngine::pack(o, noProgress, cancelFlag, err, summary);
}

static void testPrimitives() {
    auto hex = [](const dbol::Hash32 &h) { return QByteArray(reinterpret_cast<const char *>(h.data()), 32).toHex(); };
    dbol::Sha256 s; s.update("abc", 3);
    CHECK(hex(s.digest()) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const QByteArray key = "Jefe", msg = "what do ya want for nothing?";
    dbol::Hmac h(reinterpret_cast<const uint8_t *>(key.constData()), size_t(key.size()));
    h.update(msg.constData(), size_t(msg.size()));
    CHECK(hex(h.digest()) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");   // RFC 4231
    const dbol::Bytes dk = dbol::pbkdf2(reinterpret_cast<const uint8_t *>("password"), 8, reinterpret_cast<const uint8_t *>("salt"), 4, 1, 32);
    CHECK(QByteArray(reinterpret_cast<const char *>(dk.data()), 32).toHex() == "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    uint8_t key32[32];
    for (int i = 0; i < 32; ++i) key32[i] = uint8_t(i);
    const uint8_t nonce[12] = {0, 0, 0, 9, 0, 0, 0, 0x4a, 0, 0, 0, 0};
    uint8_t block[64] = {0};
    dbol::chacha20Xor(key32, nonce, 1, block, 64);
    CHECK(QByteArray(reinterpret_cast<const char *>(block), 16).toHex() == "10f1e7e4d13b5915500fdd1fa32071c4");  // RFC 8439 §2.3.2
    CHECK(dbol::safeRelPath("a/b/c.txt"));
    CHECK(dbol::safeRelPath("Türkçe/şğüı.txt"));
    CHECK(dbol::safeRelPath(".gizli"));
    CHECK(!dbol::safeRelPath("../x"));
    CHECK(!dbol::safeRelPath("a/../x"));
    CHECK(!dbol::safeRelPath("/etc/passwd"));
    CHECK(!dbol::safeRelPath("a\\b"));
    CHECK(!dbol::safeRelPath("C:/x"));
    CHECK(!dbol::safeRelPath("a//b"));
    CHECK(!dbol::safeRelPath("con.txt"));
    CHECK(!dbol::safeRelPath("x/ad."));
    CHECK(!dbol::safeRelPath(std::string("a\0b", 3)));
    CHECK(!dbol::safeRelPath("\xC0\xAF"));  // geçersiz UTF-8
}

static void testInflate() {
    dbol::Inflater inf;
    for (int kind = 0; kind < 3; ++kind)
        for (int level : {1, 6, 9}) {
            const QByteArray d = kind == 0 ? makeData(300000, 1, false) : kind == 1 ? makeData(300000, 2, true) : QByteArray(100000, '\0');
            const QByteArray z = qCompress(d, level).mid(4);
            QByteArray out(d.size(), 0);
            CHECK(inf.run(reinterpret_cast<const uint8_t *>(z.constData()), size_t(z.size()), reinterpret_cast<uint8_t *>(out.data()), size_t(out.size())));
            CHECK(out == d);
            QByteArray bad = z;
            bad[bad.size() / 2] = char(bad[bad.size() / 2] ^ 0x55);
            // bozuk akış ya reddedilmeli ya da (anlamsız bit denk geldiyse) aynı çıktıyı vermeli; asla farklı veri üretmemeli
            const bool accepted = inf.run(reinterpret_cast<const uint8_t *>(bad.constData()), size_t(bad.size()), reinterpret_cast<uint8_t *>(out.data()), size_t(out.size()));
            CHECK(!accepted || out == d);
        }
}

static void testLegacy(const QString &root) {
    const QString source = root + "/legacy.bin";
    QByteArray bytes(50000, 'A'); bytes.append("Hello world!\0binary", 19);
    CHECK(writeFile(source, bytes));
    QString err;
    for (int level : {0, 6, 9}) {
        const QString dir = root + QString("/legacy_parts%1").arg(level);
        CHECK_MSG(SplitEngine::split(source, dir, 4096, level, {}, cancelFlag, err), err);
        const QString manifest = dir + "/legacy.bin.dbmanifest.json";
        CHECK_MSG(SplitEngine::verify(manifest, {}, cancelFlag, err), err);
        const QString restored = root + QString("/legacy_joined%1").arg(level);
        CHECK_MSG(SplitEngine::join(manifest, restored, {}, cancelFlag, err), err);
        CHECK(readFile(restored + "/legacy.bin") == bytes);
        // Yeni API de eski manifesti tanımalı
        const QString viaNew = root + QString("/legacy_new%1").arg(level);
        CHECK_MSG(SplitEngine::unpack(manifest, viaNew, "", {}, cancelFlag, err), err);
        CHECK(readFile(viaNew + "/legacy.bin") == bytes);
    }
}

static void testFileRoundtrips(const QString &root) {
    const QByteArray data = makeData(150000, 3, true) + makeData(60000, 4, false);
    const QString src = root + "/src/payload.bin";
    CHECK(writeFile(src, data));
    QString err, summary;
    for (int level : {0, 1, 6, 9})
        for (const QString &pw : QStringList{QString(), QString("Gizli şifre 123 ğüş")}) {
            const QString out = root + QString("/f_%1_%2").arg(level).arg(pw.isEmpty() ? "plain" : "enc");
            CHECK_MSG(packFile(src, out, 20000, level, pw, err, false, false, false, &summary), err);
            const QStringList parts = partFiles(out);
            CHECK(parts.size() >= 3);
            for (int i = 0; i < parts.size(); ++i) {
                const qint64 sz = QFileInfo(out + "/" + parts[i]).size();
                CHECK(sz <= 20000);
                if (i + 1 < parts.size()) CHECK(sz == 20000);   // son parça hariç hepsi tam boyutta
            }
            const QString first = out + "/" + parts.first();
            const ArchiveSummary info = SplitEngine::inspect(first);
            CHECK(info.valid && info.complete && info.encrypted == !pw.isEmpty());
            bool need = false;
            const QString dst = out + "_restored";
            CHECK_MSG(SplitEngine::check(first, pw, noProgress, cancelFlag, err, nullptr, &need), err);
            // herhangi bir parçadan başlatılabilmeli: sonuncuyu seç
            CHECK_MSG(SplitEngine::unpack(out + "/" + parts.last(), dst, pw, noProgress, cancelFlag, err, &summary, &need), err);
            CHECK(readFile(dst + "/payload.bin") == data);
            // aynı yere tekrar açma: üzerine yazmamalı
            CHECK(!SplitEngine::unpack(first, dst, pw, noProgress, cancelFlag, err));
            CHECK(readFile(dst + "/payload.bin") == data);
        }
}

static void testPasswords(const QString &root) {
    const QByteArray data = makeData(90000, 5, true);
    const QString src = root + "/pw/secret.dat";
    CHECK(writeFile(src, data));
    QString err;
    const QString out = root + "/pw_out";
    CHECK_MSG(packFile(src, out, 16384, 6, "doğru", err), err);
    const QString first = out + "/" + partFiles(out).first();
    bool need = false;
    const QString dst = root + "/pw_dst";
    CHECK(!SplitEngine::unpack(first, dst, "yanlış", noProgress, cancelFlag, err, nullptr, &need));
    CHECK(need);
    CHECK(dirIsEmpty(dst));
    need = false;
    CHECK(!SplitEngine::unpack(first, dst, "", noProgress, cancelFlag, err, nullptr, &need));
    CHECK(need);
    CHECK(dirIsEmpty(dst));
    need = false;
    CHECK(!SplitEngine::check(first, "yanlış", noProgress, cancelFlag, err, nullptr, &need) && need);
    QString summary;
    CHECK_MSG(SplitEngine::check(first, "", noProgress, cancelFlag, err, &summary), err);   // yalnızca parça SHA-256
    CHECK(summary.contains("şifre girilmediği"));
    CHECK_MSG(SplitEngine::unpack(first, dst, "doğru", noProgress, cancelFlag, err), err);
    CHECK(readFile(dst + "/secret.dat") == data);
    // Şifreli dosyada düz metin ve dosya adı bulunmamalı
    const QByteArray raw = readFile(first);
    CHECK(!raw.contains(data.left(64)));
    CHECK(!raw.contains("secret.dat"));
}

static void testFolder(const QString &root) {
    const QString src = root + "/Proje Klasörü";
    QDir().mkpath(src + "/boş klasör");
    QDir().mkpath(src + "/alt/derin/daha derin");
    CHECK(writeFile(src + "/kök.txt", "kök dosyası"));
    CHECK(writeFile(src + "/boş.dat", ""));
    CHECK(writeFile(src + "/.gizli", "gizli dosya"));
    CHECK(writeFile(src + "/alt/Türkçe Ad şğüıöç.txt", makeData(30000, 6, true)));
    CHECK(writeFile(src + "/alt/derin/ikili.bin", makeData(70000, 7, false)));
    CHECK(writeFile(src + "/alt/derin/daha derin/küçük.txt", "x"));
    QString err, summary;
    for (const QString &pw : QStringList{QString(), QString("klasör şifresi")}) {
        const QString out = root + (pw.isEmpty() ? "/folder_plain" : "/folder_enc");
        CHECK_MSG(packFile(src, out, 12000, 6, pw, err, true, false, false, &summary), err);
        CHECK(QFileInfo::exists(out + "/" + QFileInfo(DOSYABOL_STUB_PATH).fileName()));
        const QString first = out + "/" + partFiles(out).first();
        const QString dst = out + "_restored";
        CHECK_MSG(SplitEngine::unpack(first, dst, pw, noProgress, cancelFlag, err, &summary), err);
        const QMap<QString, QByteArray> a = snapshot(src), b = snapshot(dst + "/Proje Klasörü");
        CHECK(a == b);
        CHECK(a.contains("boş klasör") && a.contains(".gizli") && a.contains("boş.dat"));
    }
    // Çıkış klasörü kaynağın içinde olamaz
    CHECK(!packFile(src, src + "/cikis", 12000, 6, "", err));
    CHECK(err.contains("içinde"));
}

static void testDamage(const QString &root) {
    const QByteArray data = makeData(120000, 8, false);
    const QString src = root + "/dmg/x.bin";
    CHECK(writeFile(src, data));
    QString err;
    for (const QString &pw : QStringList{QString(), QString("pw")}) {
        const QString out = root + (pw.isEmpty() ? "/dmg_plain" : "/dmg_enc");
        CHECK_MSG(packFile(src, out, 20000, 0, pw, err), err);
        const QStringList parts = partFiles(out);
        const QString first = out + "/" + parts.first();
        // 3. parçanın ortasında bir bayt boz
        {
            QFile f(out + "/" + parts[2]);
            CHECK(f.open(QIODevice::ReadWrite));
            f.seek(f.size() / 2);
            char c = 0;
            f.read(&c, 1);
            f.seek(f.size() / 2);
            c = char(c ^ 0x40);
            f.write(&c, 1);
        }
        CHECK(!SplitEngine::check(first, pw, noProgress, cancelFlag, err));
        CHECK_MSG(err.contains("3. parça"), err);
        const QString dst = out + "_restored";
        CHECK(!SplitEngine::unpack(first, dst, pw, noProgress, cancelFlag, err));
        CHECK_MSG(err.contains("3. parça"), err);
        CHECK(dirIsEmpty(dst));   // başarısız çıkarma hiçbir şey bırakmamalı
        // Şifre verilmeden de parça düzeyinde bozulma yakalanmalı
        CHECK(!SplitEngine::check(first, "", noProgress, cancelFlag, err));
    }
    // Eksik parça
    const QString out = root + "/missing";
    CHECK_MSG(packFile(src, out, 20000, 0, "", err), err);
    QStringList parts = partFiles(out);
    QFile::remove(out + "/" + parts[1]);
    const ArchiveSummary s = SplitEngine::inspect(out + "/" + parts.first());
    CHECK(s.valid && !s.complete && s.text.contains("2"));
    CHECK(!SplitEngine::unpack(out + "/" + parts.first(), root + "/missing_dst", "", noProgress, cancelFlag, err));
    CHECK(err.contains("Eksik"));
    // Son parça eksik
    const QString out2 = root + "/missing_last";
    CHECK_MSG(packFile(src, out2, 20000, 0, "", err), err);
    parts = partFiles(out2);
    QFile::remove(out2 + "/" + parts.last());
    CHECK(!SplitEngine::unpack(out2 + "/" + parts.first(), root + "/missing_last_dst", "", noProgress, cancelFlag, err));
    CHECK(dirIsEmpty(root + "/missing_last_dst"));
    // İptal: çıkış klasöründe artık dosya kalmamalı
    PackOptions o;
    o.source = src; o.outFolder = root + "/cancelled"; o.partSize = 20000; o.compression = 6; o.copyDecoder = false;
    cancelFlag = true;
    CHECK(!SplitEngine::pack(o, noProgress, cancelFlag, err));
    cancelFlag = false;
    CHECK(dirIsEmpty(root + "/cancelled"));
    // Parça boyutu çözücüden küçükse anlaşılır hata
    if (QFileInfo(DOSYABOL_STUB_PATH).isFile()) {
        CHECK(!packFile(src, root + "/toosmall", 4096, 6, "", err, false, true, false));
        CHECK(err.contains("çok küçük"));
    }
}

struct RunResult { int code; QString out; };
static RunResult runProcess(const QString &program, const QStringList &args, const QByteArray &stdinData) {
    QProcess p;
    p.setProgram(program); p.setArguments(args);
    p.start();
    if (!p.waitForStarted(10000)) return {-100, "başlatılamadı"};
    p.write(stdinData); p.closeWriteChannel();
    if (!p.waitForFinished(120000)) { p.kill(); return {-101, "zaman aşımı"}; }
    return {p.exitCode(), QString::fromUtf8(p.readAllStandardOutput())};
}

static void testDecoderExe(const QString &root) {
    const QString stub = DOSYABOL_STUB_PATH;
    if (!QFileInfo(stub).isFile()) { qWarning() << "Çözücü bulunamadı; exe testleri atlandı"; return; }
    const QByteArray data = makeData(260000, 9, true) + makeData(50000, 10, false);
    const QString src = root + "/exe/belge.bin";
    CHECK(writeFile(src, data));
    QString err;
    for (const QString &pw : QStringList{QString(), QString("exe şifresi")})
        for (int mode = 0; mode < 3; ++mode) {   // 0: yalnızca kopya, 1: ilk parçaya göm, 2: her parçaya göm
            const QString out = root + QString("/exe_%1_%2").arg(pw.isEmpty() ? "p" : "e").arg(mode);
            CHECK_MSG(packFile(src, out, mode >= 1 ? 150000 : 60000, 6, pw, err, true, mode >= 1, mode == 2), err);
            const QStringList parts = partFiles(out);
            CHECK(!parts.isEmpty());
            if (parts.isEmpty()) continue;
            for (int i = 0; i < parts.size(); ++i) CHECK(QFileInfo(out + "/" + parts[i]).size() <= (mode >= 1 ? 150000 : 60000));
            const QByteArray pwIn = pw.isEmpty() ? QByteArray() : (pw.toUtf8() + "\n");
            const QString decoderCopy = out + "/" + QFileInfo(stub).fileName();
            CHECK(QFileInfo(decoderCopy).isFile());
            // (a) klasördeki çözücü kopyası
            RunResult r = runProcess(decoderCopy, {"--cikis", out + "_a"}, pwIn);
            CHECK_MSG(r.code == 0, r.out);
            CHECK(readFile(out + "_a/belge.bin") == data);
            // (b) parçanın kendisi çalıştırılır (gömülü çözücü)
            if (mode >= 1) {
                CHECK(parts.first().endsWith(".exe"));
                CHECK(mode == 2 ? parts.last().endsWith(".exe") : !parts.last().endsWith(".exe"));
                const QString runner = out + "/" + (mode == 2 ? parts[parts.size() / 2] : parts.first());
                r = runProcess(runner, {"--cikis", out + "_b"}, pwIn);
                CHECK_MSG(r.code == 0, r.out);
                CHECK(readFile(out + "_b/belge.bin") == data);
                // gömülü parça, ana uygulama tarafından da geçerli parça olarak okunmalı
                bool need = false;
                CHECK_MSG(SplitEngine::unpack(runner, out + "_c", pw, noProgress, cancelFlag, err, nullptr, &need), err);
                CHECK(readFile(out + "_c/belge.bin") == data);
            }
            // (c) doğrulama modu
            r = runProcess(decoderCopy, {"--dogrula"}, pwIn);
            CHECK_MSG(r.code == 0, r.out);
            // (d) yanlış şifre, sonra doğru şifre
            if (!pw.isEmpty()) {
                r = runProcess(decoderCopy, {"--cikis", out + "_d"}, QByteArray("yanlış\n") + pwIn);
                CHECK_MSG(r.code == 0 && r.out.contains("Şifre yanlış"), r.out);
                CHECK(readFile(out + "_d/belge.bin") == data);
                r = runProcess(decoderCopy, {"--cikis", out + "_e"}, QByteArray("a\nb\nc\n"));
                CHECK(r.code != 0);
                CHECK(dirIsEmpty(out + "_e"));
            }
        }
    // Klasör arşivini çözücüyle aç
    const QString fsrc = root + "/exe_folder/Veri";
    CHECK(writeFile(fsrc + "/a/b.txt", "içerik"));
    CHECK(writeFile(fsrc + "/c.bin", makeData(80000, 11, false)));
    QDir().mkpath(fsrc + "/bos");
    const QString fout = root + "/exe_folder_out";
    CHECK_MSG(packFile(fsrc, fout, 150000, 6, "", err, true, true, true), err);
    if (partFiles(fout).isEmpty()) return;
    const RunResult r = runProcess(fout + "/" + partFiles(fout).first(), {"--cikis", fout + "_x"}, "");
    CHECK_MSG(r.code == 0, r.out);
    CHECK(snapshot(fsrc) == snapshot(fout + "_x/Veri"));
}

static void testEmptyAndTiny(const QString &root) {
    QString err;
    CHECK(writeFile(root + "/e/empty.bin", ""));
    CHECK_MSG(packFile(root + "/e/empty.bin", root + "/e_out", 4096, 6, "", err), err);
    CHECK(partFiles(root + "/e_out").size() == 1);
    CHECK_MSG(SplitEngine::unpack(root + "/e_out/" + partFiles(root + "/e_out").first(), root + "/e_dst", "", noProgress, cancelFlag, err), err);
    CHECK(QFileInfo(root + "/e_dst/empty.bin").size() == 0 && QFileInfo(root + "/e_dst/empty.bin").isFile());
    CHECK(writeFile(root + "/e/one.txt", "x"));
    CHECK_MSG(packFile(root + "/e/one.txt", root + "/e_out2", 1024 + 128, 9, "p", err), err);
    CHECK_MSG(SplitEngine::unpack(root + "/e_out2/" + partFiles(root + "/e_out2").first(), root + "/e_dst2", "p", noProgress, cancelFlag, err), err);
    CHECK(readFile(root + "/e_dst2/one.txt") == "x");
}

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    QTemporaryDir tmp;
    if (!tmp.isValid()) return 1;
    const QString root = tmp.path();
    testPrimitives();
    testInflate();
    testLegacy(root);
    testFileRoundtrips(root);
    testPasswords(root);
    testFolder(root);
    testDamage(root);
    testEmptyAndTiny(root);
    testDecoderExe(root);
    if (g_fails) { qCritical() << g_fails << "kontrol başarısız"; return 1; }
    qInfo() << "PASS: ilkeller, inflate, eski biçim, dosya/klasör, şifre, bozulma, eksik parça, çözücü exe";
    return 0;
}
