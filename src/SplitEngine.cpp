#include "SplitEngine.h"
#include "common/dbcore.h"
#include <QCoreApplication>
#include <QDirIterator>
#include <QRandomGenerator>
#include <array>
#include <iterator>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QSaveFile>
#include <QCryptographicHash>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QSet>
#include <QStringList>
#include <QtEndian>
#include <algorithm>

namespace {
constexpr qint64 blockSize=1024*1024;
QString digest(QCryptographicHash &hash){return QString::fromLatin1(hash.result().toHex());}
bool writeAll(QIODevice &out,const QByteArray &b){return out.write(b)==b.size();}
bool safeFile(const QString &s){return !s.isEmpty() && s!="." && s!=".." && s==QFileInfo(s).fileName() && !s.contains('/') && !s.contains('\\');}
struct Metadata {QJsonObject root;QJsonArray parts;QString name;bool packed=false;qint64 total=0;};
bool readMetadata(const QString &path,Metadata &m,QString &err){
    QFile f(path);
    if(!f.open(QIODevice::ReadOnly)){err=f.errorString();return false;}
    if(f.size()>16*1024*1024){err="Manifest çok büyük.";return false;}
    QJsonParseError pe{};auto doc=QJsonDocument::fromJson(f.readAll(),&pe);
    if(pe.error!=QJsonParseError::NoError || !doc.isObject()){err="Manifest JSON geçersiz.";return false;}
    m.root=doc.object();const QString format=m.root.value("format").toString();
    if(format!="DOSYA-BOL-1"){err="Desteklenmeyen manifest biçimi.";return false;}
    m.packed=m.root.value("compression").toString()=="zlib-chunks";
    if(!m.packed && m.root.value("compression").toString()!="none"){err="Sıkıştırma türü desteklenmiyor.";return false;}
    m.name=m.root.value("fileName").toString();if(!safeFile(m.name)){err="Güvensiz dosya adı.";return false;}
    bool ok=false;m.total=m.root.value("fileSize").toString().toLongLong(&ok);
    if(!ok||m.total<0||!m.root.value("parts").isArray()){err="Manifest alanları geçersiz.";return false;}
    m.parts=m.root.value("parts").toArray();
    if(m.parts.size()>100000){err="Çok fazla parça.";return false;}
    return true;
}
bool processParts(const QString &manifest,QIODevice *destination,const SplitEngine::Progress &progress,
                  std::atomic_bool &cancel,QString &err){
    Metadata m;if(!readMetadata(manifest,m,err))return false;
    const QDir folder=QFileInfo(manifest).absoluteDir();
    QCryptographicHash whole(QCryptographicHash::Sha256);
    qint64 done=0;QSet<QString> used;
    for(const QJsonValue &v:m.parts){
        if(cancel.load()){err="İşlem iptal edildi.";return false;}
        if(!v.isObject()){err="Parça bilgisi geçersiz.";return false;}
        auto p=v.toObject();QString name=p.value("name").toString();
        if(!safeFile(name)||used.contains(name)){err="Geçersiz/tekrarlı parça adı.";return false;}
        used.insert(name);
        bool ok1=false,ok2=false;
        const qint64 stored=p.value("stored").toString().toLongLong(&ok1);
        const qint64 rawExpected=p.value("raw").toString().toLongLong(&ok2);
        if(!ok1||!ok2||stored<0||rawExpected<0||rawExpected>m.total-done){err="Parça boyutu geçersiz.";return false;}
        QFile f(folder.filePath(name));
        if(!f.open(QIODevice::ReadOnly)||f.size()!=stored){err="Eksik veya yanlış boyutlu parça: "+name;return false;}
        QCryptographicHash rawHash(QCryptographicHash::Sha256),storedHash(QCryptographicHash::Sha256);
        qint64 produced=0;
        while(!f.atEnd()){
            if(cancel.load()){err="İşlem iptal edildi.";return false;}
            QByteArray raw;
            if(m.packed){
                QByteArray header=f.read(4);
                if(header.size()!=4){err="Eksik blok başlığı.";return false;}
                const quint32 n=qFromLittleEndian<quint32>(reinterpret_cast<const uchar*>(header.constData()));
                if(n<6||n>blockSize+4096||n>static_cast<quint64>(f.bytesAvailable())){err="Sıkıştırılmış blok uzunluğu geçersiz.";return false;}
                QByteArray payload=f.read(n);
                if(payload.size()!=qsizetype(n)){err="Eksik sıkıştırılmış blok.";return false;}
                const quint32 expanded=qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(payload.constData()));
                if(expanded>blockSize || expanded>quint64(rawExpected-produced)){err="Blok açılım boyutu geçersiz.";return false;}
                raw=qUncompress(payload);
                if(raw.size()!=qsizetype(expanded)){err="Sıkıştırılmış blok bozuk.";return false;}
                storedHash.addData(header);storedHash.addData(payload);
            }else{
                raw=f.read(blockSize);
                if(raw.isEmpty()){err="Okuma başarısız.";return false;}
                storedHash.addData(raw);
            }
            if(raw.size()>rawExpected-produced){err="Parça ham boyut aşımı.";return false;}
            rawHash.addData(raw);whole.addData(raw);
            if(destination&&!writeAll(*destination,raw)){err="Çıkışa yazılamadı.";return false;}
            produced+=raw.size();done+=raw.size();
            if(progress)progress(done,m.total);
        }
        if(produced!=rawExpected || digest(rawHash).compare(p.value("sha256").toString(),Qt::CaseInsensitive)!=0 ||
           digest(storedHash).compare(p.value("storedSha256").toString(),Qt::CaseInsensitive)!=0){
            err="Parça SHA-256 eşleşmedi: "+name;return false;
        }
    }
    if(done!=m.total || digest(whole).compare(m.root.value("sha256").toString(),Qt::CaseInsensitive)!=0){
        err="Orijinal dosya SHA-256 eşleşmedi.";return false;
    }
    if(progress)progress(m.total,m.total);
    return true;
}
}
bool SplitEngine::split(const QString &source,const QString &folder,qint64 chunkSize,int compression,
                       const Progress &progress,std::atomic_bool &cancel,QString &error){
    if(chunkSize<1024 || compression<0 || compression>9){error="Parça boyutu veya sıkıştırma seviyesi geçersiz.";return false;}
    QFile in(source);if(!in.open(QIODevice::ReadOnly)){error=in.errorString();return false;}
    QDir dir(folder);if(!dir.exists()&&!QDir().mkpath(folder)){error="Çıkış klasörü oluşturulamadı.";return false;}
    const qint64 total=in.size();const QString base=QFileInfo(source).fileName();
    const QString manifestPath=dir.filePath(base+".dbmanifest.json");
    if(QFileInfo::exists(manifestPath)){error="Manifest zaten var; farklı klasör seçin.";return false;}
    const qint64 count=total?((total-1)/chunkSize+1):0;
    if(count>100000){error="100.000 parçadan fazlası desteklenmiyor.";return false;}
    for(qint64 i=1;i<=count;++i){
        QString name=QString("%1.part%2").arg(base).arg(i,6,10,QLatin1Char('0'));
        if(QFileInfo::exists(dir.filePath(name))){error="Parça zaten mevcut: "+name;return false;}
    }
    QStringList created;
    auto cleanup=[&]{for(const QString &p:created)QFile::remove(p);};
    QCryptographicHash whole(QCryptographicHash::Sha256);QJsonArray parts;
    qint64 done=0;
    for(qint64 i=1;i<=count;++i){
        if(cancel.load()){error="İşlem iptal edildi.";cleanup();return false;}
        const QString name=QString("%1.part%2").arg(base).arg(i,6,10,QLatin1Char('0'));
        const QString path=dir.filePath(name);
        QSaveFile out(path);
        if(!out.open(QIODevice::WriteOnly)){error=out.errorString();cleanup();return false;}
        QCryptographicHash rawHash(QCryptographicHash::Sha256),storedHash(QCryptographicHash::Sha256);
        qint64 rawCount=0,storedCount=0;
        const qint64 target=std::min(chunkSize,total-done);
        while(rawCount<target){
            if(cancel.load()){out.cancelWriting();error="İşlem iptal edildi.";cleanup();return false;}
            const QByteArray raw=in.read(std::min(blockSize,target-rawCount));
            if(raw.isEmpty()){out.cancelWriting();error="Kaynak okunamadı.";cleanup();return false;}
            QByteArray packet;
            if(compression){
                const QByteArray packed=qCompress(raw,compression);
                quint32 n=qToLittleEndian<quint32>(quint32(packed.size()));
                packet=QByteArray(reinterpret_cast<const char*>(&n),4)+packed;
            }else packet=raw;
            if(!writeAll(out,packet)){out.cancelWriting();error="Yazma hatası.";cleanup();return false;}
            rawHash.addData(raw);storedHash.addData(packet);whole.addData(raw);
            rawCount+=raw.size();storedCount+=packet.size();done+=raw.size();
            if(progress)progress(done,total);
        }
        if(!out.commit()){error="Parça kaydedilemedi.";cleanup();return false;}
        created<<path;
        QJsonObject row;row["name"]=name;row["raw"]=QString::number(rawCount);
        row["stored"]=QString::number(storedCount);row["sha256"]=digest(rawHash);
        row["storedSha256"]=digest(storedHash);parts.append(row);
    }
    QJsonObject root;
    root["format"]="DOSYA-BOL-1";root["fileName"]=base;
    root["fileSize"]=QString::number(total);root["partSize"]=QString::number(chunkSize);
    root["compression"]=compression?"zlib-chunks":"none";
    root["compressionLevel"]=compression;root["sha256"]=digest(whole);root["parts"]=parts;
    QSaveFile mf(manifestPath);
    if(!mf.open(QIODevice::WriteOnly)||!writeAll(mf,QJsonDocument(root).toJson(QJsonDocument::Indented))||!mf.commit()){
        error="Manifest yazılamadı.";cleanup();return false;
    }
    if(progress)progress(total,total);
    return true;
}
bool SplitEngine::join(const QString &manifest,const QString &folder,const Progress &progress,
                       std::atomic_bool &cancel,QString &error){
    Metadata m;if(!readMetadata(manifest,m,error))return false;
    QDir dir(folder);if(!dir.exists()&&!QDir().mkpath(folder)){error="Çıkış klasörü oluşturulamadı.";return false;}
    const QString path=dir.filePath(m.name);
    if(QFileInfo::exists(path)){error="Hedef dosya zaten var; başka klasör seçin.";return false;}
    QSaveFile output(path);if(!output.open(QIODevice::WriteOnly)){error=output.errorString();return false;}
    if(!processParts(manifest,&output,progress,cancel,error)){output.cancelWriting();return false;}
    if(!output.commit()){error="Dosya tamamlanamadı.";return false;}
    return true;
}
bool SplitEngine::verify(const QString &manifest,const Progress &progress,
                         std::atomic_bool &cancel,QString &error){return processParts(manifest,nullptr,progress,cancel,error);}

// =====================================================================================
//  DOSYA-BOL-2: dosya/klasör bölme, isteğe bağlı şifreleme, gömülebilir çözücü
// =====================================================================================
namespace v2 {
using dbol::Hash32;
using dbol::Id16;

dbol::fs::path toPath(const QString &q){return dbol::fromUtf8(QFileInfo(q).absoluteFilePath().toUtf8().toStdString());}
std::string utf8(const QString &q){return q.toUtf8().toStdString();}

struct FileEntry{QString abs;std::string rel;quint8 kind=1;quint64 size=0;qint64 mtime=0;};

bool walk(const QDir &dir,const std::string &prefix,std::vector<FileEntry> &out,int &skipped,
          QString &err,std::atomic_bool &cancel,int depth){
    if(depth>256){err="Klasör ağacı çok derin.";return false;}
    const QFileInfoList list=dir.entryInfoList(QDir::AllEntries|QDir::NoDotAndDotDot|QDir::Hidden|QDir::System,QDir::Name);
    for(const QFileInfo &fi:list){
        if(cancel.load()){err="İşlem iptal edildi.";return false;}
        if(fi.isSymbolicLink()||fi.isJunction()){++skipped;continue;}
        const std::string rel=prefix+"/"+utf8(fi.fileName());
        if(!fi.isDir()&&!fi.isFile()){++skipped;continue;}
        if(!dbol::safeRelPath(rel)){err="Arşivde desteklenmeyen dosya adı (Windows'ta geçersiz karakter, ayrılmış ad veya sonda nokta/boşluk): "+fi.absoluteFilePath();return false;}
        if(out.size()>=dbol::kMaxEntries){err="Çok fazla dosya (en fazla 2.000.000).";return false;}
        FileEntry e;e.abs=fi.absoluteFilePath();e.rel=rel;e.mtime=fi.lastModified().toSecsSinceEpoch();
        if(fi.isDir()){
            e.kind=2;out.push_back(e);
            if(!walk(QDir(fi.absoluteFilePath()),rel,out,skipped,err,cancel,depth+1))return false;
        }else{e.kind=1;e.size=quint64(fi.size());out.push_back(e);}
    }
    return true;
}

bool collect(const QString &source,std::vector<FileEntry> &out,int &skipped,QString &base,QString &err,std::atomic_bool &cancel){
    const QFileInfo si(source);
    if(si.isFile()){
        FileEntry e;e.abs=si.absoluteFilePath();e.rel=utf8(si.fileName());e.size=quint64(si.size());
        e.mtime=si.lastModified().toSecsSinceEpoch();base=si.fileName();
        if(!dbol::safeRelPath(e.rel)){err="Arşivde desteklenmeyen dosya adı: "+si.fileName();return false;}
        out.push_back(e);return true;
    }
    if(si.isDir()){
        const QDir root(si.absoluteFilePath());const QString name=root.dirName();
        if(name.isEmpty()||name=="."||name==".."){err="Sürücü/kök klasör bölünemez; bir alt klasör seçin.";return false;}
        base=name;const std::string rel=utf8(name);
        if(!dbol::safeRelPath(rel)){err="Klasör adı arşivde desteklenmiyor: "+name;return false;}
        FileEntry e;e.abs=si.absoluteFilePath();e.rel=rel;e.kind=2;e.mtime=si.lastModified().toSecsSinceEpoch();out.push_back(e);
        return walk(root,rel,out,skipped,err,cancel,0);
    }
    err="Kaynak dosya veya klasör bulunamadı.";return false;
}

QByteArray buildIndex(const std::vector<FileEntry> &entries){
    QByteArray b;uint8_t t[16];
    dbol::wr32(t,uint32_t(entries.size()));b.append(reinterpret_cast<const char*>(t),4);
    for(const FileEntry &e:entries){
        b.append(char(e.kind));
        const quint16 n=quint16(e.rel.size());b.append(char(n&255));b.append(char(n>>8));
        b.append(e.rel.data(),qsizetype(e.rel.size()));
        dbol::wr64(t,e.size);dbol::wr64(t+8,quint64(e.mtime));b.append(reinterpret_cast<const char*>(t),16);
    }
    return b;
}

// Parçaları sırayla yazar; dilimler tam boyutta bölünür. Geçici adla yazılır, sonda yeniden adlandırılır.
class PartSink{
public:
    PartSink(const QDir &dir,const QString &base,qint64 partSize,const QByteArray &stub,bool stubAll,
             const Id16 &id,const Id16 &salt,quint32 kdf,quint8 flags,const std::array<uint8_t,8> &check)
        :dir_(dir),base_(base),partSize_(partSize),stub_(stub),stubAll_(stubAll),id_(id),salt_(salt),kdf_(kdf),flags_(flags),check_(check){}
    QString error;
    int count()const{return int(parts_.size());}
    bool write(const char *p,qint64 n){
        while(n>0){
            if(!open_&&!openNext())return false;
            const qint64 room=qint64(cap_-slice_);
            if(room==0){if(!closeCurrent(false))return false;continue;}
            const qint64 t=std::min(n,room);
            if(file_.write(p,t)!=t){error="Yazma hatası (disk dolu olabilir): "+file_.errorString();return false;}
            hash_.update(p,size_t(t));slice_+=quint64(t);p+=t;n-=t;
        }
        return true;
    }
    bool finish(){
        if(open_&&!closeCurrent(true))return false;
        for(const P &p:parts_){
            QFile f(p.tmp);
            uint8_t c[4];dbol::wr32(c,uint32_t(parts_.size()));
            if(!f.open(QIODevice::ReadWrite)||!f.seek(qint64(p.off)+16)||f.write(reinterpret_cast<const char*>(c),4)!=4){error="Parça başlığı güncellenemedi.";return false;}
        }
        for(P &p:parts_){
            if(QFileInfo::exists(p.fin)){error="Parça zaten mevcut: "+QFileInfo(p.fin).fileName();return false;}
            if(!QFile::rename(p.tmp,p.fin)){error="Parça yeniden adlandırılamadı: "+QFileInfo(p.fin).fileName();return false;}
            p.renamed=true;
            if(p.stub)QFile::setPermissions(p.fin,QFile::permissions(p.fin)|QFileDevice::ExeOwner|QFileDevice::ExeGroup|QFileDevice::ExeOther);
        }
        return true;
    }
    void abort(){
        if(open_){file_.close();open_=false;}
        for(const P &p:parts_){QFile::remove(p.tmp);if(p.renamed)QFile::remove(p.fin);}
        parts_.clear();
    }
private:
    struct P{QString tmp,fin;quint64 off=0;bool stub=false;bool renamed=false;};
    bool openNext(){
        const int index=int(parts_.size())+1;
        if(index>100000){error="100.000 parçadan fazlası desteklenmiyor; parça boyutunu büyütün.";return false;}
        const bool hasStub=!stub_.isEmpty()&&(stubAll_||index==1);
        const QString name=QString("%1.part%2%3").arg(base_).arg(index,6,10,QLatin1Char('0')).arg(hasStub?".exe":"");
        P p;p.fin=dir_.filePath(name);p.tmp=p.fin+".dbtmp";p.stub=hasStub;
        if(QFileInfo::exists(p.fin)){error="Parça zaten mevcut, üzerine yazılmaz: "+name;return false;}
        QFile::remove(p.tmp);
        file_.setFileName(p.tmp);
        if(!file_.open(QIODevice::WriteOnly|QIODevice::Truncate)){error="Parça oluşturulamadı: "+file_.errorString();return false;}
        const qint64 stubLen=hasStub?stub_.size():0;
        if(hasStub&&file_.write(stub_)!=stubLen){error="Çözücü yazılamadı.";file_.close();QFile::remove(p.tmp);return false;}
        uint8_t h[dbol::kHeaderSize]={0};
        std::memcpy(h,dbol::kHeaderMagic,8);h[8]=flags_;dbol::wr32(h+12,uint32_t(index));dbol::wr32(h+20,kdf_);
        std::memcpy(h+24,id_.data(),16);std::memcpy(h+40,salt_.data(),16);std::memcpy(h+56,check_.data(),8);
        if(file_.write(reinterpret_cast<const char*>(h),qint64(dbol::kHeaderSize))!=qint64(dbol::kHeaderSize)){error="Başlık yazılamadı.";file_.close();QFile::remove(p.tmp);return false;}
        p.off=quint64(stubLen);parts_.push_back(p);
        cap_=quint64(partSize_-stubLen-qint64(dbol::kHeaderSize+dbol::kTailSize));
        slice_=0;hash_=dbol::Sha256();open_=true;
        return true;
    }
    bool closeCurrent(bool last){
        uint8_t t[dbol::kTailSize]={0};
        std::memcpy(t,dbol::kTailMagic,8);dbol::wr64(t+8,parts_.back().off);dbol::wr64(t+16,slice_);t[24]=last?dbol::kTailLast:0;
        const Hash32 d=hash_.digest();std::memcpy(t+32,d.data(),32);
        if(file_.write(reinterpret_cast<const char*>(t),qint64(dbol::kTailSize))!=qint64(dbol::kTailSize)){error="Parça sonu yazılamadı: "+file_.errorString();return false;}
        file_.close();open_=false;
        if(file_.error()!=QFileDevice::NoError){error="Parça kapatılamadı: "+file_.errorString();return false;}
        return true;
    }
    QDir dir_;QString base_;qint64 partSize_;QByteArray stub_;bool stubAll_;Id16 id_,salt_;quint32 kdf_;quint8 flags_;std::array<uint8_t,8> check_;
    QFile file_;dbol::Sha256 hash_;quint64 slice_=0,cap_=0;bool open_=false;std::vector<P> parts_;
};

// Düz akışı 1 MiB'lık bloklara böler; her blok sıkıştırılır (kazanç varsa) ve şifrelenir.
class BlockWriter{
public:
    BlockWriter(PartSink &sink,bool enc,const dbol::Keys &keys,int level):sink_(sink),enc_(enc),keys_(keys),level_(level){buf_.reserve(int(dbol::kBlockMax));}
    bool add(const char *p,qint64 n){
        while(n>0){
            const qint64 t=std::min<qint64>(n,qint64(dbol::kBlockMax)-buf_.size());
            buf_.append(p,qsizetype(t));p+=t;n-=t;
            if(buf_.size()==qint64(dbol::kBlockMax)&&!flush())return false;
        }
        return true;
    }
    bool flush(){
        if(buf_.isEmpty())return true;
        QByteArray data;quint8 method=0;
        if(level_>0){const QByteArray z=qCompress(buf_,level_);if(z.size()-4<buf_.size()){data=z.mid(4);method=1;}}
        if(method==0)data=buf_;
        uint8_t hd[9];dbol::wr32(hd,uint32_t(buf_.size()));dbol::wr32(hd+4,uint32_t(data.size()));hd[8]=method;
        QByteArray blk(reinterpret_cast<const char*>(hd),9);
        if(enc_){
            uint8_t nonce[12];dbol::blockNonce(nonce,index_);
            dbol::chacha20Xor(keys_.enc,nonce,0,reinterpret_cast<uint8_t*>(data.data()),size_t(data.size()));
            const Hash32 mac=dbol::blockMac(keys_,index_,hd,reinterpret_cast<const uint8_t*>(data.constData()),size_t(data.size()));
            blk.append(data);blk.append(reinterpret_cast<const char*>(mac.data()),32);
        }else blk.append(data);
        ++index_;buf_.clear();
        return sink_.write(blk.constData(),blk.size());
    }
private:
    PartSink &sink_;bool enc_;dbol::Keys keys_;int level_;quint64 index_=0;QByteArray buf_;
};

QString sizeText(quint64 b){
    if(b>=(1ULL<<30))return QString::number(double(b)/(1ULL<<30),'f',2)+" GiB";
    if(b>=(1ULL<<20))return QString::number(double(b)/(1ULL<<20),'f',2)+" MiB";
    return QString::number(double(b)/1024.0,'f',1)+" KiB";
}
bool isInside(const QString &child,const QString &parent){
    const Qt::CaseSensitivity cs=
#ifdef Q_OS_WIN
        Qt::CaseInsensitive;
#else
        Qt::CaseSensitive;
#endif
    const QString c=QDir::cleanPath(QFileInfo(child).absoluteFilePath()),p=QDir::cleanPath(QFileInfo(parent).absoluteFilePath());
    return c.compare(p,cs)==0||c.startsWith(p+"/",cs);
}
QString toQ(const std::string &s){return QString::fromUtf8(s.data(),qsizetype(s.size()));}
}  // namespace v2

QString SplitEngine::defaultDecoderPath(){
    return QDir(QCoreApplication::applicationDirPath()).filePath(
#ifdef Q_OS_WIN
        "DosyaBolCozucu.exe"
#else
        "DosyaBolCozucu"
#endif
    );
}

bool SplitEngine::pack(const PackOptions &o,const Progress &progress,std::atomic_bool &cancel,QString &error,QString *summary){
    using namespace v2;
    if(o.compression<0||o.compression>9){error="Sıkıştırma seviyesi geçersiz.";return false;}
    if(o.source.isEmpty()||o.outFolder.isEmpty()){error="Kaynak ve çıkış klasörü seçin.";return false;}
    const QFileInfo si(o.source);
    if(!si.exists()){error="Kaynak bulunamadı.";return false;}
    if(si.isDir()&&isInside(o.outFolder,o.source)){error="Çıkış klasörü, bölünecek klasörün içinde olamaz.";return false;}

    QByteArray stub;
    const QString decoder=o.decoderPath.isEmpty()?defaultDecoderPath():o.decoderPath;
    if(o.embedDecoder||o.copyDecoder){
        if(!QFileInfo(decoder).isFile()){error="Çözücü bulunamadı: "+decoder+"\nDosyaBolCozucu, DosyaBol ile aynı klasörde olmalıdır.";return false;}
    }
    if(o.embedDecoder){
        QFile sf(decoder);
        if(!sf.open(QIODevice::ReadOnly)){error="Çözücü okunamadı: "+sf.errorString();return false;}
        if(sf.size()>16*1024*1024){error="Çözücü dosyası beklenenden büyük.";return false;}
        stub=sf.readAll();
        if(stub.size()>=qsizetype(dbol::kTailSize)&&std::memcmp(stub.constData()+stub.size()-dbol::kTailSize,dbol::kTailMagic,8)==0){error="Çözücü olarak bir arşiv parçası seçilemez.";return false;}
    }
    const qint64 overhead=qint64(dbol::kHeaderSize+dbol::kTailSize);
    const qint64 firstCap=o.partSize-stub.size()-overhead;
    if(o.partSize<=0||firstCap<1024){
        error="Parça boyutu çok küçük. Gömülü çözücü ("+sizeText(quint64(stub.size()))+") ile en az "+sizeText(quint64(stub.size()+overhead+1024))+" olmalı.";return false;
    }

    std::vector<FileEntry> entries;int skipped=0;QString base;
    if(!collect(o.source,entries,skipped,base,error,cancel))return false;
    const QByteArray index=buildIndex(entries);
    quint64 sum=0;for(const FileEntry &e:entries)sum+=e.size;
    const quint64 total=quint64(index.size())+sum+32;

    QDir dir(o.outFolder);
    if(!dir.exists()&&!QDir().mkpath(o.outFolder)){error="Çıkış klasörü oluşturulamadı.";return false;}
    dir=QDir(QFileInfo(o.outFolder).absoluteFilePath());

    Id16 id{},salt{};
    {quint32 r[8];QRandomGenerator::system()->generate(std::begin(r),std::end(r));std::memcpy(id.data(),r,16);std::memcpy(salt.data(),r+4,16);}
    const bool enc=!o.password.isEmpty();
    dbol::Keys keys{};
    const quint32 kdf=dbol::kDefaultKdf;
    std::array<uint8_t,8> check{};
    if(enc){keys=dbol::deriveKeys(utf8(o.password),salt,kdf);check=dbol::keyCheck(keys);}
    else salt={};

    PartSink sink(dir,base,o.partSize,stub,o.embedEveryPart,id,salt,kdf,enc?dbol::kFlagEncrypted:0,check);
    BlockWriter bw(sink,enc,keys,o.compression);
    dbol::Sha256 plain;quint64 done=0;
    auto fail=[&](const QString &m){sink.abort();error=m;return false;};
    auto addPlain=[&](const char *p,qint64 n,bool hash){
        if(hash)plain.update(p,size_t(n));
        if(!bw.add(p,n))return false;
        done+=quint64(n);if(progress)progress(qint64(done),qint64(total));
        return true;
    };
    if(!addPlain(index.constData(),index.size(),true))return fail(sink.error);
    for(const FileEntry &e:entries){
        if(e.kind!=1)continue;
        QFile f(e.abs);
        if(!f.open(QIODevice::ReadOnly))return fail("Dosya açılamadı: "+e.abs+" ("+f.errorString()+")");
        quint64 left=e.size;
        while(left){
            if(cancel.load())return fail("İşlem iptal edildi.");
            const QByteArray b=f.read(qint64(std::min<quint64>(left,dbol::kBlockMax)));
            if(b.isEmpty())return fail("Dosya bölünürken kısaldı veya okunamadı: "+e.abs);
            if(!addPlain(b.constData(),b.size(),true))return fail(sink.error);
            left-=quint64(b.size());
        }
        if(!f.atEnd())return fail("Dosya bölünürken değişti: "+e.abs);
    }
    const Hash32 trailer=plain.digest();
    if(!addPlain(reinterpret_cast<const char*>(trailer.data()),32,false)||!bw.flush()||!sink.finish())return fail(sink.error);

    QString decoderNote;
    if(o.copyDecoder){
        const QString dest=dir.filePath(QFileInfo(decoder).fileName());
        if(QFileInfo::exists(dest))decoderNote="; çözücü klasörde zaten vardı";
        else if(QFile::copy(decoder,dest)){
            QFile::setPermissions(dest,QFile::permissions(dest)|QFileDevice::ExeOwner|QFileDevice::ExeGroup|QFileDevice::ExeOther);
            decoderNote="; çözücü klasöre kopyalandı";
        }else decoderNote="; UYARI: çözücü klasöre kopyalanamadı";
    }
    if(summary){
        QString s=QString("%1 parça oluşturuldu (%2, %3)").arg(sink.count()).arg(enc?"şifreli":"şifresiz")
            .arg(o.compression?QString("sıkıştırma seviye %1").arg(o.compression):QString("sıkıştırmasız"));
        s+=QString("; %1 dosya/klasör, %2 işlendi").arg(entries.size()).arg(sizeText(sum));
        if(o.embedDecoder)s+=o.embedEveryPart?"; çözücü her parçanın başında":"; çözücü ilk parçanın başında";
        s+=decoderNote;
        if(skipped)s+=QString("; %1 sembolik bağ/özel dosya atlandı").arg(skipped);
        *summary=s+".";
    }
    return true;
}

namespace {
bool isLegacy(const QString &path){return path.endsWith(".dbmanifest.json",Qt::CaseInsensitive);}
bool loadArchive(const QString &part,dbol::Archive &a,QString &err){
    std::string e;
    if(!dbol::loadArchiveFromPart(v2::toPath(part),a,e)){err=v2::toQ(e);return false;}
    return true;
}
void fillOptions(dbol::Options &o,const QString &password,const SplitEngine::Progress &progress,std::atomic_bool &cancel){
    o.password=v2::utf8(password);
    o.cancelled=[&cancel]{return cancel.load();};
    if(progress)o.progress=[&progress](uint64_t d,uint64_t t){progress(qint64(d),qint64(t));};
}
bool finishResult(const dbol::Result &r,QString &error,bool *needPassword){
    if(needPassword)*needPassword=(r.st==dbol::Status::NeedPassword||r.st==dbol::Status::WrongPassword);
    if(r.st==dbol::Status::Ok)return true;
    error=v2::toQ(r.msg);return false;
}
}

bool SplitEngine::unpack(const QString &part,const QString &folder,const QString &password,const Progress &progress,
                         std::atomic_bool &cancel,QString &error,QString *summary,bool *needPassword){
    if(needPassword)*needPassword=false;
    if(isLegacy(part)){
        const bool ok=join(part,folder,progress,cancel,error);
        if(ok&&summary)*summary="Eski biçimli dosya birleştirildi.";
        return ok;
    }
    dbol::Archive a;if(!loadArchive(part,a,error))return false;
    dbol::Options o;fillOptions(o,password,progress,cancel);
    o.outDir=v2::toPath(folder);o.write=true;
    const dbol::Result r=dbol::process(a,o);
    if(!finishResult(r,error,needPassword))return false;
    if(summary)*summary=QString("%1 dosya, %2 klasör, %3 çıkarıldı ve doğrulandı.").arg(r.files).arg(r.dirs).arg(v2::sizeText(r.bytes));
    return true;
}

bool SplitEngine::check(const QString &part,const QString &password,const Progress &progress,
                        std::atomic_bool &cancel,QString &error,QString *summary,bool *needPassword){
    if(needPassword)*needPassword=false;
    if(isLegacy(part)){
        const bool ok=verify(part,progress,cancel,error);
        if(ok&&summary)*summary="Eski biçimli parçalar doğrulandı.";
        return ok;
    }
    dbol::Archive a;if(!loadArchive(part,a,error))return false;
    if(!a.ok()){
        error=a.problem.empty()?QString("Eksik parça numaraları: ")+v2::toQ(dbol::missingText(a)):v2::toQ(a.problem);return false;
    }
    if(a.encrypted&&password.isEmpty()){
        const dbol::Result r=dbol::verifyParts(a,progress?std::function<void(uint64_t,uint64_t)>([&progress](uint64_t d,uint64_t t){progress(qint64(d),qint64(t));}):nullptr,
                                              [&cancel]{return cancel.load();});
        if(!finishResult(r,error,nullptr))return false;
        if(summary)*summary=v2::toQ(r.msg)+" Şifreli içerik şifre girilmediği için çözülmedi.";
        return true;
    }
    dbol::Options o;fillOptions(o,password,progress,cancel);o.write=false;
    const dbol::Result r=dbol::process(a,o);
    if(!finishResult(r,error,needPassword))return false;
    if(summary)*summary=QString("Arşiv tamamen doğrulandı: %1 dosya, %2.").arg(r.files).arg(v2::sizeText(r.bytes));
    return true;
}

ArchiveSummary SplitEngine::inspect(const QString &part){
    ArchiveSummary s;
    if(isLegacy(part)){s.valid=QFileInfo(part).isFile();s.legacy=true;s.complete=s.valid;s.text="Eski biçim (manifest) — şifresiz.";return s;}
    dbol::Archive a;QString err;
    if(!QFileInfo(part).isFile()||!loadArchive(part,a,err)){s.text=err;return s;}
    s.valid=true;s.encrypted=a.encrypted;s.complete=a.ok();
    if(!a.problem.empty())s.text=v2::toQ(a.problem);
    else{
        s.text=QString("%1/%2 parça bulundu").arg(a.parts.size()).arg(a.count)+(a.encrypted?" • şifreli":" • şifresiz");
        if(!a.missing.empty())s.text+=" • eksik parça: "+v2::toQ(dbol::missingText(a));
    }
    return s;
}
