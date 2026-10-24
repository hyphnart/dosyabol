#include "SplitEngine.h"
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
