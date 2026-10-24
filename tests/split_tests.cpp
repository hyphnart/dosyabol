#include "SplitEngine.h"
#include <QCoreApplication>
#include <QTemporaryDir>
#include <QFile>
#include <QDir>
#include <QDebug>
#include <atomic>
int main(int argc,char **argv){
    QCoreApplication app(argc,argv);
    QTemporaryDir tmp;if(!tmp.isValid())return 1;
    const QString source=tmp.filePath("sample.bin");
    QByteArray bytes(50000,'A');bytes.append("Hello world!\0binary",19);
    {QFile f(source);if(!f.open(QIODevice::WriteOnly)||f.write(bytes)!=bytes.size())return 2;}
    std::atomic_bool cancel{false};QString err;
    for(int level:{0,6,9}){
        QString dir=tmp.filePath(QString("parts%1").arg(level));
        if(!SplitEngine::split(source,dir,4096,level,{},cancel,err)){qCritical()<<err;return 3;}
        QString manifest=QDir(dir).filePath("sample.bin.dbmanifest.json");
        if(!SplitEngine::verify(manifest,{},cancel,err)){qCritical()<<err;return 4;}
        QString restored=tmp.filePath(QString("joined%1").arg(level));
        if(!SplitEngine::join(manifest,restored,{},cancel,err)){qCritical()<<err;return 5;}
        QFile f(QDir(restored).filePath("sample.bin"));if(!f.open(QIODevice::ReadOnly)||f.readAll()!=bytes)return 6;
    }
    const QString empty=tmp.filePath("empty.bin");{QFile f(empty);if(!f.open(QIODevice::WriteOnly))return 7;}
    const QString emptyDir=tmp.filePath("empty_parts");
    if(!SplitEngine::split(empty,emptyDir,4096,6,{},cancel,err))return 8;
    if(!SplitEngine::verify(QDir(emptyDir).filePath("empty.bin.dbmanifest.json"),{},cancel,err))return 9;
    qInfo()<<"PASS: plain/compressed split, join, verify and empty file";
    return 0;
}
