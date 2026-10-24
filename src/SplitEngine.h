#pragma once
#include <QString>
#include <functional>
#include <atomic>

class SplitEngine {
public:
    using Progress = std::function<void(qint64,qint64)>;
    static bool split(const QString &source,const QString &folder,qint64 chunkSize,int compression,
                      const Progress &progress,std::atomic_bool &cancel,QString &error);
    static bool join(const QString &manifest,const QString &folder,const Progress &progress,
                     std::atomic_bool &cancel,QString &error);
    static bool verify(const QString &manifest,const Progress &progress,
                       std::atomic_bool &cancel,QString &error);
};
