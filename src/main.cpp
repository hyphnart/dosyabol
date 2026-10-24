#include "SplitEngine.h"
#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QTabWidget>
#include <QLineEdit>
#include <QPushButton>
#include <QFileDialog>
#include <QLabel>
#include <QSpinBox>
#include <QComboBox>
#include <QAction>
#include <QCheckBox>
#include <QProgressBar>
#include <QMessageBox>
#include <QGroupBox>
#include <QMenuBar>
#include <QCloseEvent>
#include <QThread>
#include <QTimer>
#include <QSettings>
#include <QFileInfo>
#include <QDir>
#include <atomic>
#include <memory>

class Job final: public QThread {
    Q_OBJECT
public:
    enum Action {Split,Join,Verify};
    Action action=Split;
    QString source,folder;
    qint64 size=100*1024*1024;
    int compression=6;
    std::atomic_bool cancel{false};
    using QThread::QThread;
signals:
    void percent(int value);
    void finishedJob(bool ok,const QString &message);
protected:
    void run() override {
        QString error;
        auto cb=[this](qint64 done,qint64 total){emit percent(total?int(done*100.0/total):100);};
        bool ok=false;
        if(action==Split)ok=SplitEngine::split(source,folder,size,compression,cb,cancel,error);
        else if(action==Join)ok=SplitEngine::join(source,folder,cb,cancel,error);
        else ok=SplitEngine::verify(source,cb,cancel,error);
        emit finishedJob(ok,ok?QStringLiteral("İşlem başarıyla tamamlandı."):error);
    }
};
class Window final: public QMainWindow {
    Q_OBJECT
    QLineEdit *source_=nullptr,*destination_=nullptr,*manifest_=nullptr,*joinFolder_=nullptr;
    QSpinBox *amount_=nullptr,*level_=nullptr;
    QComboBox *unit_=nullptr;
    QCheckBox *compress_=nullptr;
    QProgressBar *progress_=nullptr;
    QLabel *status_=nullptr;
    QPushButton *startSplit_=nullptr,*startJoin_=nullptr,*verify_=nullptr,*cancel_=nullptr;
    Job *job_=nullptr;
public:
    Window(){
        setWindowTitle("Dosya Böl — Yapımcı: Yaser Sayıcı");resize(780,560);
        auto *central=new QWidget(this);auto *root=new QVBoxLayout(central);
        auto *heading=new QLabel("DOSYA BÖL",central);heading->setObjectName("heading");root->addWidget(heading);
        auto *credit=new QLabel("Yapımcı: Yaser Sayıcı  •  C++ / Qt6  •  Kayıpsız bölme ve birleştirme",central);
        credit->setObjectName("credit");root->addWidget(credit);
        auto *tabs=new QTabWidget(central);
        auto *split=new QWidget(tabs);auto *splitLayout=new QVBoxLayout(split);auto *sf=new QFormLayout;
        source_=new QLineEdit(split);source_->setPlaceholderText("Bölünecek dosya...");
        sf->addRow("Kaynak dosya",lineWithBrowse(source_,false));
        destination_=new QLineEdit(split);destination_->setPlaceholderText("Parçaların kaydedileceği klasör...");
        sf->addRow("Çıkış klasörü",lineWithBrowse(destination_,true));
        amount_=new QSpinBox(split);amount_->setRange(1,2048);amount_->setValue(100);
        unit_=new QComboBox(split);unit_->addItems({"KiB","MiB","GiB"});unit_->setCurrentIndex(1);
        auto *sizeRow=new QWidget(split);auto *sizeLayout=new QHBoxLayout(sizeRow);sizeLayout->setContentsMargins(0,0,0,0);
        sizeLayout->addWidget(amount_);sizeLayout->addWidget(unit_);sf->addRow("Parça boyutu",sizeRow);
        compress_=new QCheckBox("Kayıpsız zlib sıkıştırması",split);compress_->setChecked(true);sf->addRow("Sıkıştırma",compress_);
        level_=new QSpinBox(split);level_->setRange(1,9);level_->setValue(6);level_->setToolTip("1: hızlı, 9: daha çok sıkıştırma");
        sf->addRow("Sıkıştırma seviyesi",level_);
        connect(compress_,&QCheckBox::toggled,level_,&QWidget::setEnabled);
        splitLayout->addLayout(sf);
        auto *note=new QLabel("Sıkıştırılmış ZIP/MP4/JPG dosyaları her zaman küçülmeyebilir. Bölme sonrası oluşan .dbmanifest.json dosyasını saklayın.",split);
        note->setWordWrap(true);splitLayout->addWidget(note);
        startSplit_=new QPushButton("Dosyayı Böl",split);startSplit_->setObjectName("primary");splitLayout->addWidget(startSplit_);
        splitLayout->addStretch();tabs->addTab(split,"Dosya Böl");
        auto *join=new QWidget(tabs);auto *jl=new QVBoxLayout(join);auto *jf=new QFormLayout;
        manifest_=new QLineEdit(join);manifest_->setPlaceholderText(".dbmanifest.json seçin");jf->addRow("Manifest",lineWithBrowse(manifest_,false,true));
        joinFolder_=new QLineEdit(join);joinFolder_->setPlaceholderText("Dosyanın yeniden oluşturulacağı klasör...");jf->addRow("Çıkış klasörü",lineWithBrowse(joinFolder_,true));
        jl->addLayout(jf);
        startJoin_=new QPushButton("Parçaları Birleştir",join);startJoin_->setObjectName("primary");jl->addWidget(startJoin_);
        verify_=new QPushButton("Parçaları SHA-256 ile Doğrula",join);jl->addWidget(verify_);
        auto *hint=new QLabel("Birleştirme orijinal dosyayı SHA-256 ile doğrular. Doğrulama işleminde yeni dosya oluşturulmaz.",join);
        hint->setWordWrap(true);jl->addWidget(hint);jl->addStretch();tabs->addTab(join,"Birleştir / Doğrula");
        root->addWidget(tabs);
        progress_=new QProgressBar(central);progress_->setRange(0,100);root->addWidget(progress_);
        status_=new QLabel("Hazır",central);root->addWidget(status_);
        cancel_=new QPushButton("İptal",central);cancel_->setEnabled(false);root->addWidget(cancel_);
        setCentralWidget(central);
        connect(startSplit_,&QPushButton::clicked,this,[this]{begin(Job::Split);});
        connect(startJoin_,&QPushButton::clicked,this,[this]{begin(Job::Join);});
        connect(verify_,&QPushButton::clicked,this,[this]{begin(Job::Verify);});
        connect(cancel_,&QPushButton::clicked,this,[this]{if(job_)job_->cancel.store(true);status_->setText("İptal ediliyor...");});
        QSettings settings("Yaser Sayici","Dosya Bol");
        resize(settings.value("window/size",size()).toSize());
        auto *menu=menuBar()->addMenu("Görünüm");
        QAction *dark=menu->addAction("Gece Teması");dark->setCheckable(true);
        dark->setChecked(settings.value("dark",true).toBool());
        connect(dark,&QAction::toggled,this,[this](bool enabled){QSettings("Yaser Sayici","Dosya Bol").setValue("dark",enabled);theme(enabled);});
        theme(dark->isChecked());
        QTimer::singleShot(0,this,[this]{status_->setText("Hoş geldiniz — Yapımcı: Yaser Sayıcı");});
    }
    ~Window() override {if(job_){job_->cancel.store(true);job_->wait();}}
protected:
    void closeEvent(QCloseEvent *event) override {
        if(job_ && job_->isRunning()){QMessageBox::information(this,"İşlem sürüyor","Önce işlemi iptal edin veya tamamlanmasını bekleyin.");event->ignore();return;}
        QSettings("Yaser Sayici","Dosya Bol").setValue("window/size",size());event->accept();
    }
private:
    QWidget *lineWithBrowse(QLineEdit *edit,bool folder,bool manifest=false){
        auto *w=new QWidget(this);auto *row=new QHBoxLayout(w);row->setContentsMargins(0,0,0,0);row->addWidget(edit);
        auto *browse=new QPushButton("Gözat",w);row->addWidget(browse);
        connect(browse,&QPushButton::clicked,this,[this,edit,folder,manifest]{
            QString path=folder?QFileDialog::getExistingDirectory(this,"Klasör seç"):
               QFileDialog::getOpenFileName(this,"Dosya seç",{},manifest?"Dosya Böl manifest (*.dbmanifest.json)":"Tüm dosyalar (*)");
            if(!path.isEmpty())edit->setText(path);
        });return w;
    }
    void theme(bool dark){
        setStyleSheet(dark?R"(QWidget{background:#070b12;color:#d9e6f6;font:10pt 'Segoe UI';}QLineEdit,QSpinBox,QComboBox,QTabWidget::pane{background:#111c2c;color:#edf4ff;border:1px solid #26364c;border-radius:5px;padding:6px;}QPushButton{background:#142235;border:1px solid #304462;padding:9px;border-radius:6px;}QPushButton:hover{background:#203854;}QPushButton#primary{background:#2157ab;color:white;font-weight:bold;}QTabBar::tab{background:#121f32;padding:10px;}QTabBar::tab:selected{background:#254a76;}QLabel#heading{font-size:26pt;font-weight:bold;color:#7db4ff;}QLabel#credit{color:#91a9c7;}QProgressBar{border:1px solid #32465f;background:#101c2a;text-align:center;}QProgressBar::chunk{background:#3e83db;})":
        R"(QWidget{background:#f4f7fb;color:#233247;font:10pt 'Segoe UI';}QLineEdit,QSpinBox,QComboBox,QTabWidget::pane{background:white;border:1px solid #cbd5e1;border-radius:5px;padding:6px;}QPushButton{background:#e9eff8;border:1px solid #b7c8de;padding:9px;border-radius:6px;}QPushButton:hover{background:#d6e5fa;}QPushButton#primary{background:#2563c7;color:white;font-weight:bold;}QTabBar::tab{background:#e6edf7;padding:10px;}QTabBar::tab:selected{background:white;}QLabel#heading{font-size:26pt;font-weight:bold;color:#245db3;}QLabel#credit{color:#66758c;}QProgressBar{border:1px solid #b4c5d9;background:white;text-align:center;}QProgressBar::chunk{background:#3e83db;})");
    }
    void begin(Job::Action action){
        if(job_)return;
        QString path=(action==Job::Split?source_:manifest_)->text().trimmed();
        QString folder=(action==Job::Split?destination_:joinFolder_)->text().trimmed();
        if(path.isEmpty()||(action!=Job::Verify&&folder.isEmpty())){QMessageBox::warning(this,"Eksik bilgi","Dosya ve klasör seçin.");return;}
        if(!QFileInfo(path).isFile()){QMessageBox::warning(this,"Hata","Dosya bulunamadı.");return;}
        job_=new Job(this);job_->action=action;job_->source=path;job_->folder=folder;
        const qint64 multiplier=unit_->currentIndex()==0?1024LL:unit_->currentIndex()==1?1024LL*1024:1024LL*1024*1024;
        job_->size=amount_->value()*multiplier;job_->compression=compress_->isChecked()?level_->value():0;
        startSplit_->setEnabled(false);startJoin_->setEnabled(false);verify_->setEnabled(false);cancel_->setEnabled(true);
        progress_->setValue(0);status_->setText("İşleniyor...");
        connect(job_,&Job::percent,progress_,&QProgressBar::setValue);
        connect(job_,&Job::finishedJob,this,[this](bool ok,const QString &message){
            status_->setText(message);cancel_->setEnabled(false);startSplit_->setEnabled(true);startJoin_->setEnabled(true);verify_->setEnabled(true);
            if(ok)progress_->setValue(100);
            auto *completed=job_;job_=nullptr;completed->wait();completed->deleteLater();
            QMessageBox::information(this,ok?"Tamamlandı":"İşlem başarısız",message);
        });job_->start();
    }
};
int main(int argc,char **argv){
    QApplication app(argc,argv);app.setApplicationName("Dosya Böl");app.setOrganizationName("Yaser Sayici");
    Window window;window.show();return app.exec();
}
#include "main.moc"
