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
    enum Action {Pack,Unpack,Check};
    Action action=Pack;
    PackOptions pack;
    QString part,folder,password;
    std::atomic_bool cancel{false};
    using QThread::QThread;
signals:
    void percent(int value);
    void finishedJob(bool ok,const QString &message,bool needPassword);
protected:
    void run() override {
        QString error,summary;bool need=false;
        auto cb=[this](qint64 done,qint64 total){emit percent(total?int(done*100.0/total):100);};
        bool ok=false;
        if(action==Pack)ok=SplitEngine::pack(pack,cb,cancel,error,&summary);
        else if(action==Unpack)ok=SplitEngine::unpack(part,folder,password,cb,cancel,error,&summary,&need);
        else ok=SplitEngine::check(part,password,cb,cancel,error,&summary,&need);
        emit finishedJob(ok,ok?(summary.isEmpty()?QStringLiteral("İşlem başarıyla tamamlandı."):summary):error,need);
    }
};
class Window final: public QMainWindow {
    Q_OBJECT
    QLineEdit *source_=nullptr,*destination_=nullptr,*part_=nullptr,*joinFolder_=nullptr;
    QLineEdit *password_=nullptr,*password2_=nullptr,*joinPassword_=nullptr;
    QSpinBox *amount_=nullptr,*level_=nullptr;
    QComboBox *unit_=nullptr,*embedMode_=nullptr;
    QCheckBox *compress_=nullptr,*encrypt_=nullptr,*showPassword_=nullptr,*copyDecoder_=nullptr,*embedDecoder_=nullptr;
    QProgressBar *progress_=nullptr;
    QLabel *status_=nullptr,*partInfo_=nullptr;
    QPushButton *startSplit_=nullptr,*startJoin_=nullptr,*verify_=nullptr,*cancel_=nullptr;
    Job *job_=nullptr;
public:
    Window(){
        setWindowTitle("Dosya Böl — Yapımcı: Yaser Sayıcı");resize(820,700);
        auto *central=new QWidget(this);auto *root=new QVBoxLayout(central);
        auto *heading=new QLabel("DOSYA BÖL",central);heading->setObjectName("heading");root->addWidget(heading);
        auto *credit=new QLabel("Yapımcı: Yaser Sayıcı  •  C++ / Qt6  •  Dosya ve klasör bölme, şifreleme, gömülü çözücü",central);
        credit->setObjectName("credit");root->addWidget(credit);
        auto *tabs=new QTabWidget(central);
        tabs->addTab(buildSplitTab(tabs),"Böl");
        tabs->addTab(buildJoinTab(tabs),"Birleştir / Doğrula");
        root->addWidget(tabs);
        progress_=new QProgressBar(central);progress_->setRange(0,100);root->addWidget(progress_);
        status_=new QLabel("Hazır",central);status_->setWordWrap(true);root->addWidget(status_);
        cancel_=new QPushButton("İptal",central);cancel_->setEnabled(false);root->addWidget(cancel_);
        setCentralWidget(central);
        connect(startSplit_,&QPushButton::clicked,this,[this]{begin(Job::Pack);});
        connect(startJoin_,&QPushButton::clicked,this,[this]{begin(Job::Unpack);});
        connect(verify_,&QPushButton::clicked,this,[this]{begin(Job::Check);});
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
    QWidget *buildSplitTab(QWidget *parent){
        auto *split=new QWidget(parent);auto *layout=new QVBoxLayout(split);auto *sf=new QFormLayout;
        source_=new QLineEdit(split);source_->setPlaceholderText("Bölünecek dosya veya klasör...");
        auto *srcRow=new QWidget(split);auto *sr=new QHBoxLayout(srcRow);sr->setContentsMargins(0,0,0,0);sr->addWidget(source_);
        auto *pickFile=new QPushButton("Dosya…",srcRow),*pickDir=new QPushButton("Klasör…",srcRow);
        sr->addWidget(pickFile);sr->addWidget(pickDir);sf->addRow("Kaynak",srcRow);
        connect(pickFile,&QPushButton::clicked,this,[this]{const QString p=QFileDialog::getOpenFileName(this,"Bölünecek dosyayı seç",{},"Tüm dosyalar (*)");if(!p.isEmpty())source_->setText(p);});
        connect(pickDir,&QPushButton::clicked,this,[this]{const QString p=QFileDialog::getExistingDirectory(this,"Bölünecek klasörü seç");if(!p.isEmpty())source_->setText(p);});
        destination_=new QLineEdit(split);destination_->setPlaceholderText("Parçaların kaydedileceği klasör...");
        sf->addRow("Çıkış klasörü",lineWithBrowse(destination_,true));
        amount_=new QSpinBox(split);amount_->setRange(1,2048);amount_->setValue(100);
        unit_=new QComboBox(split);unit_->addItems({"KiB","MiB","GiB"});unit_->setCurrentIndex(1);
        auto *sizeRow=new QWidget(split);auto *sizeLayout=new QHBoxLayout(sizeRow);sizeLayout->setContentsMargins(0,0,0,0);
        sizeLayout->addWidget(amount_);sizeLayout->addWidget(unit_);sf->addRow("En büyük parça boyutu",sizeRow);
        compress_=new QCheckBox("Kayıpsız zlib sıkıştırması",split);compress_->setChecked(true);sf->addRow("Sıkıştırma",compress_);
        level_=new QSpinBox(split);level_->setRange(1,9);level_->setValue(6);level_->setToolTip("1: hızlı, 9: daha çok sıkıştırma");
        sf->addRow("Sıkıştırma seviyesi",level_);
        connect(compress_,&QCheckBox::toggled,level_,&QWidget::setEnabled);
        layout->addLayout(sf);

        auto *crypt=new QGroupBox("Şifreleme (isteğe bağlı)",split);auto *cf=new QFormLayout(crypt);
        encrypt_=new QCheckBox("Parçaları şifrele (ChaCha20 + HMAC-SHA256, PBKDF2)",crypt);cf->addRow(encrypt_);
        password_=new QLineEdit(crypt);password_->setEchoMode(QLineEdit::Password);password_->setPlaceholderText("Şifre");
        password2_=new QLineEdit(crypt);password2_->setEchoMode(QLineEdit::Password);password2_->setPlaceholderText("Şifre (tekrar)");
        showPassword_=new QCheckBox("Şifreyi göster",crypt);
        cf->addRow("Şifre",password_);cf->addRow("Tekrar",password2_);cf->addRow(showPassword_);
        auto *warn=new QLabel("Şifre unutulursa veriler kurtarılamaz. Dosya adları da şifrelenir.",crypt);warn->setWordWrap(true);warn->setObjectName("credit");cf->addRow(warn);
        auto setCrypt=[this](bool on){password_->setEnabled(on);password2_->setEnabled(on);showPassword_->setEnabled(on);};
        setCrypt(false);connect(encrypt_,&QCheckBox::toggled,this,setCrypt);
        connect(showPassword_,&QCheckBox::toggled,this,[this](bool show){const auto m=show?QLineEdit::Normal:QLineEdit::Password;password_->setEchoMode(m);password2_->setEchoMode(m);});
        layout->addWidget(crypt);

        auto *dec=new QGroupBox("Çözücü EXE (DosyaBolCozucu)",split);auto *dl=new QVBoxLayout(dec);
        copyDecoder_=new QCheckBox("Çözücü EXE'yi çıkış klasörüne de kopyala (parçaları açmak için gereken exe)",dec);copyDecoder_->setChecked(true);dl->addWidget(copyDecoder_);
        embedDecoder_=new QCheckBox("Çözücüyü parçaların başına göm (parça çift tıklanınca kendini açar)",dec);dl->addWidget(embedDecoder_);
        embedMode_=new QComboBox(dec);embedMode_->addItems({"Yalnızca ilk parçanın başına","Her parçanın başına"});embedMode_->setEnabled(false);dl->addWidget(embedMode_);
        connect(embedDecoder_,&QCheckBox::toggled,embedMode_,&QWidget::setEnabled);
        const bool haveDecoder=QFileInfo(SplitEngine::defaultDecoderPath()).isFile();
        if(!haveDecoder){
            copyDecoder_->setChecked(false);copyDecoder_->setEnabled(false);embedDecoder_->setEnabled(false);
            auto *miss=new QLabel("DosyaBolCozucu bu programın yanında bulunamadı; çözücü seçenekleri kapalı.",dec);miss->setWordWrap(true);dl->addWidget(miss);
        }else{
            auto *sz=new QLabel(QString("Çözücü boyutu: %1 KiB. Gömülürse parça dosyaları .exe uzantılı olur ve her biri o kadar büyür; parça boyutu sınırı çözücü dahil uygulanır.")
                .arg(QFileInfo(SplitEngine::defaultDecoderPath()).size()/1024),dec);
            sz->setWordWrap(true);sz->setObjectName("credit");dl->addWidget(sz);
        }
        layout->addWidget(dec);
        startSplit_=new QPushButton("Böl",split);startSplit_->setObjectName("primary");layout->addWidget(startSplit_);
        layout->addStretch();
        return split;
    }
    QWidget *buildJoinTab(QWidget *parent){
        auto *join=new QWidget(parent);auto *jl=new QVBoxLayout(join);auto *jf=new QFormLayout;
        part_=new QLineEdit(join);part_->setPlaceholderText("Herhangi bir parça dosyası (.part000001 / .exe) veya .dbmanifest.json");
        auto *row=new QWidget(join);auto *rl=new QHBoxLayout(row);rl->setContentsMargins(0,0,0,0);rl->addWidget(part_);
        auto *browse=new QPushButton("Gözat",row);rl->addWidget(browse);jf->addRow("Parça / manifest",row);
        connect(browse,&QPushButton::clicked,this,[this]{
            const QString p=QFileDialog::getOpenFileName(this,"Parça dosyasını seç",{},"Dosya Böl parçaları (*.part* *.exe *.dbmanifest.json);;Tüm dosyalar (*)");
            if(!p.isEmpty()){part_->setText(p);refreshInfo();}
        });
        connect(part_,&QLineEdit::editingFinished,this,[this]{refreshInfo();});
        partInfo_=new QLabel(join);partInfo_->setWordWrap(true);jf->addRow("Durum",partInfo_);
        joinFolder_=new QLineEdit(join);joinFolder_->setPlaceholderText("Dosya/klasörün çıkarılacağı klasör...");jf->addRow("Çıkış klasörü",lineWithBrowse(joinFolder_,true));
        joinPassword_=new QLineEdit(join);joinPassword_->setEchoMode(QLineEdit::Password);joinPassword_->setPlaceholderText("Yalnızca şifreli arşivler için");
        jf->addRow("Şifre",joinPassword_);
        jl->addLayout(jf);
        startJoin_=new QPushButton("Parçaları Birleştir / Çıkar",join);startJoin_->setObjectName("primary");jl->addWidget(startJoin_);
        verify_=new QPushButton("Doğrula (SHA-256)",join);jl->addWidget(verify_);
        auto *hint=new QLabel("Çıkarma, orijinal veriyi SHA-256 ile doğrular ve var olan dosyaların üzerine yazmaz; hata olursa yarım dosya bırakmaz. Şifre girmeden doğrulama yalnızca parça bütünlüğünü denetler.",join);
        hint->setWordWrap(true);jl->addWidget(hint);jl->addStretch();
        return join;
    }
    void refreshInfo(){
        const QString p=part_->text().trimmed();
        if(p.isEmpty()){partInfo_->clear();return;}
        const ArchiveSummary s=SplitEngine::inspect(p);
        partInfo_->setText(s.valid?s.text:("Tanınmadı: "+s.text));
        joinPassword_->setEnabled(!s.valid||s.encrypted);
    }
    QWidget *lineWithBrowse(QLineEdit *edit,bool folder){
        auto *w=new QWidget(this);auto *row=new QHBoxLayout(w);row->setContentsMargins(0,0,0,0);row->addWidget(edit);
        auto *browse=new QPushButton("Gözat",w);row->addWidget(browse);
        connect(browse,&QPushButton::clicked,this,[this,edit,folder]{
            const QString path=folder?QFileDialog::getExistingDirectory(this,"Klasör seç"):QFileDialog::getOpenFileName(this,"Dosya seç",{},"Tüm dosyalar (*)");
            if(!path.isEmpty())edit->setText(path);
        });return w;
    }
    void theme(bool dark){
        setStyleSheet(dark?R"(QWidget{background:#070b12;color:#d9e6f6;font:10pt 'Segoe UI';}QLineEdit,QSpinBox,QComboBox,QTabWidget::pane{background:#111c2c;color:#edf4ff;border:1px solid #26364c;border-radius:5px;padding:6px;}QGroupBox{border:1px solid #26364c;border-radius:6px;margin-top:10px;padding:8px;}QGroupBox::title{subcontrol-origin:margin;left:10px;color:#7db4ff;}QPushButton{background:#142235;border:1px solid #304462;padding:9px;border-radius:6px;}QPushButton:hover{background:#203854;}QPushButton:disabled{color:#5c6b80;}QPushButton#primary{background:#2157ab;color:white;font-weight:bold;}QTabBar::tab{background:#121f32;padding:10px;}QTabBar::tab:selected{background:#254a76;}QLabel#heading{font-size:26pt;font-weight:bold;color:#7db4ff;}QLabel#credit{color:#91a9c7;}QProgressBar{border:1px solid #32465f;background:#101c2a;text-align:center;}QProgressBar::chunk{background:#3e83db;})":
        R"(QWidget{background:#f4f7fb;color:#233247;font:10pt 'Segoe UI';}QLineEdit,QSpinBox,QComboBox,QTabWidget::pane{background:white;border:1px solid #cbd5e1;border-radius:5px;padding:6px;}QGroupBox{border:1px solid #cbd5e1;border-radius:6px;margin-top:10px;padding:8px;}QGroupBox::title{subcontrol-origin:margin;left:10px;color:#245db3;}QPushButton{background:#e9eff8;border:1px solid #b7c8de;padding:9px;border-radius:6px;}QPushButton:hover{background:#d6e5fa;}QPushButton:disabled{color:#9aa7b8;}QPushButton#primary{background:#2563c7;color:white;font-weight:bold;}QTabBar::tab{background:#e6edf7;padding:10px;}QTabBar::tab:selected{background:white;}QLabel#heading{font-size:26pt;font-weight:bold;color:#245db3;}QLabel#credit{color:#66758c;}QProgressBar{border:1px solid #b4c5d9;background:white;text-align:center;}QProgressBar::chunk{background:#3e83db;})");
    }
    void setBusy(bool busy){
        startSplit_->setEnabled(!busy);startJoin_->setEnabled(!busy);verify_->setEnabled(!busy);cancel_->setEnabled(busy);
    }
    void begin(Job::Action action){
        if(job_)return;
        auto job=std::make_unique<Job>(this);job->action=action;
        if(action==Job::Pack){
            const QString src=source_->text().trimmed(),dst=destination_->text().trimmed();
            if(src.isEmpty()||dst.isEmpty()){QMessageBox::warning(this,"Eksik bilgi","Kaynak ve çıkış klasörünü seçin.");return;}
            if(!QFileInfo::exists(src)){QMessageBox::warning(this,"Hata","Kaynak bulunamadı.");return;}
            QString pw;
            if(encrypt_->isChecked()){
                pw=password_->text();
                if(pw.isEmpty()){QMessageBox::warning(this,"Şifre","Şifreleme açık ama şifre boş.");return;}
                if(pw!=password2_->text()){QMessageBox::warning(this,"Şifre","Şifreler birbiriyle uyuşmuyor.");return;}
            }
            const qint64 multiplier=unit_->currentIndex()==0?1024LL:unit_->currentIndex()==1?1024LL*1024:1024LL*1024*1024;
            PackOptions &o=job->pack;
            o.source=src;o.outFolder=dst;o.partSize=amount_->value()*multiplier;o.compression=compress_->isChecked()?level_->value():0;
            o.password=pw;o.copyDecoder=copyDecoder_->isChecked();o.embedDecoder=embedDecoder_->isChecked();
            o.embedEveryPart=embedMode_->currentIndex()==1;
        }else{
            const QString p=part_->text().trimmed(),folder=joinFolder_->text().trimmed();
            if(p.isEmpty()||(action==Job::Unpack&&folder.isEmpty())){QMessageBox::warning(this,"Eksik bilgi","Parça dosyasını ve çıkış klasörünü seçin.");return;}
            if(!QFileInfo(p).isFile()){QMessageBox::warning(this,"Hata","Dosya bulunamadı.");return;}
            job->part=p;job->folder=folder;job->password=joinPassword_->text();
        }
        job_=job.release();
        setBusy(true);progress_->setValue(0);status_->setText("İşleniyor...");
        connect(job_,&Job::percent,progress_,&QProgressBar::setValue);
        connect(job_,&Job::finishedJob,this,[this](bool ok,const QString &message,bool needPassword){
            status_->setText(message);setBusy(false);
            if(ok)progress_->setValue(100);
            auto *completed=job_;job_=nullptr;completed->wait();completed->deleteLater();
            if(ok&&completed->action==Job::Pack)refreshInfo();
            QMessageBox::information(this,ok?"Tamamlandı":"İşlem başarısız",message);
            if(needPassword){joinPassword_->setEnabled(true);joinPassword_->setFocus();joinPassword_->selectAll();}
        });
        job_->start();
    }
};
int main(int argc,char **argv){
    QApplication app(argc,argv);app.setApplicationName("Dosya Böl");app.setOrganizationName("Yaser Sayici");
    Window window;window.show();return app.exec();
}
#include "main.moc"
