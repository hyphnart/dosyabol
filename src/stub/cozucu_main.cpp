// DosyaBolCozucu — Dosya Böl arşivlerini (DOSYA-BOL-2) açan bağımsız çözücü.
// Qt gerektirmez; statik CRT ile derlenir. Parçaların başına gömülebilir veya yanına konabilir.
// Yapımcı: Yaser Sayıcı
#ifdef _WIN32
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <conio.h>
#else
#include <termios.h>
#include <unistd.h>
#endif
#include "../common/dbcore.h"
#include <csignal>
#include <cstdio>
#include <iostream>

using namespace dbol;

static volatile std::sig_atomic_t g_cancel = 0;
static void onSignal(int) { g_cancel = 1; }

#ifdef _WIN32
static std::string narrow(const std::wstring &w) {
    if (w.empty()) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), nullptr, 0, nullptr, nullptr);
    std::string s(size_t(n), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), int(w.size()), s.data(), n, nullptr, nullptr);
    return s;
}
#endif

static bool inputIsConsole() {
#ifdef _WIN32
    DWORD m = 0;
    return GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), &m) != 0;
#else
    return isatty(0) != 0;
#endif
}

static void say(const std::string &s) {
    std::fwrite(s.data(), 1, s.size(), stdout);
    std::fflush(stdout);
}

static bool readLine(std::string &out) {
#ifdef _WIN32
    if (inputIsConsole()) {
        wchar_t b[2048];
        DWORD n = 0;
        if (!ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE), b, 2047, &n, nullptr) || n == 0) return false;
        std::wstring w(b, n);
        while (!w.empty() && (w.back() == L'\r' || w.back() == L'\n')) w.pop_back();
        out = narrow(w);
        return true;
    }
#endif
    if (!std::getline(std::cin, out)) return false;
    while (!out.empty() && (out.back() == '\r' || out.back() == '\n')) out.pop_back();
    return true;
}

static bool readPassword(std::string &out) {
#ifdef _WIN32
    if (inputIsConsole()) {
        std::wstring w;
        for (;;) {
            const wint_t c = _getwch();
            if (c == L'\r' || c == L'\n') break;
            if (c == 3) { g_cancel = 1; return false; }
            if (c == 8) { if (!w.empty()) w.pop_back(); continue; }
            if (c == 0 || c == 0xE0) { _getwch(); continue; }
            w.push_back(wchar_t(c));
        }
        say("\n");
        out = narrow(w);
        return true;
    }
#else
    if (isatty(0)) {
        termios old{}, t{};
        tcgetattr(0, &old);
        t = old;
        t.c_lflag &= ~tcflag_t(ECHO);
        tcsetattr(0, TCSANOW, &t);
        const bool ok = readLine(out);
        tcsetattr(0, TCSANOW, &old);
        say("\n");
        return ok;
    }
#endif
    return readLine(out);
}

static fs::path selfPath() {
#ifdef _WIN32
    std::wstring buf(32768, L'\0');
    const DWORD n = GetModuleFileNameW(nullptr, buf.data(), DWORD(buf.size()));
    buf.resize(n);
    return fs::path(buf);
#else
    std::error_code ec;
    return fs::read_symlink("/proc/self/exe", ec);
#endif
}

static std::string trim(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.pop_back();
    size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
    s.erase(0, i);
    if (s.size() >= 2 && s.front() == '"' && s.back() == '"') s = s.substr(1, s.size() - 2);
    return s;
}

static std::string mib(uint64_t b) {
    char buf[64];
    std::snprintf(buf, sizeof buf, "%.2f MiB", double(b) / (1024.0 * 1024.0));
    return buf;
}

static void pause(bool interactive) {
    if (!interactive) return;
    say("\nÇıkmak için Enter'a basın...");
    std::string dummy;
    readLine(dummy);
}

static int run(const std::vector<std::string> &args) {
    std::signal(SIGINT, onSignal);
    fs::path outDir;
    bool hasOut = false, verifyOnly = false;
    std::string positional;
    for (size_t i = 0; i < args.size(); ++i) {
        const std::string &a = args[i];
        if ((a == "--cikis" || a == "--out") && i + 1 < args.size()) { outDir = fs::absolute(fromUtf8(args[++i])); hasOut = true; }
        else if (a == "--dogrula" || a == "--verify") verifyOnly = true;
        else if (a == "--yardim" || a == "--help" || a == "-h") {
            say("Kullanım: DosyaBolCozucu [parça_dosyası_veya_klasör] [--cikis klasör] [--dogrula]\n"
                "Parametresiz çalıştırılırsa kendi klasöründeki Dosya Böl parçalarını bulur.\n");
            return 0;
        } else positional = a;
    }
    const bool interactive = args.empty() && inputIsConsole();

    say("DOSYA BÖL — Çözücü   (Yapımcı: Yaser Sayıcı)\n\n");
    const fs::path self = selfPath();
    PartInfo own;
    const bool hasOwn = !self.empty() && readPartInfo(self, own);

    std::vector<Archive> list;
    fs::path baseDir;
    if (!positional.empty()) {
        const fs::path p = fs::absolute(fromUtf8(trim(positional)));
        std::error_code ec;
        if (fs::is_directory(p, ec)) { baseDir = p; list = scanDirectory(p); }
        else {
            Archive a;
            std::string err;
            if (!loadArchiveFromPart(p, a, err)) { say(err + "\n"); return 1; }
            baseDir = p.parent_path();
            list.push_back(std::move(a));
        }
    } else {
        baseDir = self.parent_path();
        list = hasOwn ? scanDirectory(baseDir, &own.id) : scanDirectory(baseDir);
    }
    if (list.empty()) {
        say("Bu klasörde Dosya Böl parçası bulunamadı:\n  " + toUtf8(baseDir) + "\n");
        pause(interactive);
        return 1;
    }
    size_t pick = 0;
    if (list.size() > 1) {
        say("Birden fazla arşiv bulundu:\n");
        for (size_t i = 0; i < list.size(); ++i) {
            const Archive &a = list[i];
            say("  " + std::to_string(i + 1) + ") " + toUtf8(a.parts.front().path.filename()) + " — " + std::to_string(a.parts.size()) + " parça" + (a.encrypted ? ", şifreli" : "") + "\n");
        }
        for (;;) {
            say("Hangisi? [1-" + std::to_string(list.size()) + "]: ");
            std::string line;
            if (!readLine(line)) return 1;
            const int v = std::atoi(trim(line).c_str());
            if (v >= 1 && size_t(v) <= list.size()) { pick = size_t(v - 1); break; }
        }
    }
    const Archive &arc = list[pick];
    if (!arc.ok()) {
        say("Arşiv eksik veya bozuk: ");
        if (!arc.problem.empty()) say(arc.problem + "\n");
        else say("şu parça numaraları bulunamadı: " + missingText(arc) + "\n");
        say("Tüm parçaları aynı klasöre koyup tekrar deneyin.\n");
        pause(interactive);
        return 2;
    }
    say(std::to_string(arc.parts.size()) + " parça bulundu" + (arc.encrypted ? " (şifreli)." : ".") + "\n");

    if (!verifyOnly && !hasOut) {
        const fs::path def = baseDir / "Cozulen";
        say("Çıkış klasörü [Enter = " + toUtf8(def) + "]: ");
        std::string line;
        if (!readLine(line)) return 1;
        line = trim(line);
        outDir = line.empty() ? def : fs::absolute(fromUtf8(line));
    }

    int lastPct = -1;
    Options o;
    o.outDir = outDir;
    o.write = !verifyOnly;
    o.cancelled = [] { return g_cancel != 0; };
    o.progress = [&](uint64_t done, uint64_t total) {
        const int pct = total ? int(double(done) * 100.0 / double(total)) : 100;
        if (pct != lastPct) { lastPct = pct; say("\r  İşleniyor... %" + std::to_string(pct)); }
    };

    int attempts = 0;
    Result r;
    for (;;) {
        if (arc.encrypted && o.password.empty()) {
            say("Şifre: ");
            if (!readPassword(o.password)) { say("\nİptal edildi.\n"); return 3; }
            if (o.password.empty()) { if (++attempts >= 3) return 1; continue; }
        }
        lastPct = -1;
        r = process(arc, o);
        if (lastPct >= 0) say("\n");
        if (r.st == Status::WrongPassword) {
            say("Şifre yanlış.\n");
            o.password.clear();
            if (++attempts >= 3) { say("Çok fazla hatalı deneme.\n"); pause(interactive); return 1; }
            continue;
        }
        break;
    }
    if (r.st != Status::Ok) {
        say(std::string(r.st == Status::Cancelled ? "" : "HATA: ") + r.msg + "\n");
        pause(interactive);
        return r.st == Status::Cancelled ? 3 : 1;
    }
    if (verifyOnly) say("Arşiv doğrulandı: " + std::to_string(r.files) + " dosya, " + mib(r.bytes) + ".\n");
    else say("Tamamlandı: " + std::to_string(r.files) + " dosya, " + std::to_string(r.dirs) + " klasör, " + mib(r.bytes) + "\n  → " + toUtf8(outDir) + "\n");
    pause(interactive);
    return 0;
}

#ifdef _WIN32
int wmain(int argc, wchar_t **argv) {
    const UINT oldCp = GetConsoleOutputCP();
    SetConsoleOutputCP(CP_UTF8);
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.push_back(narrow(argv[i]));
    int rc = 1;
    try { rc = run(args); } catch (const std::exception &e) { say(std::string("Beklenmeyen hata: ") + e.what() + "\n"); }
    SetConsoleOutputCP(oldCp);
    return rc;
}
#else
int main(int argc, char **argv) {
    std::vector<std::string> args;
    for (int i = 1; i < argc; ++i) args.emplace_back(argv[i]);
    try { return run(args); } catch (const std::exception &e) { say(std::string("Beklenmeyen hata: ") + e.what() + "\n"); }
    return 1;
}
#endif
