#pragma once
// Dosya Böl — ortak çekirdek (Qt'ten bağımsız).
// SHA-256, HMAC-SHA256, PBKDF2, ChaCha20, zlib/inflate ve DOSYA-BOL-2 arşiv okuyucusu.
// Hem DosyaBol.exe (Qt) hem de DosyaBolCozucu.exe (bağımsız çözücü) bu dosyayı kullanır.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace dbol {
namespace fs = std::filesystem;
using Bytes = std::vector<uint8_t>;
using Id16 = std::array<uint8_t, 16>;
using Hash32 = std::array<uint8_t, 32>;

// ---------------------------------------------------------------- biçim sabitleri
//
// Parça dosyası:  [çözücü exe (isteğe bağlı)] [başlık 64B] [dilim] [kuyruk 64B]
// Dilim'lerin art arda eklenmesi "akış"ı verir. Akış, bloklardan oluşur:
//   blok = u32 rawLen | u32 storedLen | u8 yöntem(0 ham,1 zlib) | veri | (şifreliyse 32B HMAC)
// Bloklar açılınca düz akış çıkar:
//   u32 girdiSayısı | girdiler (u8 tür, u16 yolUzunluğu, yol, u64 boyut, i64 mtime) |
//   dosya verileri (girdi sırasıyla) | 32B SHA-256 (önceki tüm düz akış)
constexpr size_t kHeaderSize = 64;
constexpr size_t kTailSize = 64;
constexpr uint32_t kBlockMax = 1u << 20;
constexpr uint32_t kMaxEntries = 2000000;
constexpr uint32_t kMaxPath = 4096;
constexpr uint32_t kDefaultKdf = 200000;
constexpr uint8_t kFlagEncrypted = 1;
constexpr uint8_t kTailLast = 1;
inline const char kHeaderMagic[8] = {'D', 'O', 'S', 'Y', 'A', 'B', 'L', '2'};
inline const char kTailMagic[8] = {'D', 'B', 'O', 'L', 'T', 'A', 'I', 'L'};

inline uint32_t rd32(const uint8_t *p) { return p[0] | uint32_t(p[1]) << 8 | uint32_t(p[2]) << 16 | uint32_t(p[3]) << 24; }
inline uint64_t rd64(const uint8_t *p) { return rd32(p) | uint64_t(rd32(p + 4)) << 32; }
inline void wr32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; ++i) p[i] = uint8_t(v >> (8 * i)); }
inline void wr64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; ++i) p[i] = uint8_t(v >> (8 * i)); }

// ---------------------------------------------------------------- SHA-256
class Sha256 {
    uint32_t h_[8];
    uint8_t buf_[64];
    uint64_t len_ = 0;
    size_t fill_ = 0;
    static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void block(const uint8_t *p) {
        static const uint32_t K[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = uint32_t(p[4 * i]) << 24 | uint32_t(p[4 * i + 1]) << 16 | uint32_t(p[4 * i + 2]) << 8 | p[4 * i + 3];
        for (int i = 16; i < 64; ++i) {
            const uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
        for (int i = 0; i < 64; ++i) {
            const uint32_t t1 = h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
            const uint32_t t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
    }
public:
    Sha256() {
        static const uint32_t init[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
        std::memcpy(h_, init, sizeof h_);
    }
    void update(const void *data, size_t n) {
        const uint8_t *p = static_cast<const uint8_t *>(data);
        len_ += n;
        if (fill_) {
            const size_t t = std::min(n, size_t(64) - fill_);
            std::memcpy(buf_ + fill_, p, t); fill_ += t; p += t; n -= t;
            if (fill_ == 64) { block(buf_); fill_ = 0; }
        }
        while (n >= 64) { block(p); p += 64; n -= 64; }
        if (n) { std::memcpy(buf_, p, n); fill_ = n; }
    }
    // Durumu bozmaz; kopya üzerinde sonuçlandırır.
    Hash32 digest() const {
        Sha256 s = *this;
        const uint64_t bits = s.len_ * 8;
        const uint8_t pad = 0x80;
        s.update(&pad, 1);
        const uint8_t zero = 0;
        while (s.fill_ != 56) s.update(&zero, 1);
        uint8_t lenBytes[8];
        for (int i = 0; i < 8; ++i) lenBytes[i] = uint8_t(bits >> (56 - 8 * i));
        s.update(lenBytes, 8);
        Hash32 out{};
        for (int i = 0; i < 8; ++i) { out[4 * i] = uint8_t(s.h_[i] >> 24); out[4 * i + 1] = uint8_t(s.h_[i] >> 16); out[4 * i + 2] = uint8_t(s.h_[i] >> 8); out[4 * i + 3] = uint8_t(s.h_[i]); }
        return out;
    }
};

class Hmac {
    Sha256 in_, out_;
public:
    Hmac(const uint8_t *key, size_t kl) {
        uint8_t k[64] = {0};
        if (kl > 64) { Sha256 s; s.update(key, kl); const Hash32 d = s.digest(); std::memcpy(k, d.data(), 32); }
        else if (kl) std::memcpy(k, key, kl);
        uint8_t ip[64], op[64];
        for (int i = 0; i < 64; ++i) { ip[i] = k[i] ^ 0x36; op[i] = k[i] ^ 0x5c; }
        in_.update(ip, 64); out_.update(op, 64);
    }
    void update(const void *p, size_t n) { in_.update(p, n); }
    Hash32 digest() const { const Hash32 ih = in_.digest(); Sha256 o = out_; o.update(ih.data(), 32); return o.digest(); }
};

inline Bytes pbkdf2(const uint8_t *pw, size_t pl, const uint8_t *salt, size_t sl, uint32_t iterations, size_t outLen) {
    const Hmac base(pw, pl);
    Bytes out;
    for (uint32_t blk = 1; out.size() < outLen; ++blk) {
        Hmac h = base;
        h.update(salt, sl);
        const uint8_t be[4] = {uint8_t(blk >> 24), uint8_t(blk >> 16), uint8_t(blk >> 8), uint8_t(blk)};
        h.update(be, 4);
        Hash32 u = h.digest(), t = u;
        for (uint32_t i = 1; i < iterations; ++i) {
            Hmac h2 = base;
            h2.update(u.data(), 32);
            u = h2.digest();
            for (int j = 0; j < 32; ++j) t[j] ^= u[j];
        }
        out.insert(out.end(), t.begin(), t.end());
    }
    out.resize(outLen);
    return out;
}

// RFC 8439 ChaCha20 (şifreleme ve çözme aynı işlemdir).
inline void chacha20Xor(const uint8_t key[32], const uint8_t nonce[12], uint32_t counter, uint8_t *data, size_t n) {
    uint32_t st[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 8; ++i) st[4 + i] = rd32(key + 4 * i);
    st[12] = counter;
    for (int i = 0; i < 3; ++i) st[13 + i] = rd32(nonce + 4 * i);
    auto rotl = [](uint32_t x, int c) { return (x << c) | (x >> (32 - c)); };
    auto qr = [&](uint32_t *x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl(x[d], 16);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl(x[b], 12);
        x[a] += x[b]; x[d] ^= x[a]; x[d] = rotl(x[d], 8);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = rotl(x[b], 7);
    };
    uint8_t ks[64];
    while (n) {
        uint32_t x[16];
        std::memcpy(x, st, sizeof x);
        for (int r = 0; r < 10; ++r) {
            qr(x, 0, 4, 8, 12); qr(x, 1, 5, 9, 13); qr(x, 2, 6, 10, 14); qr(x, 3, 7, 11, 15);
            qr(x, 0, 5, 10, 15); qr(x, 1, 6, 11, 12); qr(x, 2, 7, 8, 13); qr(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; ++i) wr32(ks + 4 * i, x[i] + st[i]);
        const size_t m = std::min<size_t>(n, 64);
        for (size_t i = 0; i < m; ++i) data[i] ^= ks[i];
        data += m; n -= m; ++st[12];
    }
}

struct Keys { uint8_t enc[32]; uint8_t mac[32]; };
inline Keys deriveKeys(const std::string &password, const Id16 &salt, uint32_t iterations) {
    const Bytes dk = pbkdf2(reinterpret_cast<const uint8_t *>(password.data()), password.size(), salt.data(), salt.size(), iterations, 64);
    Keys k{};
    std::memcpy(k.enc, dk.data(), 32);
    std::memcpy(k.mac, dk.data() + 32, 32);
    return k;
}
// Başlıkta saklanan 8 baytlık anahtar kontrolü: yanlış şifreyi, veri okumadan ve bozulmadan ayırt eder.
inline std::array<uint8_t, 8> keyCheck(const Keys &k) {
    Hmac h(k.mac, 32);
    h.update("DOSYABOL-KEYCHECK", 17);
    const Hash32 d = h.digest();
    std::array<uint8_t, 8> out{};
    std::memcpy(out.data(), d.data(), 8);
    return out;
}
inline void blockNonce(uint8_t nonce[12], uint64_t blockIndex) { std::memset(nonce, 0, 4); wr64(nonce + 4, blockIndex); }
inline bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; ++i) d |= a[i] ^ b[i];
    return d == 0;
}
// Bir bloğun kimlik doğrulama etiketi: HMAC(macKey, blokNo | başlık(9B) | şifreli veri)
inline Hash32 blockMac(const Keys &k, uint64_t blockIndex, const uint8_t header[9], const uint8_t *cipher, size_t n) {
    Hmac h(k.mac, 32);
    uint8_t idx[8];
    wr64(idx, blockIndex);
    h.update(idx, 8); h.update(header, 9); h.update(cipher, n);
    return h.digest();
}

// ---------------------------------------------------------------- zlib / inflate
class Inflater {
    struct Huff { std::vector<uint16_t> tab = std::vector<uint16_t>(1u << 15); int bits = 1; };
    Huff lit_, dist_, cl_, fixLit_, fixDist_;
    bool fixedBuilt_ = false;
    const uint8_t *p_ = nullptr, *end_ = nullptr;
    uint64_t buf_ = 0;
    int cnt_ = 0;

    void fill() { while (cnt_ <= 56 && p_ < end_) { buf_ |= uint64_t(*p_++) << cnt_; cnt_ += 8; } }
    void drop(int n) { buf_ >>= n; cnt_ -= n; }
    int bits(int n) {
        if (n == 0) return 0;
        fill();
        if (cnt_ < n) return -1;
        const int v = int(buf_ & ((1ull << n) - 1));
        drop(n);
        return v;
    }
    int sym(const Huff &h) {
        fill();
        const uint16_t e = h.tab[buf_ & ((1u << h.bits) - 1)];
        const int l = e & 15;
        if (l == 0 || l > cnt_) return -1;
        drop(l);
        return e >> 4;
    }
    static bool build(Huff &h, const uint8_t *lens, int n) {
        int count[16] = {0};
        for (int i = 0; i < n; ++i) ++count[lens[i]];
        count[0] = 0;
        int maxl = 0;
        for (int l = 15; l >= 1; --l) if (count[l]) { maxl = l; break; }
        if (maxl == 0) { h.bits = 1; h.tab[0] = h.tab[1] = 0; return true; }
        int left = 1;
        for (int l = 1; l <= 15; ++l) { left <<= 1; left -= count[l]; if (left < 0) return false; }
        uint32_t next[16] = {0}, code = 0;
        for (int l = 1; l <= 15; ++l) { code = (code + count[l - 1]) << 1; next[l] = code; }
        h.bits = maxl;
        const uint32_t size = 1u << maxl;
        std::fill(h.tab.begin(), h.tab.begin() + size, uint16_t(0));
        for (int s = 0; s < n; ++s) {
            const int l = lens[s];
            if (!l) continue;
            const uint32_t c = next[l]++;
            uint32_t r = 0;
            for (int k = 0; k < l; ++k) r |= ((c >> k) & 1u) << (l - 1 - k);
            for (uint32_t i = r; i < size; i += 1u << l) h.tab[i] = uint16_t((s << 4) | l);
        }
        return true;
    }
    static uint32_t adler32(const uint8_t *d, size_t n) {
        uint32_t a = 1, b = 0;
        while (n) {
            const size_t t = std::min<size_t>(n, 5552);
            for (size_t i = 0; i < t; ++i) { a += d[i]; b += a; }
            a %= 65521; b %= 65521; d += t; n -= t;
        }
        return (b << 16) | a;
    }
public:
    // zlib akışını (RFC1950) tam olarak outLen bayta açar; aksi halde false.
    bool run(const uint8_t *in, size_t inLen, uint8_t *out, size_t outLen) {
        static const uint16_t lbase[29] = {3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
        static const uint8_t lext[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
        static const uint16_t dbase[30] = {1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
        static const uint8_t dext[30] = {0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
        static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15};
        if (inLen < 6) return false;
        if (((in[0] << 8) | in[1]) % 31 != 0 || (in[0] & 15) != 8 || (in[1] & 0x20)) return false;
        p_ = in + 2; end_ = in + inLen; buf_ = 0; cnt_ = 0;
        if (!fixedBuilt_) {
            uint8_t l[288];
            for (int i = 0; i < 144; ++i) l[i] = 8;
            for (int i = 144; i < 256; ++i) l[i] = 9;
            for (int i = 256; i < 280; ++i) l[i] = 7;
            for (int i = 280; i < 288; ++i) l[i] = 8;
            build(fixLit_, l, 288);
            uint8_t d[30];
            for (int i = 0; i < 30; ++i) d[i] = 5;
            build(fixDist_, d, 30);
            fixedBuilt_ = true;
        }
        size_t op = 0;
        for (;;) {
            const int fin = bits(1), type = bits(2);
            if (fin < 0 || type < 0) return false;
            if (type == 0) {
                drop(cnt_ & 7);
                const int len = bits(16), nlen = bits(16);
                if (len < 0 || nlen < 0 || len != (~nlen & 0xffff) || op + size_t(len) > outLen) return false;
                int left = len;
                while (left && cnt_ >= 8) { out[op++] = uint8_t(buf_ & 255); drop(8); --left; }
                if (left) {
                    if (size_t(end_ - p_) < size_t(left)) return false;
                    std::memcpy(out + op, p_, size_t(left)); p_ += left; op += size_t(left);
                }
            } else if (type == 1 || type == 2) {
                const Huff *lh = &fixLit_, *dh = &fixDist_;
                if (type == 2) {
                    const int hlit = bits(5), hdist = bits(5), hclen = bits(4);
                    if (hlit < 0 || hdist < 0 || hclen < 0) return false;
                    const int nlit = hlit + 257, ndist = hdist + 1, ncl = hclen + 4;
                    if (nlit > 286 || ndist > 30) return false;
                    uint8_t cl[19] = {0};
                    for (int i = 0; i < ncl; ++i) { const int v = bits(3); if (v < 0) return false; cl[order[i]] = uint8_t(v); }
                    if (!build(cl_, cl, 19)) return false;
                    uint8_t lens[320] = {0};
                    int i = 0;
                    while (i < nlit + ndist) {
                        const int s = sym(cl_);
                        if (s < 0) return false;
                        if (s < 16) { lens[i++] = uint8_t(s); continue; }
                        int rep = 0, val = 0;
                        if (s == 16) { if (i == 0) return false; val = lens[i - 1]; const int b = bits(2); if (b < 0) return false; rep = 3 + b; }
                        else if (s == 17) { const int b = bits(3); if (b < 0) return false; rep = 3 + b; }
                        else { const int b = bits(7); if (b < 0) return false; rep = 11 + b; }
                        if (i + rep > nlit + ndist) return false;
                        while (rep--) lens[i++] = uint8_t(val);
                    }
                    if (lens[256] == 0) return false;
                    if (!build(lit_, lens, nlit) || !build(dist_, lens + nlit, ndist)) return false;
                    lh = &lit_; dh = &dist_;
                }
                for (;;) {
                    int s = sym(*lh);
                    if (s < 0) return false;
                    if (s < 256) { if (op >= outLen) return false; out[op++] = uint8_t(s); }
                    else if (s == 256) break;
                    else {
                        s -= 257;
                        if (s >= 29) return false;
                        const int eb = bits(lext[s]);
                        if (eb < 0) return false;
                        const size_t len = lbase[s] + size_t(eb);
                        const int ds = sym(*dh);
                        if (ds < 0 || ds >= 30) return false;
                        const int db = bits(dext[ds]);
                        if (db < 0) return false;
                        const size_t dist = dbase[ds] + size_t(db);
                        if (dist > op || op + len > outLen) return false;
                        for (size_t k = 0; k < len; ++k, ++op) out[op] = out[op - dist];
                    }
                }
            } else return false;
            if (fin) break;
        }
        if (op != outLen) return false;
        drop(cnt_ & 7);
        uint32_t expect = 0;
        for (int i = 0; i < 4; ++i) { const int v = bits(8); if (v < 0) return false; expect = (expect << 8) | uint32_t(v); }
        return expect == adler32(out, outLen);
    }
};

// ---------------------------------------------------------------- yol güvenliği
inline bool validUtf8(const std::string &s) {
    size_t i = 0;
    while (i < s.size()) {
        const uint8_t c = uint8_t(s[i]);
        int n = 0;
        uint32_t cp = 0;
        if (c < 0x80) { ++i; continue; }
        else if ((c & 0xE0) == 0xC0) { n = 1; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { n = 2; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { n = 3; cp = c & 0x07; }
        else return false;
        if (i + size_t(n) >= s.size()) return false;
        for (int k = 1; k <= n; ++k) {
            const uint8_t cc = uint8_t(s[i + size_t(k)]);
            if ((cc & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (cc & 0x3F);
        }
        if ((n == 1 && cp < 0x80) || (n == 2 && cp < 0x800) || (n == 3 && cp < 0x10000) || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += size_t(n) + 1;
    }
    return true;
}

// Arşivdeki göreli yol: '/' ayraçlı, mutlak/üst dizin/Windows'ta sorunlu adlar yok.
inline bool safeRelPath(const std::string &p) {
    if (p.empty() || p.size() > kMaxPath || !validUtf8(p) || p.front() == '/') return false;
    size_t start = 0;
    while (start <= p.size()) {
        size_t slash = p.find('/', start);
        if (slash == std::string::npos) slash = p.size();
        const std::string c = p.substr(start, slash - start);
        if (c.empty() || c.size() > 255 || c == "." || c == "..") return false;
        if (c.back() == ' ' || c.back() == '.') return false;
        for (const char ch : c) {
            const uint8_t u = uint8_t(ch);
            if (u < 0x20 || u == 0x7f || ch == '\\' || ch == ':' || ch == '*' || ch == '?' || ch == '"' || ch == '<' || ch == '>' || ch == '|') return false;
        }
        std::string stem = c.substr(0, c.find('.'));
        for (char &ch : stem) if (ch >= 'a' && ch <= 'z') ch = char(ch - 32);
        if (stem == "CON" || stem == "PRN" || stem == "AUX" || stem == "NUL") return false;
        if (stem.size() == 4 && (stem.compare(0, 3, "COM") == 0 || stem.compare(0, 3, "LPT") == 0) && stem[3] >= '1' && stem[3] <= '9') return false;
        if (slash == p.size()) break;
        start = slash + 1;
    }
    return true;
}
inline fs::path fromUtf8(const std::string &s) { return fs::path(std::u8string(reinterpret_cast<const char8_t *>(s.data()), s.size())); }
inline std::string toUtf8(const fs::path &p) { const auto u = p.u8string(); return std::string(u.begin(), u.end()); }

// ---------------------------------------------------------------- parça ve arşiv bulma
struct PartInfo {
    fs::path path;
    uint64_t fileSize = 0, payloadOffset = 0, sliceLen = 0;
    uint32_t index = 0, count = 0, kdf = 0;
    uint8_t flags = 0;
    bool last = false;
    Id16 id{}, salt{};
    std::array<uint8_t, 8> check{};
    Hash32 sha{};
};

inline bool readPartInfo(const fs::path &path, PartInfo &pi) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return false;
    const uint64_t size = fs::file_size(path, ec);
    if (ec || size < kHeaderSize + kTailSize) return false;
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    uint8_t t[kTailSize];
    f.seekg(std::streamoff(size - kTailSize));
    f.read(reinterpret_cast<char *>(t), kTailSize);
    if (f.gcount() != std::streamsize(kTailSize) || std::memcmp(t, kTailMagic, 8) != 0) return false;
    const uint64_t off = rd64(t + 8), slice = rd64(t + 16);
    if (off > size || slice > size || off + kHeaderSize + slice + kTailSize != size) return false;
    uint8_t h[kHeaderSize];
    f.seekg(std::streamoff(off));
    f.read(reinterpret_cast<char *>(h), kHeaderSize);
    if (f.gcount() != std::streamsize(kHeaderSize) || std::memcmp(h, kHeaderMagic, 8) != 0) return false;
    pi.path = path; pi.fileSize = size; pi.payloadOffset = off; pi.sliceLen = slice;
    pi.flags = h[8]; pi.index = rd32(h + 12); pi.count = rd32(h + 16); pi.kdf = rd32(h + 20);
    std::memcpy(pi.id.data(), h + 24, 16);
    std::memcpy(pi.salt.data(), h + 40, 16);
    std::memcpy(pi.check.data(), h + 56, 8);
    pi.last = (t[24] & kTailLast) != 0;
    std::memcpy(pi.sha.data(), t + 32, 32);
    return pi.index >= 1;
}

struct Archive {
    Id16 id{};
    std::vector<PartInfo> parts;
    uint32_t count = 0;
    bool encrypted = false;
    std::vector<uint32_t> missing;
    std::string problem;
    bool ok() const { return problem.empty() && missing.empty() && count > 0 && !parts.empty(); }
};

inline void finalizeArchive(Archive &a) {
    std::sort(a.parts.begin(), a.parts.end(), [](const PartInfo &x, const PartInfo &y) { return x.index < y.index; });
    const PartInfo &first = a.parts.front();
    a.id = first.id;
    a.encrypted = (first.flags & kFlagEncrypted) != 0;
    uint32_t declared = 0, lastIdx = 0;
    for (size_t i = 0; i < a.parts.size(); ++i) {
        const PartInfo &p = a.parts[i];
        if (p.flags != first.flags || p.kdf != first.kdf || p.salt != first.salt || p.check != first.check) { a.problem = "Parçaların şifreleme bilgileri birbiriyle uyuşmuyor."; return; }
        if (i && p.index == a.parts[i - 1].index) {
            a.problem = std::to_string(p.index) + ". parça birden fazla kopya olarak bulundu: " + toUtf8(a.parts[i - 1].path.filename()) + " ve " + toUtf8(p.path.filename());
            return;
        }
        if (p.count) { if (declared && declared != p.count) { a.problem = "Parçalardaki toplam parça sayısı uyuşmuyor."; return; } declared = p.count; }
        if (p.last) lastIdx = p.index;
    }
    if (!declared) declared = lastIdx;
    a.count = declared;
    if (!declared) { a.problem = "Son parça bulunamadı; arşiv eksik."; return; }
    if (lastIdx && lastIdx != declared) { a.problem = "Son parça numarası toplam parça sayısıyla uyuşmuyor."; return; }
    if (a.parts.back().index > declared) { a.problem = "Beklenenden büyük numaralı parça var."; return; }
    size_t k = 0;
    for (uint32_t i = 1; i <= declared; ++i) {
        if (k < a.parts.size() && a.parts[k].index == i) ++k;
        else a.missing.push_back(i);
    }
}

inline std::vector<Archive> scanDirectory(const fs::path &dir, const Id16 *only = nullptr) {
    std::map<Id16, Archive> found;
    std::error_code ec;
    for (fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec), end; !ec && it != end; it.increment(ec)) {
        PartInfo pi;
        if (!readPartInfo(it->path(), pi)) continue;
        if (only && pi.id != *only) continue;
        found[pi.id].parts.push_back(pi);
    }
    std::vector<Archive> list;
    for (auto &kv : found) { finalizeArchive(kv.second); list.push_back(std::move(kv.second)); }
    return list;
}

inline bool loadArchiveFromPart(const fs::path &part, Archive &out, std::string &err) {
    PartInfo pi;
    if (!readPartInfo(part, pi)) { err = "Bu dosya bir Dosya Böl parçası değil."; return false; }
    fs::path dir = part.parent_path();
    if (dir.empty()) dir = ".";
    std::vector<Archive> list = scanDirectory(dir, &pi.id);
    if (list.empty()) { err = "Parçalar okunamadı."; return false; }
    out = std::move(list.front());
    return true;
}

inline std::string missingText(const Archive &a) {
    std::string s;
    for (size_t i = 0; i < a.missing.size(); ++i) {
        if (i == 12) { s += ", ..."; break; }
        if (i) s += ", ";
        s += std::to_string(a.missing[i]);
    }
    return s;
}

// ---------------------------------------------------------------- okuma / çıkarma
enum class Status { Ok, Cancelled, NeedPassword, WrongPassword, Integrity, Error };
struct Options {
    std::string password;
    fs::path outDir;                 // write=true ise çıkış klasörü
    bool write = false;              // false: yalnızca doğrula
    std::function<void(uint64_t, uint64_t)> progress;
    std::function<bool()> cancelled;
};
struct Result {
    Status st = Status::Ok;
    std::string msg;
    uint64_t files = 0, dirs = 0, bytes = 0;
};

class PartReader {
    const std::vector<PartInfo> &parts_;
    size_t cur_ = 0;
    uint64_t remain_ = 0;
    std::ifstream f_;
    bool next() {
        while (remain_ == 0) {
            if (cur_ >= parts_.size()) { error = "Parçalar beklenenden önce bitti."; return false; }
            const PartInfo &p = parts_[cur_++];
            f_.close(); f_.clear();
            f_.open(p.path, std::ios::binary);
            if (!f_) { error = "Parça açılamadı: " + toUtf8(p.path.filename()); return false; }
            f_.seekg(std::streamoff(p.payloadOffset + kHeaderSize));
            remain_ = p.sliceLen;
        }
        return true;
    }
public:
    std::string error;
    explicit PartReader(const std::vector<PartInfo> &p) : parts_(p) {}
    bool read(uint8_t *dst, size_t n) {
        while (n) {
            if (!next()) return false;
            const size_t t = size_t(std::min<uint64_t>(n, remain_));
            f_.read(reinterpret_cast<char *>(dst), std::streamsize(t));
            if (f_.gcount() != std::streamsize(t)) { error = "Parça okunamadı (dosya değişmiş olabilir)."; return false; }
            remain_ -= t; n -= t; dst += t;
        }
        return true;
    }
    bool atEnd() const {
        if (remain_) return false;
        for (size_t i = cur_; i < parts_.size(); ++i) if (parts_[i].sliceLen) return false;
        return true;
    }
};

class BlockStream {
    PartReader &rd_;
    bool enc_;
    const Keys *keys_;
    uint64_t blockIndex_ = 0;
    Bytes cur_;
    size_t pos_ = 0;
    Inflater infl_;
    bool fail(Status s, const std::string &m) { status = s; error = m; return false; }
    bool load() {
        uint8_t hd[9];
        if (!rd_.read(hd, 9)) return fail(Status::Integrity, "Arşiv beklenenden önce bitti. " + rd_.error);
        const uint32_t raw = rd32(hd), stored = rd32(hd + 4);
        const uint8_t method = hd[8];
        if (raw == 0 || raw > kBlockMax || stored == 0 || stored > raw || method > 1 || (method == 0 && stored != raw) || (method == 1 && stored >= raw))
            return fail(Status::Integrity, "Blok başlığı geçersiz (veri bozuk).");
        Bytes data(stored);
        if (!rd_.read(data.data(), stored)) return fail(Status::Integrity, "Blok okunamadı. " + rd_.error);
        if (enc_) {
            uint8_t mac[32];
            if (!rd_.read(mac, 32)) return fail(Status::Integrity, "Blok etiketi okunamadı. " + rd_.error);
            const Hash32 want = blockMac(*keys_, blockIndex_, hd, data.data(), data.size());
            if (!constantTimeEqual(want.data(), mac, 32))
                return fail(Status::Integrity, "Blok doğrulaması başarısız (veri bozuk veya değiştirilmiş).");
            uint8_t nonce[12];
            blockNonce(nonce, blockIndex_);
            chacha20Xor(keys_->enc, nonce, 0, data.data(), data.size());
        }
        if (method == 1) {
            cur_.assign(raw, 0);
            if (!infl_.run(data.data(), data.size(), cur_.data(), raw)) return fail(Status::Integrity, "Sıkıştırılmış blok bozuk.");
        } else cur_ = std::move(data);
        pos_ = 0;
        ++blockIndex_;
        return true;
    }
public:
    Status status = Status::Ok;
    std::string error;
    BlockStream(PartReader &r, bool enc, const Keys *k) : rd_(r), enc_(enc), keys_(k) {}
    bool read(uint8_t *dst, size_t n, Sha256 *h) {
        while (n) {
            if (pos_ == cur_.size() && !load()) return false;
            const size_t t = std::min(n, cur_.size() - pos_);
            std::memcpy(dst, cur_.data() + pos_, t);
            if (h) h->update(dst, t);
            pos_ += t; dst += t; n -= t;
        }
        return true;
    }
    bool drained() const { return pos_ == cur_.size() && rd_.atEnd(); }
};

// Her parçanın dilim SHA-256 değerini kuyruktaki kayıtla karşılaştırır (şifre gerekmez).
inline Result verifyParts(const Archive &a, const std::function<void(uint64_t, uint64_t)> &progress = {}, const std::function<bool()> &cancelled = {}) {
    Result r;
    uint64_t total = 0, done = 0;
    for (const PartInfo &p : a.parts) total += p.sliceLen;
    Bytes buf(1u << 20);
    for (const PartInfo &p : a.parts) {
        std::ifstream f(p.path, std::ios::binary);
        if (!f) { r.st = Status::Error; r.msg = "Parça açılamadı: " + toUtf8(p.path.filename()); return r; }
        f.seekg(std::streamoff(p.payloadOffset + kHeaderSize));
        Sha256 h;
        uint64_t left = p.sliceLen;
        while (left) {
            if (cancelled && cancelled()) { r.st = Status::Cancelled; r.msg = "İşlem iptal edildi."; return r; }
            const size_t t = size_t(std::min<uint64_t>(left, buf.size()));
            f.read(reinterpret_cast<char *>(buf.data()), std::streamsize(t));
            if (f.gcount() != std::streamsize(t)) { r.st = Status::Integrity; r.msg = "Parça okunamadı: " + toUtf8(p.path.filename()); return r; }
            h.update(buf.data(), t); left -= t; done += t;
            if (progress) progress(done, total);
        }
        if (h.digest() != p.sha) { r.st = Status::Integrity; r.msg = std::to_string(p.index) + ". parça bozuk (SHA-256 uyuşmuyor): " + toUtf8(p.path.filename()); return r; }
    }
    r.msg = std::to_string(a.parts.size()) + " parçanın SHA-256 değerleri doğru.";
    return r;
}

namespace detail {
struct Entry { std::string rel; uint8_t kind = 1; uint64_t size = 0; int64_t mtime = 0; };
inline std::string lowerAscii(std::string s) { for (char &c : s) if (c >= 'A' && c <= 'Z') c = char(c + 32); return s; }

inline Result processImpl(const Archive &a, const Options &o) {
    Result R;
    auto fail = [&](Status s, std::string m) { R.st = s; R.msg = std::move(m); return R; };
    if (!a.problem.empty()) return fail(Status::Error, a.problem);
    if (!a.missing.empty()) return fail(Status::Error, "Eksik parça numaraları: " + missingText(a));
    if (!a.ok()) return fail(Status::Error, "Arşiv geçersiz.");
    Keys keys{};
    const bool enc = a.encrypted;
    if (enc) {
        if (o.password.empty()) return fail(Status::NeedPassword, "Bu arşiv şifreli; şifre gerekli.");
        keys = deriveKeys(o.password, a.parts.front().salt, a.parts.front().kdf);
        const auto kc = keyCheck(keys);
        if (!constantTimeEqual(kc.data(), a.parts.front().check.data(), 8)) return fail(Status::WrongPassword, "Şifre yanlış.");
    }
    PartReader rd(a.parts);
    BlockStream bs(rd, enc, enc ? &keys : nullptr);
    Sha256 plain;
    uint64_t consumed = 0, total = 0;
    auto bsFail = [&]() { return fail(bs.status, bs.error); };
    auto cancelled = [&]() { return o.cancelled && o.cancelled(); };

    uint8_t b4[4];
    if (!bs.read(b4, 4, &plain)) return bsFail();
    const uint32_t n = rd32(b4);
    if (n == 0 || n > kMaxEntries) return fail(Status::Integrity, "Dosya listesi geçersiz.");
    std::vector<Entry> entries;
    entries.reserve(std::min<uint32_t>(n, 100000));
    uint64_t indexBytes = 4, sumSizes = 0;
    for (uint32_t i = 0; i < n; ++i) {
        uint8_t h3[3];
        if (!bs.read(h3, 3, &plain)) return bsFail();
        Entry e;
        e.kind = h3[0];
        const uint32_t plen = h3[1] | uint32_t(h3[2]) << 8;
        if ((e.kind != 1 && e.kind != 2) || plen == 0 || plen > kMaxPath) return fail(Status::Integrity, "Dosya listesi bozuk.");
        e.rel.assign(plen, '\0');
        if (!bs.read(reinterpret_cast<uint8_t *>(e.rel.data()), plen, &plain)) return bsFail();
        uint8_t t16[16];
        if (!bs.read(t16, 16, &plain)) return bsFail();
        e.size = rd64(t16);
        e.mtime = int64_t(rd64(t16 + 8));
        if (!safeRelPath(e.rel)) return fail(Status::Integrity, "Arşivde güvensiz bir yol var, işlem durduruldu: " + e.rel);
        if (e.kind == 2 && e.size != 0) return fail(Status::Integrity, "Dosya listesi bozuk (klasör boyutu).");
        if (e.size > UINT64_MAX - sumSizes) return fail(Status::Integrity, "Dosya boyutları geçersiz.");
        sumSizes += e.size;
        indexBytes += 19 + plen;
        entries.push_back(std::move(e));
    }
    if (sumSizes > UINT64_MAX - indexBytes - 32) return fail(Status::Integrity, "Dosya boyutları geçersiz.");
    total = indexBytes + sumSizes + 32;
    consumed = indexBytes;
    if (o.progress) o.progress(consumed, total);

    const fs::path outDir = o.outDir;
    std::vector<fs::path> targets(entries.size());
    if (o.write) {
        std::set<std::string> seen, fileSet;
        for (const Entry &e : entries) {
            const std::string key = lowerAscii(e.rel);
            if (!seen.insert(key).second) return fail(Status::Integrity, "Arşivde tekrarlı yol var: " + e.rel);
            if (e.kind == 1) fileSet.insert(key);
        }
        for (size_t i = 0; i < entries.size(); ++i) {
            const std::string key = lowerAscii(entries[i].rel);
            for (size_t pos = key.find('/'); pos != std::string::npos; pos = key.find('/', pos + 1))
                if (fileSet.count(key.substr(0, pos))) return fail(Status::Integrity, "Arşivde yol çakışması var: " + entries[i].rel);
            targets[i] = outDir / fromUtf8(entries[i].rel);
            std::error_code ec;
            const fs::file_status st = fs::symlink_status(targets[i], ec);
            if (entries[i].kind == 1) {
                fs::path tmp = targets[i]; tmp += ".dbtmp";
                if (fs::exists(st) || fs::exists(fs::symlink_status(tmp, ec))) return fail(Status::Error, "Hedefte zaten var, üzerine yazılmaz: " + entries[i].rel);
            } else if (fs::exists(st) && !fs::is_directory(st)) return fail(Status::Error, "Hedefte aynı adlı bir dosya var: " + entries[i].rel);
        }
    }

    std::vector<fs::path> createdDirs;
    struct Done { fs::path tmp, fin; int64_t mtime; };
    std::vector<Done> done;
    std::ofstream out;
    fs::path openTmp;
    auto rollback = [&]() {
        if (out.is_open()) out.close();
        std::error_code ec;
        if (!openTmp.empty()) fs::remove(openTmp, ec);
        for (const Done &d : done) fs::remove(d.tmp, ec);
        for (auto it = createdDirs.rbegin(); it != createdDirs.rend(); ++it) fs::remove(*it, ec);
    };
    auto ensureDir = [&](const fs::path &d) {
        std::vector<fs::path> miss;
        std::error_code ec;
        fs::path cur = d;
        while (!cur.empty() && !fs::exists(cur, ec)) { miss.push_back(cur); cur = cur.parent_path(); }
        for (auto it = miss.rbegin(); it != miss.rend(); ++it) {
            std::error_code e2;
            if (!fs::create_directory(*it, e2) || e2) return false;
            createdDirs.push_back(*it);
        }
        return true;
    };
    auto stop = [&](Status s, const std::string &m) { rollback(); return fail(s, m); };

    if (o.write && !ensureDir(outDir)) return stop(Status::Error, "Çıkış klasörü oluşturulamadı.");
    Bytes chunk(kBlockMax);
    for (size_t i = 0; i < entries.size(); ++i) {
        const Entry &e = entries[i];
        if (cancelled()) return stop(Status::Cancelled, "İşlem iptal edildi.");
        if (e.kind == 2) {
            if (o.write && !ensureDir(targets[i])) return stop(Status::Error, "Klasör oluşturulamadı: " + e.rel);
            ++R.dirs;
            continue;
        }
        if (o.write) {
            if (!ensureDir(targets[i].parent_path())) return stop(Status::Error, "Klasör oluşturulamadı: " + e.rel);
            openTmp = targets[i]; openTmp += ".dbtmp";
            out.open(openTmp, std::ios::binary | std::ios::trunc);
            if (!out) { openTmp.clear(); return stop(Status::Error, "Dosya oluşturulamadı: " + e.rel); }
        }
        uint64_t left = e.size;
        while (left) {
            if (cancelled()) return stop(Status::Cancelled, "İşlem iptal edildi.");
            const size_t t = size_t(std::min<uint64_t>(left, chunk.size()));
            if (!bs.read(chunk.data(), t, &plain)) return stop(bs.status, bs.error);
            if (o.write) {
                out.write(reinterpret_cast<const char *>(chunk.data()), std::streamsize(t));
                if (!out) return stop(Status::Error, "Yazma hatası (disk dolu olabilir): " + e.rel);
            }
            left -= t; consumed += t; R.bytes += t;
            if (o.progress) o.progress(consumed, total);
        }
        if (o.write) {
            out.close();
            if (out.fail()) return stop(Status::Error, "Dosya kapatılamadı: " + e.rel);
            done.push_back({openTmp, targets[i], e.mtime});
            openTmp.clear();
        }
        ++R.files;
    }
    uint8_t trailer[32];
    const Hash32 want = plain.digest();
    if (!bs.read(trailer, 32, nullptr)) return stop(bs.status, bs.error);
    if (!constantTimeEqual(want.data(), trailer, 32)) return stop(Status::Integrity, "Orijinal veri SHA-256 değeriyle uyuşmuyor (veri bozuk).");
    if (!bs.drained()) return stop(Status::Integrity, "Arşivde beklenmeyen fazladan veri var.");
    consumed += 32;
    if (o.progress) o.progress(consumed, total);
    if (o.write) {
        for (size_t i = 0; i < done.size(); ++i) {
            std::error_code ec;
            fs::rename(done[i].tmp, done[i].fin, ec);
            if (ec) {
                const std::string name = toUtf8(done[i].fin.filename());
                std::error_code e2;
                for (size_t k = 0; k < i; ++k) fs::remove(done[k].fin, e2);
                for (size_t k = i; k < done.size(); ++k) fs::remove(done[k].tmp, e2);
                done.clear();
                rollback();
                return fail(Status::Error, "Dosya yerine yerleştirilemedi: " + name);
            }
            if (done[i].mtime > 0) {
                try {
                    const auto sys = std::chrono::sys_seconds{std::chrono::seconds(done[i].mtime)};
                    fs::last_write_time(done[i].fin, std::chrono::file_clock::from_sys(sys), ec);
                } catch (...) {}
            }
        }
    }
    return R;
}
}  // namespace detail

inline Result process(const Archive &a, const Options &o) {
    Result r = detail::processImpl(a, o);
    if (r.st == Status::Integrity) {
        const Result v = verifyParts(a, {}, o.cancelled);
        if (v.st == Status::Integrity) r.msg += " " + v.msg;
    }
    return r;
}

}  // namespace dbol
