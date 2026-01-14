<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy;

use Kelompok1\CryptoGraphy\KDF\HKDF;
use Kelompok1\CryptoGraphy\MAC\HmacSha256;
use Kelompok1\CryptoGraphy\Cipher\AESCBC;
use Kelompok1\CryptoGraphy\Token\EtmToken;

/**
 * =============================================================================
 *  CLASS: CryptoService  —  Fasad Utama Skema "Encrypt-then-MAC" (EtM)
 * =============================================================================
 *
 *  Tujuan
 *  ------
 *  Menyediakan API tingkat tinggi untuk enkripsi dan dekripsi aman menggunakan:
 *    - AES-256-CBC (kerahasiaan / confidentiality)
 *    - HMAC-SHA256 (integritas & autentikasi / integrity & authenticity)
 *  dengan pola komposisional aman: **Encrypt-then-MAC (EtM)**.
 *
 *  Konsep Inti (Ringkas)
 *  ---------------------
 *  1) **Key Separation via HKDF-SHA256**
 *     Dari satu master key (biner, ≥ 32B), diturunkan 2 sub-key independen:
 *       K_enc = HKDF(masterKey, 32, info="aes-256-cbc:enc")
 *       K_mac = HKDF(masterKey, 32, info="aes-256-cbc:mac")
 *     Pemisahan kunci mencegah satu kunci dipakai untuk dua tujuan kriptografi.
 *
 *  2) **AES-256-CBC dengan PKCS#7 Padding**
 *     - AES memiliki ukuran blok 16 byte.
 *     - CBC butuh IV 16 byte **acak & unik** per enkripsi.
 *     - Plaintext akan di-*pad* (PKCS#7) agar kelipatan 16 byte.
 *
 *  3) **HMAC-SHA256 di atas (IV || Ciphertext)**
 *     - Tag MAC dihitung atas gabungan IV dan ciphertext agar IV juga terlindungi integritasnya.
 *     - Verifikasi MAC dilakukan **sebelum** dekripsi untuk mencegah padding oracle.
 *
 *  4) **Token portable**
 *     - Hasil dikemas sebagai base64(JSON) dengan struktur:
 *          { "iv": base64url(IV), "value": base64url(C), "mac": base64url(M) }
 *
 * -----------------------------------------------------------------------------
 *  FORMULASI MATEMATIS
 * -----------------------------------------------------------------------------
 *  Notasi:
 *    • K_enc : sub-key enkripsi (32 byte)
 *    • K_mac : sub-key MAC (32 byte)
 *    • IV    : vektor inisialisasi 16B (acak & unik)
 *    • P     : plaintext (setelah PKCS#7 pad di level cipher)
 *    • C     : ciphertext
 *    • M     : tag HMAC-SHA256 (32B)
 *    • ||    : konkatenasi biner
 *
 *  Derivasi sub-key (HKDF-SHA256):
 *    K_enc = HKDF(masterKey, 32, info="aes-256-cbc:enc")
 *    K_mac = HKDF(masterKey, 32, info="aes-256-cbc:mac")
 *
 *  Enkripsi (Encrypt-then-MAC):
 *    1) C = AES_256_CBC_Enc(K_enc, P ; IV)
 *    2) M = HMAC_SHA256(K_mac, IV || C)
 *    3) Token = base64(JSON {iv, value=C, mac=M})
 *
 *  Dekripsi:
 *    1) Parse token → (IV, C, M)
 *    2) Tolak jika  M ≠ HMAC_SHA256(K_mac, IV || C)
 *    3) P = AES_256_CBC_Dec(K_enc, C ; IV) → unpad (PKCS#7) → plaintext
 *
 * -----------------------------------------------------------------------------
 *  ALASAN DESAIN (Security Rationale)
 * -----------------------------------------------------------------------------
 *  • Encrypt-then-MAC (EtM) → banyak literatur menilai komposisionalnya **aman**:
 *    MAC diverifikasi dulu (melindungi dari manipulasi C/IV) sehingga dekripsi
 *    tidak dipanggil untuk data yang rusak (mencegah padding oracle).
 *
 *  • HKDF-SHA256 → memisahkan K_enc dan K_mac dari masterKey yang sama (key separation),
 *    mengurangi risiko *cross-protocol/key reuse*.
 *
 *  • IV 16B acak & unik per enkripsi → CBC memerlukan IV yang tidak boleh reuse
 *    untuk master key yang sama. IV **tidak rahasia**, tapi integritasnya dilindungi
 *    oleh HMAC (karena M dihitung atas (IV||C)).
 *
 *  • PKCS#7 padding → standar umum di banyak library; memastikan input AES blok 16 byte.
 *
 * -----------------------------------------------------------------------------
 *  "DO & DON'T"
 * -----------------------------------------------------------------------------
 *  ✓ DO:
 *    - Simpan masterKey secara aman (HSM/.env/secret manager).
 *    - Gunakan masterKey biner dengan panjang ≥ 32B. Jika dari passphrase,
 *      lakukan KDF (PBKDF2/Argon2) dulu → hasilnya menjadi masterKey 32B.
 *    - Selalu **verifikasi MAC sebelum dekripsi** (sudah dipaksa di `decrypt()`).
 *    - Ganti IV di setiap enkripsi (otomatis di sini).
 *
 *  ✗ DON'T:
 *    - Jangan reuse IV untuk masterKey yang sama.
 *    - Jangan pakai satu kunci yang sama untuk enkripsi dan MAC (tanpa HKDF).
 *    - Jangan mem-bypass verifikasi MAC (raw decrypt atas C tanpa verifikasi).
 *
 * -----------------------------------------------------------------------------
 *  ERROR & EXCEPTION
 * -----------------------------------------------------------------------------
 *  • InvalidArgumentException → bila masterKey < 32B atau parameter invalid.
 *  • RuntimeException → MAC verification failed / OpenSSL gagal.
 *
 * -----------------------------------------------------------------------------
 *  CONTOH PEMAKAIAN SINGKAT
 * -----------------------------------------------------------------------------
 *  // 1) Master key biner 32B langsung:
 *  $masterKey = random_bytes(32);
 *  $token = CryptoService::encrypt("pesan rahasia", $masterKey);
 *  $plain = CryptoService::decrypt($token, $masterKey);
 *
 *  // 2) Dari passphrase → masterKey 32B (contoh simpel pakai SHA-256):
 *  $masterKey = hash('sha256', $passphrase, true); // lalu pakai seperti di atas
 *
 *  // 3) Akses komponen EtM (untuk edukasi/trace):
 *  $raw = CryptoService::encryptEtMRaw("abc", $masterKey);
 *  // $raw['iv'], $raw['ciphertext'], $raw['mac'] (semua biner)
 *  // decryptEtMRaw($iv, $ct, $mac, $masterKey) → plaintext (verif MAC dulu)
 *
 * =============================================================================
 */
final class CryptoService
{
    /**
     * Validasi panjang minimal masterKey.
     *
     * @param  string $masterKey  Master key biner (disarankan ≥ 32 byte).
     * @throws \InvalidArgumentException Jika panjang < 32 byte.
     */
    private static function assertKey(string $masterKey): void
    {
        if (strlen($masterKey) < 32) {
            throw new \InvalidArgumentException('masterKey harus ≥ 32 byte (gunakan KDF bila dari passphrase).');
        }
    }

    /**
     * ENCRYPT: AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).
     *
     * Flow ringkas:
     *   1) Derive K_enc & K_mac via HKDF-SHA256 (info pengikat "enc"/"mac").
     *   2) AES-256-CBC encrypt (auto IV acak, PKCS#7 pad).
     *   3) Hitung MAC = HMAC_SHA256(K_mac, IV || C).
     *   4) Kemas menjadi token base64(JSON {iv,value,mac}).
     *
     * @param  string $plaintext   Data asli (teks/biner).
     * @param  string $masterKey   Master key biner (≥ 32B). Jika dari teks, gunakan KDF/sha256 dahulu.
     * @return string              Token base64(JSON {iv,value,mac}).
     *
     * @throws \InvalidArgumentException Jika masterKey kurang panjang.
     * @throws \RuntimeException         Jika OpenSSL encrypt gagal.
     */
    public static function encrypt(string $plaintext, string $masterKey, ?array $meta = null): string
    {
        self::assertKey($masterKey);

        // 1) Key separation (HKDF-SHA256)
        $keyEnc = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');
        $keyMac = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:mac');

        // 2) AES-256-CBC (PKCS#7 pad; IV acak)
        $out = AESCBC::encrypt($plaintext, $keyEnc);
        $iv  = $out['iv'];
        $ct  = $out['ciphertext'];

        // 3) HMAC atas (IV || C)
        $mac = HmacSha256::mac($keyMac, $iv . $ct);

        // 4) Token base64(JSON)
        return EtmToken::pack($iv, $ct, $mac, $meta);
    }

    /**
     * DECRYPT: Verifikasi MAC terlebih dahulu, baru dekripsi AES-256-CBC.
     *
     * Flow ringkas:
     *   1) base64 decode → JSON decode → ambil iv,value,mac (bentuk biner).
     *   2) Verifikasi: MAC ?= HMAC_SHA256(K_mac, IV || C) — jika gagal: tolak.
     *   3) AES-256-CBC decrypt(K_enc, C ; IV) → PKCS#7 unpad → plaintext.
     *
     * @param  string $token      base64(JSON {iv,value,mac})
     * @param  string $masterKey  Master key biner (≥ 32B).
     * @return string             Plaintext asli.
     *
     * @throws \InvalidArgumentException Jika masterKey kurang panjang.
     * @throws \RuntimeException         Jika token rusak / MAC salah / OpenSSL decrypt gagal.
     */
    public static function decrypt(string $token, string $masterKey): string
    {
        self::assertKey($masterKey);

        // 1) Key separation (HKDF-SHA256)
        $keyEnc = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');
        $keyMac = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:mac');

        // 2) Parse token
        $obj = EtmToken::unpack($token); // {iv,value,mac} → biner

        // 3) Verifikasi MAC terlebih dahulu (konstan-waktu)
        if (! HmacSha256::verify($keyMac, $obj['iv'] . $obj['value'], $obj['mac'])) {
            throw new \RuntimeException('MAC verification failed (ciphertext/IV mungkin berubah).');
        }

        // 4) Dekripsi AES-256-CBC
        return AESCBC::decrypt($obj['value'], $keyEnc, $obj['iv']);
    }

    // =========================================================================
    //  OPSIONAL (untuk edukasi/trace): akses komponen EtM secara "raw"
    // =========================================================================

    /**
     * Encrypt-then-MAC (RAW) — Kembalikan IV, Ciphertext, MAC, serta sub-key.
     * Cocok untuk demonstrasi/trace di CLI.
     *
     * @param  string $plaintext
     * @param  string $masterKey
     * @return array{iv:string,ciphertext:string,mac:string,kenc:string,kmac:string}
     */
    public static function encryptEtMRaw(string $plaintext, string $masterKey): array
    {
        self::assertKey($masterKey);
        $kEnc = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');
        $kMac = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:mac');

        $out = AESCBC::encrypt($plaintext, $kEnc);
        $iv  = $out['iv'];
        $ct  = $out['ciphertext'];
        $mac = HmacSha256::mac($kMac, $iv . $ct);

        return ['iv' => $iv, 'ciphertext' => $ct, 'mac' => $mac, 'kenc' => $kEnc, 'kmac' => $kMac];
    }

    /**
     * Decrypt-with-verify (RAW) — Verifikasi MAC atas (IV||C) kemudian dekripsi.
     *
     * @param  string $iv   16 byte
     * @param  string $ct   ciphertext (biner)
     * @param  string $mac  tag HMAC (biner, 32B)
     * @param  string $masterKey
     * @return string plaintext
     *
     * @throws \RuntimeException jika MAC tidak valid / OpenSSL gagal
     */
    public static function decryptEtMRaw(string $iv, string $ct, string $mac, string $masterKey): string
    {
        self::assertKey($masterKey);
        $kEnc = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');
        $kMac = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:mac');

        if (! HmacSha256::verify($kMac, $iv . $ct, $mac)) {
            throw new \RuntimeException('MAC verification failed');
        }
        return AESCBC::decrypt($ct, $kEnc, $iv);
    }
}
