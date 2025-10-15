<?php

namespace Kelompok1\CryptoGraphy\KDF;

/**
 * Class PassphraseKDF
 * KDF untuk mengubah passphrase (teks) menjadi master key 32 byte.
 *
 * Opsi:
 * - derivePBKDF2(): PBKDF2-HMAC-SHA256 dengan salt & iterasi tinggi (direkomendasikan).
 * - deriveQuick():  SHA-256(passphrase) → 32 byte (hanya untuk demo/tes, tidak direkomendasikan untuk produksi).
 *
 * Kenapa:
 * - Password manusia biasanya lemah. PBKDF2 memperlambat brute force dan butuh salt unik.
 */
final class PassphraseKDF
{
    /** Hasilkan salt acak aman (default 16 byte). */
    public static function randomSalt(int $length = 16): string
    {
        return random_bytes($length);
    }

    /**
     * Derivasi kunci dari passphrase menggunakan PBKDF2-HMAC-SHA256.
     *
     * @param  string  $passphrase  Teks password.
     * @param  string  $salt  Salt biner (unik per token).
     * @param  int  $iterations  Jumlah iterasi (>= 100k disarankan; default 210k).
     * @param  int  $length  Panjang key output (default 32 byte untuk AES-256).
     * @return string Master key biner.
     */
    public static function derivePBKDF2(
        string $passphrase,
        string $salt,
        int $iterations = 210_000,
        int $length = 32
    ): string {
        // hash_pbkdf2 mengembalikan hex by default; gunakan raw_output=true agar biner.
        return hash_pbkdf2('sha256', $passphrase, $salt, $iterations, $length, true);
    }

    /**
     * Derivasi cepat (demo): key = SHA-256(passphrase).
     * Tidak aman untuk produksi, tetapi kompatibel (32 byte).
     */
    public static function deriveQuick(string $passphrase): string
    {
        return hash('sha256', $passphrase, true);
    }
}
