<?php

namespace Kelompok1\CryptoGraphy\MAC;

/**
 * Class HmacSha256
 * ----------------
 * Pembungkus HMAC-SHA256 untuk menghasilkan dan memverifikasi tag MAC.
 *
 * Kenapa diperlukan?
 * - Memberikan integritas + autentikasi pada ciphertext (Encrypt-then-MAC):
 * MAC = HMAC(keyMac, IV || ciphertext).
 *
 * Bagaimana diproses?
 * - mac() : HMAC-SHA256(key, data) → 32 byte biner.
 * - verify() : hitung ulang HMAC dan bandingkan dengan hash_equals (konstan-waktu).
 */
final class HmacSha256
{
    /**
     * Menghasilkan tag HMAC-SHA256.
     *
     * @param  string  $key  Kunci MAC (32 byte hasil HKDF direkomendasikan).
     * @param  string  $data  Data yang dilindungi (contoh: IV||ciphertext).
     * @return string Tag MAC biner 32 byte.
     */
    public static function mac(string $key, string $data): string
    {
        return hash_hmac('sha256', $data, $key, true);
    }

    /**
     * Verifikasi HMAC secara konstan-waktu.
     *
     * @param  string  $key  Kunci MAC.
     * @param  string  $data  Data yang dilindungi.
     * @param  string  $tag  Tag MAC yang diterima.
     * @return bool True jika valid; false jika tidak.
     */
    public static function verify(string $key, string $data, string $tag): bool
    {
        return hash_equals(self::mac($key, $data), $tag);
    }


    /**
     * Versi heksadesimal (64 char).
     *
     * @param  string  $key  Kunci MAC.
     * @param  string  $data  Data yang dilindungi.
     * @return string hex string.
     */
    public static function macHex(string $key, string $data): string
    {
        return hash_hmac('sha256', $data, $key, false);
    }

    /**
     * Verifikasi dari tag heksadesimal.
     *
     * @param  string  $key  Kunci MAC.
     * @param  string  $data  Data yang dilindungi.
     * @param  string  $tagHex  Tag MAC yang diterima.
     * @return bool True jika valid; false jika tidak.
     */
    public static function verifyHex(string $key, string $data, string $tagHex): bool
    {
        return hash_equals(self::macHex($key, $data), strtolower($tagHex));
    }
}
