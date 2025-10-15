<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Support;

/**
 * Class Uuid
 * ----------
 * Generator & validator UUID aman.
 *
 * Fitur:
 * - generateV4()    : UUID v4 standar (RFC 4122) → "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
 * - generateHex128(): 128-bit random (16 byte) → hex-32 (tanpa tanda hubung)
 * - isValidV4()     : validasi format UUID v4 canonical
 * - isHex128()      : validasi hex-32 (merepresentasikan 16 byte)
 *
 * Catatan istilah:
 * - Yang aman adalah 16 *byte* = 128-bit
 * - UUID v4 memakai 128-bit random dengan bit versi/varian di-set sesuai RFC 4122.
 */
final class Uuid
{
    /**
     * Hasilkan UUID v4 canonical (36 karakter termasuk tanda hubung):
     * 8-4-4-4-12, dengan nibble versi = 4 dan varian = 10xxxxxx.
     */
    public static function generateV4(): string
    {
        $d = random_bytes(16);

        // Set versi (4) di byte index 6 (nibble tinggi)
        $d[6] = chr((ord($d[6]) & 0x0F) | 0x40);
        // Set varian (10xxxxxx) di byte index 8
        $d[8] = chr((ord($d[8]) & 0x3F) | 0x80);

        $hex = bin2hex($d);
        return sprintf(
            '%s-%s-%s-%s-%s',
            substr($hex, 0, 8),
            substr($hex, 8, 4),
            substr($hex, 12, 4),
            substr($hex, 16, 4),
            substr($hex, 20, 12)
        );
    }

    /**
     * Hasilkan 128-bit random (16 byte) dalam representasi HEX32 (tanpa dash).
     * Cocok kalau kamu ingin “uuid 16 byte” yang ringkas.
     */
    public static function generateHex128(): string
    {
        return bin2hex(random_bytes(16)); // 32 hex chars → 16 byte (128-bit)
    }

    /** Validasi format UUID v4 canonical (huruf besar/kecil diterima). */
    public static function isValidV4(string $uuid): bool
    {
        return (bool)preg_match(
            '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/i',
            $uuid
        );
    }

    /** Validasi hex-32 (merepresentasikan 16 byte). */
    public static function isHex128(string $hex): bool
    {
        return (bool)preg_match('/^[0-9a-fA-F]{32}$/', $hex);
    }
}
