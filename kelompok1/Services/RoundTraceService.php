<?php

namespace Kelompok1\CryptoGraphy\Services;

use Kelompok1\CryptoGraphy\Cipher\AESCBC;
use Kelompok1\CryptoGraphy\KDF\HKDF;
use Kelompok1\CryptoGraphy\KDF\PassphraseKDF;
use Kelompok1\CryptoGraphy\Trace\AES256BlockTracer;
use Kelompok1\CryptoGraphy\Trace\CBCTracer;

/**
 * Class RoundTraceService
 * Service util untuk:
 *  - Menyiapkan keyEnc dari passphrase (PBKDF2 → HKDF)
 *  - Cetak tabel Rounds (Round 0..14) untuk blok pertama
 *  - Cetak jejak CBC per-blok (P, P⊕IV/Cprev, C)
 */
final class RoundTraceService
{
    /** Turunkan keyEnc dari passphrase (PBKDF2 → HKDF). */
    public static function deriveKeyEncFromPass(string $passphrase, ?string $salt = null, int $iter = 210_000): array
    {
        $salt = $salt ?? PassphraseKDF::randomSalt(16);
        $masterKey = PassphraseKDF::derivePBKDF2($passphrase, $salt, $iter, 32);
        $keyEnc = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');

        return [$keyEnc, $salt, $iter];
    }

    /** Pad ke kelipatan 16 (untuk blok pertama tracer). */
    public static function pkcs7Pad16(string $data): string
    {
        $bs = 16;
        $pad = $bs - (strlen($data) % $bs);

        return $data.str_repeat(chr($pad), $pad);
    }

    /** Kembalikan baris-baris tabel round AES untuk blok pertama (tanpa CBC). */
    public static function traceRounds(string $plaintext, string $keyEnc): array
    {
        $padded = self::pkcs7Pad16($plaintext);
        $firstBlock = substr($padded, 0, 16);

        return AES256BlockTracer::trace($firstBlock, $keyEnc);
    }

    /** Enkripsi 1x untuk dapat IV/CT, lalu trace CBC per-blok. */
    public static function traceCBC(string $plaintext, string $keyEnc): array
    {
        $enc = AESCBC::encrypt($plaintext, $keyEnc); // auto IV
        $iv = $enc['iv'];
        $rows = CBCTracer::trace($plaintext, $keyEnc, $iv);

        return ['iv' => $iv, 'rows' => $rows];
    }
}
