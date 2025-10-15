<?php

namespace Kelompok1\CryptoGraphy\KDF;

/**
 * Class HKDF
 * ----------
 * Implementasi HKDF-SHA256 (RFC 5869) untuk menurunkan sub-key dari satu master key.
 *
 * Kenapa diperlukan?
 * - Praktik aman: pisahkan key enkripsi dan key MAC (key separation) dari satu master key.
 *
 * Bagaimana diproses?
 * - Tahap Extract: PRK = HMAC(salt, IKM)
 * - Tahap Expand : OKM = HMAC(PRK, T_prev || info || counter) di-loop sampai panjang cukup
 */
final class HKDF
{
    /**
     * Menurunkan key sepanjang $length byte.
     *
     * @param  string  $ikm  Input Keying Material (master key).
     * @param  int  $length  Panjang output yang diinginkan.
     * @param  string  $salt  Opsional (disarankan); jika kosong, salt nol 32 byte.
     * @param  string  $info  Konteks string (mis. label tujuan key).
     * @return string OKM (Output Key Material) sepanjang $length byte.
     */
    public static function derive(string $ikm, int $length, string $salt = '', string $info = ''): string
    {
        $salt = $salt !== '' ? $salt : str_repeat("\0", 32);
        $prk = hash_hmac('sha256', $ikm, $salt, true); // Extract
        $t = '';
        $okm = '';
        for ($block = 1; strlen($okm) < $length; $block++) {
            $t = hash_hmac('sha256', $t.$info.chr($block), $prk, true); // Expand
            $okm .= $t;
        }

        return substr($okm, 0, $length);
    }
}
