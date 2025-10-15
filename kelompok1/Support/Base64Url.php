<?php

namespace Kelompok1\CryptoGraphy\Support;

/**
 * Class Base64Url
 * ----------------
 * Utilitas untuk konversi Base64URL (RFC 4648) yang aman untuk URL/JSON.
 *
 * Kenapa diperlukan?
 * - Saat kita membungkus token (iv, ciphertext, mac) ke JSON, seringkali
 * lebih nyaman memakai varian Base64URL (karena karakter '+', '/' dan '='
 * di base64 standar bisa bermasalah di URL/transport tertentu).
 *
 * Bagaimana diproses?
 * - encode(): base64 standar → ganti '+/' menjadi '-_' → hapus '=' di akhir.
 * - decode(): kembalikan '-_' menjadi '+/' → tambahkan '=' padding sesuai kebutuhan → base64_decode.
 */
final class Base64Url
{
    /**
     * Mengubah data biner menjadi string Base64URL (tanpa padding '=' di akhir).
     *
     * @param  string  $bin  Data biner apa pun.
     * @return string Base64URL tanpa '='.
     */
    public static function encode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    /**
     * Mengubah Base64URL menjadi biner, dengan pemulihan padding.
     *
     * @param  string  $b64  Teks Base64URL tanpa padding '='.
     * @return string Data biner hasil decode.
     *
     * @throws \RuntimeException Jika input bukan base64 yang valid.
     */
    public static function decode(string $b64): string
    {
        $b64 = strtr($b64, '-_', '+/');
        $pad = strlen($b64) % 4;
        if ($pad) {
            $b64 .= str_repeat('=', 4 - $pad);
        }
        $out = base64_decode($b64, true);
        if ($out === false) {
            throw new \RuntimeException('Base64URL tidak valid');
        }

        return $out;
    }
}
