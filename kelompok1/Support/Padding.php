<?php

namespace Kelompok1\CryptoGraphy\Support;

/**
 * Class Padding
 * -------------
 * Implementasi PKCS#7 Padding untuk block cipher (AES block size = 16 byte).
 *
 * Kenapa diperlukan?
 * - AES-CBC bekerja pada blok 16 byte. Jika panjang data bukan kelipatan 16,
 * maka ditambah byte padding dengan nilai jumlah byte pad.
 *
 * Bagaimana diproses?
 * - pad(): hitung sisa blok → tambahkan N byte dengan nilai N.
 * - unpad(): validasi panjang + nilai byte terakhir dan semua byte pad dengan
 * perbandingan konstan-waktu (hash_equals) → hapus.
 */
final class Padding
{
    /**
     * Menambah PKCS#7 padding.
     *
     * @param  string  $data  Plaintext mentah.
     * @param  int  $blockSize  Ukuran blok (default 16 untuk AES).
     * @return string Data + padding.
     */
    public static function pad(string $data, int $blockSize = 16): string
    {
        $pad = $blockSize - (strlen($data) % $blockSize);

        return $data.str_repeat(chr($pad), $pad);
    }

    /**
     * Menghapus PKCS#7 padding dengan validasi yang aman.
     *
     * @param  string  $data  Data setelah dekripsi (masih terpad).
     * @param  int  $blockSize  Ukuran blok (default 16 untuk AES).
     * @return string Plaintext bersih.
     *
     * @throws \RuntimeException Jika format padding tidak valid.
     */
    public static function unpad(string $data, int $blockSize = 16): string
    {
        $len = strlen($data);
        if ($len === 0 || $len % $blockSize !== 0) {
            throw new \RuntimeException('Panjang padding salah');
        }
        $pad = ord($data[$len - 1]);
        if ($pad < 1 || $pad > $blockSize) {
            throw new \RuntimeException('Nilai padding salah');
        }
        $ps = substr($data, -$pad);
        if (! hash_equals(str_repeat(chr($pad), $pad), $ps)) {
            throw new \RuntimeException('Byte padding tidak konsisten');
        }

        return substr($data, 0, $len - $pad);
    }
}
