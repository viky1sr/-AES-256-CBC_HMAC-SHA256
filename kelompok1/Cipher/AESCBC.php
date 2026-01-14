<?php

namespace Kelompok1\CryptoGraphy\Cipher;

use Kelompok1\CryptoGraphy\Support\Padding;

/**
 * Class AESCBC
 * ------------
 * Enkripsi & dekripsi menggunakan AES-256-CBC (OpenSSL) + PKCS#7 padding.
 *
 * Enkripsi (encrypt):
 * 1) Pad plaintext ke kelipatan 16 byte (PKCS#7)
 * 2) Buat IV acak 16 byte
 * 3) openssl_encrypt('aes-256-cbc', key 32 byte, iv 16 byte, RAW)
 *
 * Dekripsi (decrypt):
 * 1) openssl_decrypt → dapat plaintext terpad
 * 2) Hapus padding PKCS#7 → plaintext bersih
 */
final class AESCBC
{
    /**
     * Enkripsi AES-256-CBC.
     *
     * @param  string  $plaintext  Data asli.
     * @param  string  $key  Kunci 32 byte (AES-256).
     * @param  string|null  $iv  IV 16 byte (opsional; null = acak).
     * @return array{iv:string,ciphertext:string} IV & ciphertext biner.
     */
    public static function encrypt(string $plaintext, string $key, ?string $iv = null): array
    {
        if (strlen($key) !== 32) {
            throw new \InvalidArgumentException('Key AES-256 harus 32 byte');
        }
        $iv = $iv ?? random_bytes(16);
        if (strlen($iv) !== 16) {
            throw new \InvalidArgumentException('IV harus 16 byte');
        }

        $padded = Padding::pad($plaintext, 16);
        $ct = openssl_encrypt($padded, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if ($ct === false) {
            throw new \RuntimeException('OpenSSL encrypt gagal');
        }

        return ['iv' => $iv, 'ciphertext' => $ct];
    }

    /**
     * Dekripsi AES-256-CBC.
     *
     * @param  string  $ciphertext  Ciphertext biner.
     * @param  string  $key  Kunci 32 byte.
     * @param  string  $iv  IV 16 byte.
     * @return string Plaintext bersih.
     */
    public static function decrypt(string $ciphertext, string $key, string $iv): string
    {
        if (strlen($key) !== 32) {
            throw new \InvalidArgumentException('Key AES-256 harus 32 byte');
        }
        if (strlen($iv) !== 16) {
            throw new \InvalidArgumentException('IV harus 16 byte');
        }
        $padded = openssl_decrypt($ciphertext, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if ($padded === false) {
            throw new \RuntimeException('OpenSSL decrypt gagal');
        }

        return Padding::unpad($padded, 16);
    }
}
