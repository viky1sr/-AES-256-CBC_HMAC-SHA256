<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Services;

/**
 * KeyStore — loader/generator kunci aplikasi dari file biner.
 * - generate(): buat file key 32B
 * - load(): baca 32B dari file
 */
final class KeyStore
{
    public static function generate(string $path, int $bytes = 32): void
    {
        if (file_exists($path)) {
            throw new \RuntimeException("Key file sudah ada: {$path}");
        }
        $dir = dirname($path);
        if (!is_dir($dir)) {
            if (!mkdir($dir, 0700, true) && !is_dir($dir)) {
                throw new \RuntimeException("Gagal membuat direktori: {$dir}");
            }
        }
        $key = random_bytes($bytes);
        if (file_put_contents($path, $key, LOCK_EX) === false) {
            throw new \RuntimeException("Gagal menulis key file: {$path}");
        }
        @chmod($path, 0600);
    }

    /** @return string 32B master key (biner) */
    public static function load(string $path): string
    {
        if (!is_file($path)) {
            throw new \RuntimeException("Key file tidak ditemukan: {$path}");
        }
        $key = file_get_contents($path);
        if ($key === false || strlen($key) < 32) {
            throw new \RuntimeException("Key file rusak/terlalu pendek: {$path}");
        }
        return substr($key, 0, 32);
    }
}
