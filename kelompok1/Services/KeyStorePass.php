<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Services;

use Kelompok1\CryptoGraphy\KDF\PassphraseKDF;
use Kelompok1\CryptoGraphy\Support\Base64Url;

/**
 * KeyStorePass
 * ------------
 * Simpan metadata KDF (salt, iter, auth) — TIDAK menyimpan master key.
 * masterKey = PBKDF2-SHA256(passphrase, salt, iter, 32)
 * auth = HMAC-SHA256(masterKey, "auth-check") → verifikasi passphrase benar.
 */
final class KeyStorePass
{
    private const AUTH_MSG = "auth-check";

    public static function init(string $path, string $passphrase, int $iterations = 210000): void
    {
        if (file_exists($path)) throw new \RuntimeException("KeyStore sudah ada: {$path}");
        if ($iterations < 100000) throw new \InvalidArgumentException('Iterations minimal 100000.');

        $dir = dirname($path);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new \RuntimeException("Gagal membuat direktori: {$dir}");
        }

        $salt      = PassphraseKDF::randomSalt(16);
        $masterKey = PassphraseKDF::derivePBKDF2($passphrase, $salt, $iterations, 32);
        $auth      = hash_hmac('sha256', self::AUTH_MSG, $masterKey, true);

        $payload = [
            'alg'  => 'pbkdf2-sha256',
            'salt' => Base64Url::encode($salt),
            'iter' => $iterations,
            'auth' => Base64Url::encode($auth),
        ];
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        if ($json === false) throw new \RuntimeException('Gagal encode JSON keystore');

        if (file_put_contents($path, $json, LOCK_EX) === false) {
            throw new \RuntimeException("Gagal menulis keystore: {$path}");
        }
        @chmod($path, 0600);
    }

    public static function load(string $path, string $passphrase): string
    {
        if (!is_file($path)) throw new \RuntimeException("KeyStore tidak ditemukan: {$path}");
        $obj = json_decode((string)file_get_contents($path), true);
        if (!is_array($obj) || ($obj['alg'] ?? '') !== 'pbkdf2-sha256') {
            throw new \RuntimeException('Format keystore tidak valid');
        }
        foreach (['salt','iter','auth'] as $k) {
            if (!isset($obj[$k])) throw new \RuntimeException("Field '{$k}' tidak ada");
        }

        $salt = Base64Url::decode($obj['salt']);
        $iter = (int)$obj['iter'];
        $auth = Base64Url::decode($obj['auth']);
        if ($iter < 100000 || strlen($salt) < 8 || strlen($auth)!==32) {
            throw new \RuntimeException('Parameter keystore tidak aman/valid');
        }

        $masterKey = PassphraseKDF::derivePBKDF2($passphrase, $salt, $iter, 32);
        $calc      = hash_hmac('sha256', self::AUTH_MSG, $masterKey, true);
        if (!hash_equals($auth, $calc)) {
            throw new \RuntimeException('Passphrase salah (auth gagal)');
        }
        return $masterKey; // 32B
    }
}
