<?php

namespace Kelompok1\CryptoGraphy;

use Kelompok1\CryptoGraphy\MAC\HmacSha256;

final class Crypto
{
    public static function getAppKey(): string
    {
        $config = @include __DIR__ . '/../config/app.php';
        $passPath = __DIR__ . '/../config/app_key.pass.json';
        
        if (is_array($config) && isset($config['app_key_pass_path'])) {
            $passPath = $config['app_key_pass_path'];
        }

        // Jika file .pass.json ada, gunakan KeyStorePass
        if (file_exists($passPath)) {
            try {
                // Default passphrase untuk aplikasi, bisa disesuaikan atau diambil dari env
                $passphrase = getenv('APP_PASSPHRASE') ?: 'kelompok1-secret-app-key';
                return \Kelompok1\CryptoGraphy\Services\KeyStorePass::load($passPath, $passphrase);
            } catch (\Exception $e) {
                // Silakan lihat log jika gagal load keystore yang ada
                error_log("Gagal memuat KeyStorePass: " . $e->getMessage());
            }
        }

        // Fallback ke app_key.txt (Legacy)
        $file = __DIR__.'/../app_key.txt';
        if (is_array($config) && isset($config['app_key_path'])) {
            $file = $config['app_key_path'];
        }

        if (! file_exists($file)) {
            // Jika tidak ada app_key.txt, coba inisialisasi .pass.json baru
            try {
                $passphrase = getenv('APP_PASSPHRASE') ?: 'kelompok1-secret-app-key';
                \Kelompok1\CryptoGraphy\Services\KeyStorePass::init($passPath, $passphrase);
                return \Kelompok1\CryptoGraphy\Services\KeyStorePass::load($passPath, $passphrase);
            } catch (\Exception $e) {
                error_log("Gagal inisialisasi KeyStorePass baru: " . $e->getMessage());
                // Jika gagal inisialisasi keystore baru, buat app_key.txt random (fallback terakhir)
                $key = random_bytes(32);
                file_put_contents($file, 'base64:'.base64_encode($key));
                @chmod($file, 0600);
            }
        }
        
        $txt = trim(file_get_contents($file));
        if (str_starts_with($txt, 'base64:')) {
            $raw = base64_decode(substr($txt, 7));
        } elseif (ctype_xdigit($txt) && strlen($txt) === 64) {
            $raw = hex2bin($txt);
        } else {
            $raw = $txt;
        }
        if (strlen($raw) !== 32) {
            $raw = hash('sha256', $raw, true);
        }

        return $raw;
    }

    private static function kdfSplit(string $master): array
    {
        $encKey = HmacSha256::mac($master, 'enc');
        $macKey = HmacSha256::mac($master, 'mac');

        return [hash('sha256', $encKey, true), hash('sha256', $macKey, true)];
    }

    public static function encryptThenMac(string $plaintext): array
    {
        [$encKey, $macKey] = self::kdfSplit(self::getAppKey());
        $iv = random_bytes(16);
        $cipherRaw = openssl_encrypt($plaintext, 'AES-256-CBC', $encKey, OPENSSL_RAW_DATA, $iv);
        if ($cipherRaw === false) {
            throw new \RuntimeException('Encrypt failed');
        }
        $mac = HmacSha256::macHex($macKey, $iv.$cipherRaw); // hex

        return [
            'iv' => base64_encode($iv),
            'value' => base64_encode($cipherRaw),
            'mac' => $mac,
        ];
    }

    public static function decryptWithMac(array $payload): string
    {
        if (! isset($payload['iv'], $payload['value'], $payload['mac'])) {
            throw new \InvalidArgumentException('Payload invalid: missing fields');
        }
        $iv = base64_decode($payload['iv'], true);
        $cipher = base64_decode($payload['value'], true);
        $macGiven = (string) $payload['mac'];
        if ($iv === false || $cipher === false) {
            throw new \InvalidArgumentException('Payload invalid: base64 decode failed');
        }

        [$encKey, $macKey] = self::kdfSplit(self::getAppKey());

        if (!HmacSha256::verifyHex($macKey, $iv.$cipher, $macGiven)) {
            throw new \RuntimeException('Integrity check gagal: MAC invalid (CBC)');
        }
        $plain = openssl_decrypt($cipher, 'AES-256-CBC', $encKey, OPENSSL_RAW_DATA, $iv);
        if ($plain === false) {
            throw new \RuntimeException('Decrypt failed');
        }

        return $plain;
    }
}
