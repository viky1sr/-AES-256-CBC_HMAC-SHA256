<?php

namespace Kelompok1\CryptoGraphy;

final class Crypto
{
    public static function getAppKey(): string
    {
        $file = __DIR__.'/../app_key.txt';
        if (! file_exists($file)) {
            $key = random_bytes(32);
            file_put_contents($file, 'base64:'.base64_encode($key));
            @chmod($file, 0600);
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
        $encKey = hash_hmac('sha256', 'enc', $master, true);
        $macKey = hash_hmac('sha256', 'mac', $master, true);

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
        $mac = hash_hmac('sha256', $iv.$cipherRaw, $macKey, false); // hex

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
        $macCalc = hash_hmac('sha256', $iv.$cipher, $macKey, false);

        if (! hash_equals($macCalc, $macGiven)) {
            throw new \RuntimeException('Integrity check gagal: MAC invalid (CBC)');
        }
        $plain = openssl_decrypt($cipher, 'AES-256-CBC', $encKey, OPENSSL_RAW_DATA, $iv);
        if ($plain === false) {
            throw new \RuntimeException('Decrypt failed');
        }

        return $plain;
    }
}
