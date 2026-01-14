<?php

namespace Kelompok1\CryptoGraphy;

use Kelompok1\CryptoGraphy\KDF\PassphraseKDF;
use Kelompok1\CryptoGraphy\Support\Base64Url;

/**
 * Class CryptoPassService
 * -----------------------
 * Enkripsi/dekripsi memakai PASS PHRASE (teks), bukan masterKey biner.
 *
 * ENCRYPT:
 * - salt acak → PBKDF2(pass,salt,iter) → masterKey (32B)
 * - CryptoService::encrypt(..., meta KDF) → token simpan salt & iter
 *
 * DECRYPT:
 * - baca meta.kdf dari token → PBKDF2(pass, salt, iter) → CryptoService::decrypt()
 * - fallback: jika token lama tanpa meta → SHA-256(passphrase) (kompat demo)
 */
final class CryptoPassService
{
    public static function encryptWithPassphrase(string $plaintext, string $passphrase, int $iterations = 210_000, array $meta = []): string
    {
        $salt = PassphraseKDF::randomSalt(16);
        $masterKey = PassphraseKDF::derivePBKDF2($passphrase, $salt, $iterations, 32);

        $mergedMeta = array_merge($meta, [
            'kdf' => [
                'alg' => 'pbkdf2-sha256',
                'salt' => Base64Url::encode($salt),
                'iter' => $iterations,
            ],
        ]);

        return CryptoService::encrypt($plaintext, $masterKey, $mergedMeta);
    }

    public static function decryptWithPassphrase(string $token, string $passphrase): string
    {
        $obj = \Kelompok1\CryptoGraphy\Token\EtmToken::unpack($token);
        $kdf = $obj['meta']['kdf'] ?? null;

        if (is_array($kdf) && ($kdf['alg'] ?? '') === 'pbkdf2-sha256') {
            $saltB = Base64Url::decode($kdf['salt'] ?? '');
            $iter = (int) ($kdf['iter'] ?? 210_000);
            $masterKey = PassphraseKDF::derivePBKDF2($passphrase, $saltB, $iter, 32);
        } else {
            $masterKey = PassphraseKDF::deriveQuick($passphrase); // kompat lama
        }

        return CryptoService::decrypt($token, $masterKey);
    }
}
