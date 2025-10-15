<?php

namespace Kelompok1\CryptoGraphy\Token;

use Kelompok1\CryptoGraphy\Support\Base64Url;

/**
 * Class EtmToken
 * --------------
 * Format token Encrypt-then-MAC: base64(JSON { iv, value, mac, meta? }).
 *
 * - meta (opsional): objek informasi tambahan, misal:
 *   { "kdf": { "alg": "pbkdf2-sha256", "salt": "<base64url>", "iter": 210000 } }
 *
 * Kompatibilitas:
 * - Jika meta tidak diberikan, struktur tetap {iv,value,mac} seperti sebelumnya.
 *
 *  Proses:
 *  - pack(): encode b64url setiap komponen → JSON → base64.
 *  - unpack(): base64 → JSON → decode b64url ke biner.
 */
final class EtmToken
{
    /**
     * Bungkus IV, ciphertext, MAC, plus meta opsional menjadi token base64(JSON).
     *
     * @param  array|null  $meta  Informasi tambahan opsional (akan dimasukkan ke JSON).
     * @return string Token base64(JSON).
     */
    public static function pack(string $iv, string $ciphertext, string $mac, ?array $meta = null): string
    {
        $payload = [
            'iv' => Base64Url::encode($iv),
            'value' => Base64Url::encode($ciphertext),
            'mac' => Base64Url::encode($mac),
        ];
        if ($meta !== null) {
            $payload['meta'] = $meta;
        }

        $json = json_encode($payload, JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('Gagal encode JSON');
        }

        return base64_encode($json);
    }

    /**
     * Membuka token base64(JSON) menjadi komponen biner + meta (jika ada).
     *
     * @return array{iv:string,value:string,mac:string,meta?:array}
     */
    public static function unpack(string $token): array
    {
        $json = base64_decode($token, true);
        if ($json === false) {
            throw new \RuntimeException('Base64 token rusak');
        }
        $obj = json_decode($json, true);
        if (! is_array($obj) || ! isset($obj['iv'],$obj['value'],$obj['mac'])) {
            throw new \RuntimeException('Struktur token tidak valid');
        }

        $out = [
            'iv' => Base64Url::decode($obj['iv']),
            'value' => Base64Url::decode($obj['value']),
            'mac' => Base64Url::decode($obj['mac']),
        ];
        if (isset($obj['meta']) && is_array($obj['meta'])) {
            $out['meta'] = $obj['meta'];
        }

        return $out;
    }
}
