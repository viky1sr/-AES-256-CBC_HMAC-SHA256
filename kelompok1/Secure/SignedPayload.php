<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Secure;

use Kelompok1\CryptoGraphy\Contracts\PayloadSerializer;
use Kelompok1\CryptoGraphy\Support\Base64Url;
use Kelompok1\CryptoGraphy\KDF\HKDF;
use Kelompok1\CryptoGraphy\MAC\HmacSha256;

/**
 * SignedPayload (tanpa enkripsi, anti-tamper)
 * -------------------------------------------
 * token = base64(JSON { payload: b64url(serialize(payload)), sig: b64url(HMAC) })
 * Verifikasi: HMAC(K_sig, payloadB64 || '|' || context)
 *
 * Kapan dipakai?
 * - Data boleh dibaca user, tapi tidak boleh diubah (cth: signed link).
 */
final class SignedPayload
{
    public function __construct(
        private readonly PayloadSerializer $serializer
    ) {}

    private function deriveSigKey(string $masterKey): string
    {
        // key separation untuk signature
        return HKDF::derive($masterKey, 32, info: 'signed:payload');
    }

    /** @return string token base64(JSON) */
    public function sign(array $payload, string $masterKey, string $context = ''): string
    {
        $kSig = $this->deriveSigKey($masterKey);

        $binary = $this->serializer->serialize($payload);
        $payloadB64 = Base64Url::encode($binary);

        $sig = HmacSha256::mac($kSig, $payloadB64 . '|' . $context);

        $json = json_encode([
            'payload' => $payloadB64,
            'sig'     => Base64Url::encode($sig),
        ], JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            throw new \RuntimeException('Gagal encode JSON');
        }

        return base64_encode($json);
    }

    /** @return array payload (akan throw jika signature tidak valid) */
    public function verify(string $token, string $masterKey, string $context = ''): array
    {
        $kSig = $this->deriveSigKey($masterKey);

        $json = base64_decode($token, true);
        if ($json === false) throw new \RuntimeException('Token base64 rusak');

        $obj = json_decode($json, true);
        if (!is_array($obj) || !isset($obj['payload'], $obj['sig'])) {
            throw new \RuntimeException('Struktur token tidak valid');
        }

        $payloadB64 = (string)$obj['payload'];
        $sig        = Base64Url::decode((string)$obj['sig']);

        if (!HmacSha256::verify($kSig, $payloadB64 . '|' . $context, $sig)) {
            throw new \RuntimeException('Signature tidak valid');
        }

        $payloadBin = Base64Url::decode($payloadB64);
        return $this->serializer->deserialize($payloadBin);
    }
}
