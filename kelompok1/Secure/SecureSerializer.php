<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Secure;

use Kelompok1\CryptoGraphy\Contracts\PayloadSerializer;
use Kelompok1\CryptoGraphy\CryptoService;

/**
 * SecureSerializer
 * ----------------
 * “Laravel-style” secure payload:
 *   APP → (serialize) → ENCRYPT (AES-256-CBC) + HMAC → TOKEN
 *   TOKEN → (verif MAC) → DECRYPT → (deserialize) → APP
 *
 * Jaminan:
 * - Kerahasiaan: AES-256-CBC (PKCS#7 pad, IV acak & unik).
 * - Integritas & Autentikasi: HMAC-SHA256 atas (IV || ciphertext) — Encrypt-then-MAC.
 * - Anti-tamper: 1 bit pun berubah pada IV/value/MAC → MAC mismatch → token ditolak.
 *
 * Envelope:
 * - Kita membungkus payload + meta ringan (v, purpose, issued_at, expires_at).
 * - Envelope DI-SERIALIZE → lalu dienkripsi. Jadi meta ikut terlindungi (confidentiality).
 *
 * Cara pakai cepat:
 *   $ser = new JsonSerializer();
 *   $ss  = new SecureSerializer($ser);
 *   $token = $ss->encryptPayload(['uid'=>1], $k, purpose:'session', ttlSec:3600);
 *   $data  = $ss->decryptPayload($token, $k, expectPurpose:'session');
 */
final class SecureSerializer
{
    public function __construct(
        private readonly PayloadSerializer $serializer
    ) {}

    /**
     * Enkripsi payload (serialize → encrypt → token).
     *
     * @param array       $payload     Data aplikasi.
     * @param string      $masterKey   Master key biner (≥ 32B). Jika dari passphrase: hash('sha256', pass, true).
     * @param string|null $purpose     Binding logis opsional (mis. "session", "reset-password").
     * @param int|null    $ttlSec      Time-to-live (detik). Jika null → tidak kadaluarsa otomatis.
     * @return string     base64(JSON {iv,value,mac})
     */
    public function encryptPayload(
        array $payload,
        string $masterKey,
        ?string $purpose = null,
        ?int $ttlSec = null
    ): string {
        $now = time();

        $envelope = [
            'v'          => 1,                // versi format (bisa kamu ganti saat upgrade)
            'purpose'    => $purpose,         // binding opsional
            'issued_at'  => $now,             // unix epoch
            'expires_at' => $ttlSec ? ($now + $ttlSec) : null,
            'data'       => $payload,         // payload aplikasi
        ];

        $binary = $this->serializer->serialize($envelope);
        return CryptoService::encrypt($binary, $masterKey);
    }

    /**
     * Dekripsi payload (token → verif MAC → decrypt → deserialize).
     *
     * @param string      $token          base64(JSON {iv,value,mac})
     * @param string      $masterKey      Master key biner (≥ 32B).
     * @param string|null $expectPurpose  Jika diisi, wajib sama dengan envelope.purpose.
     * @return array                      Payload aplikasi.
     */
    public function decryptPayload(
        string $token,
        string $masterKey,
        ?string $expectPurpose = null
    ): array {
        $binary = CryptoService::decrypt($token, $masterKey);  // verif MAC dulu
        $envelope = $this->serializer->deserialize($binary);

        // Validasi minimal struktur envelope
        foreach (['v','issued_at','data'] as $k) {
            if (!array_key_exists($k, $envelope)) {
                throw new \RuntimeException('Envelope tidak lengkap');
            }
        }
        if (!is_array($envelope['data'])) {
            throw new \RuntimeException('Envelope.data bukan array');
        }

        // Purpose binding (opsional)
        if ($expectPurpose !== null) {
            $p = $envelope['purpose'] ?? null;
            if ($p !== $expectPurpose) {
                throw new \RuntimeException('Purpose tidak cocok');
            }
        }

        // Expiry (opsional)
        if (!empty($envelope['expires_at']) && is_int($envelope['expires_at'])) {
            if (time() > $envelope['expires_at']) {
                throw new \RuntimeException('Token kedaluwarsa');
            }
        }

        return $envelope['data'];
    }
}
