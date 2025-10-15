<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Serialization;

use Kelompok1\CryptoGraphy\Contracts\PayloadSerializer;

/**
 * JsonSerializer
 * --------------
 * Serializer berbasis JSON (aman, portable, mudah di-inspect).
 *
 * Keamanan:
 * - Menghindari PHP unserialize() (risiko object injection).
 * - Validasi hasil decode harus array.
 */
final class JsonSerializer implements PayloadSerializer
{
    public function serialize(array $payload): string
    {
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new \RuntimeException('Gagal JSON-encode payload');
        }
        return $json;
    }

    public function deserialize(string $binary): array
    {
        $arr = json_decode($binary, true);
        if (!is_array($arr)) {
            throw new \RuntimeException('Payload bukan JSON object');
        }
        return $arr;
    }
}
