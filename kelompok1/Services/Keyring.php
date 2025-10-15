<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Services;

use Kelompok1\CryptoGraphy\KDF\HKDF;

/**
 * Keyring
 * -------
 * Menurunkan kunci dari App Secret. Tambah helper deriveChain()
 * agar bisa menjalankan HKDF bertingkat berdasarkan daftar "info".
 */
final readonly class Keyring
{
    public function __construct(private string $appSecret)
    {
        if (strlen($this->appSecret) < 32) {
            throw new \InvalidArgumentException('App secret minimal 32 byte');
        }
    }

    /**
     * Turunkan key berantai:
     *   seed = appSecret
     *   foreach $infos as $info: seed = HKDF(seed, 32, info=$info)
     * Hasil akhir = seed.
     *
     * @param array<int,string> $infos
     */
    public function deriveChain(array $infos): string
    {
        $seed = $this->appSecret;
        foreach ($infos as $info) {
            $seed = HKDF::derive($seed, 32, info: $info);
        }
        return $seed;
    }
}
