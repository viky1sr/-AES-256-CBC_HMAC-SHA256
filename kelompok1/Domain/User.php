<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Domain;

use Kelompok1\CryptoGraphy\Contracts\ArrayEntity;
use Kelompok1\CryptoGraphy\Contracts\CryptoAutoMap;

/**
 * Entity: User
 * ------------
 * Contoh model domain yang akan kita serialize → encrypt → token.
 *
 * Field (contoh tugas):
 * - uuid      : string (16 byte/karakter unik ID user)
 * - username  : string
 * - password  : string (disarankan sudah hash, mis. bcrypt/argon)
 * - timestamp : string (ISO8601 atau unix epoch, sesuai kebutuhan)
 */
final class User implements ArrayEntity, CryptoAutoMap
{
    public function __construct(
        public string $uuid,
        public string $username,
        public string $password,
        public string $timestamp
    ) {}

    // --- ArrayEntity ---
    public function toArray(): array
    {
        return [
            'uuid'      => $this->uuid,
            'username'  => $this->username,
            'password'  => $this->password,
            'timestamp' => $this->timestamp,
        ];
    }

    public static function fromArray(array $a): self
    {
        foreach (['uuid','username','password','timestamp'] as $k) {
            if (!isset($a[$k]) || !is_string($a[$k])) {
                throw new \RuntimeException("User.fromArray: field '$k' tidak valid");
            }
        }
        return new self($a['uuid'], $a['username'], $a['password'], $a['timestamp']);
    }

    // --- CryptoAutoMap ---
    public static function cryptoPurpose(): string { return 'user'; }

    /** Saat decrypt, service butuh bind ini untuk derive key dan validasi */
    public static function cryptoBindKeys(): array { return ['uuid']; }

    /**
     * Rantai HKDF:
     *   seed = appSecret
     *   K_user = HKDF(seed, 32, info="user:{uuid}")
     */
    public static function cryptoKeyInfoTemplates(): array
    {
        return ['user:{uuid}'];
    }

    /** Anti-rebinding: pastikan UUID entity cocok dengan bind['uuid'] */
    public static function cryptoValidateBinding(object $entity, array $bind): void
    {
        /** @var self $entity */
        if (!isset($bind['uuid']) || $entity->uuid !== $bind['uuid']) {
            throw new \RuntimeException('User token: UUID tidak cocok (anti-rebinding)');
        }
    }
}
