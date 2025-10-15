<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Domain;

use Kelompok1\CryptoGraphy\Contracts\ArrayEntity;
use Kelompok1\CryptoGraphy\Contracts\CryptoAutoMap;

/**
 * Entity: ChatMessage
 * -------------------
 * Pesan chat milik user tertentu.
 *
 * Field:
 * - userUuid : string (relasi ke User.uuid)
 * - message  : string
 * - timestamp: string
 */
final class ChatMessage implements ArrayEntity, CryptoAutoMap
{
    public function __construct(
        public string $userUuid,
        public string $message,
        public string $timestamp
    ) {}

    public function toArray(): array
    {
        return [
            'userUuid'  => $this->userUuid,
            'message'   => $this->message,
            'timestamp' => $this->timestamp,
        ];
    }

    public static function fromArray(array $a): self
    {
        foreach (['userUuid','message','timestamp'] as $k) {
            if (!isset($a[$k]) || !is_string($a[$k])) {
                throw new \RuntimeException("ChatMessage.fromArray: field '$k' tidak valid");
            }
        }
        return new self($a['userUuid'], $a['message'], $a['timestamp']);
    }

    public static function cryptoPurpose(): string { return 'chat'; }

    /** Saat decrypt, butuh userUuid untuk derive key & validasi */
    public static function cryptoBindKeys(): array { return ['userUuid']; }

    /**
     * Rantai HKDF:
     *   seed = appSecret
     *   K_user = HKDF(seed, 32, "user:{userUuid}")
     *   K_chat = HKDF(K_user, 32, "chat:{userUuid}")
     */
    public static function cryptoKeyInfoTemplates(): array
    {
        return ['user:{userUuid}', 'chat:{userUuid}'];
    }

    /** Anti-rebinding: pastikan message milik userUuid yang benar */
    public static function cryptoValidateBinding(object $entity, array $bind): void
    {
        /** @var self $entity */
        if (!isset($bind['userUuid']) || $entity->userUuid !== $bind['userUuid']) {
            throw new \RuntimeException('Chat token: userUuid tidak cocok (anti-rebinding)');
        }
    }
}
