<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Contracts;

/**
 * ArrayEntity
 * -----------
 * Kontrak minimal agar entity bisa di-serialize aman (JSON).
 * Hindari serialize object PHP untuk mencegah object-injection.
 */
interface ArrayEntity
{
    /** Ubah entitas → array (siap JSON serialize). */
    public function toArray(): array;

    /** Buat entitas dari array (hasil JSON decode). */
    public static function fromArray(array $a): self;
}
