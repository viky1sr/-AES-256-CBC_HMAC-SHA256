<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Contracts;

use Kelompok1\CryptoGraphy\Services\Keyring;

/**
 * EntityMapper
 * ------------
 * "Adaptor" antara Domain Entity dan layer kriptografi.
 *
 * Tugas mapper untuk tiap Class domain:
 * - Menentukan purpose (binding logis token).
 * - Mengubah entity <-> array (untuk serializer).
 * - Menurunkan kunci (HKDF) untuk encrypt/decrypt.
 * - (Opsional) Validasi binding setelah decrypt (anti-rebinding).
 */
interface EntityMapper
{
    /** Nama purpose untuk token entity ini (mis. "user", "chat"). */
    public function purpose(): string;

    /** Ubah object entity → array (untuk diserialisasi). */
    public function toArray(object $entity): array;

    /** Ubah array hasil decrypt → object entity. */
    public function fromArray(array $data): object;

    /**
     * Menurunkan masterKey untuk ENKRIPSI dari entity (biasanya pakai UUID).
     * Contoh: Keyring->userKey($entity->uuid)
     */
    public function deriveKeyForEncrypt(Keyring $keyring, object $entity): string;

    /**
     * Menurunkan masterKey untuk DEKRIPSI dari binding info (tanpa entity).
     * Contoh: Keyring->userKey($bind['uuid'])
     */
    public function deriveKeyForDecrypt(Keyring $keyring, array $bind): string;

    /**
     * (Opsional) Setelah decrypt → entity, validasi binding (anti rebind).
     * Misal: pastikan $entity->uuid === $bind['uuid'].
     * Lempar exception bila tidak cocok.
     */
    public function validateBinding(object $entity, array $bind): void;
}
