<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Contracts;

/**
 * CryptoAutoMap
 * -------------
 * Metadata kripto per entitas agar servis global bisa bekerja otomatis.
 *
 * - cryptoPurpose()       : string purpose token (mis. "user", "chat")
 * - cryptoBindKeys()      : daftar nama field yang wajib ada di $bind saat decrypt
 * - cryptoKeyInfoTemplates(): daftar template "info" untuk HKDF berantai (orde penting).
 *      Gunakan placeholder {field} yang diambil dari entity (encrypt) atau bind (decrypt).
 *      Contoh:
 *        ['user:{uuid}'] → K_user
 *        ['user:{uuid}', 'chat:{userUuid}'] → K_user lalu K_chat (berantai)
 *
 * - cryptoValidateBinding($entity, $bind): cek anti-rebinding (mis. uuid cocok)
 */
interface CryptoAutoMap
{
    public static function cryptoPurpose(): string;

    /** @return array<int,string> */
    public static function cryptoBindKeys(): array;

    /** @return array<int,string> */
    public static function cryptoKeyInfoTemplates(): array;

    public static function cryptoValidateBinding(object $entity, array $bind): void;
}
