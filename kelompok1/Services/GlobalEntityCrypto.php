<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Services;

use Kelompok1\CryptoGraphy\Contracts\ArrayEntity;
use Kelompok1\CryptoGraphy\Contracts\CryptoAutoMap;
use Kelompok1\CryptoGraphy\Secure\SecureSerializer;

/**
 * GlobalEntityCryptoAuto
 * ----------------------
 * Servis global TANPA register mapper manual.
 * Syarat entity:
 *  - implements ArrayEntity (toArray/fromArray)
 *  - implements CryptoAutoMap (purpose, bindKeys, keyInfoTemplates, validateBinding)
 *
 * ENCRYPT:
 *   - Ambil purpose + keyInfoTemplates (berisi placeholder "{field}")
 *   - Ganti placeholder dari nilai field entity (toArray)
 *   - Keyring->deriveChain(infos[]) → masterKey
 *   - SecureSerializer->encryptPayload(payload, masterKey, purpose)
 *
 * DECRYPT:
 *   - Pastikan $bind mengisi semua bindKeys
 *   - Isi placeholder dari $bind → infos[]
 *   - deriveChain → masterKey
 *   - SecureSerializer->decryptPayload(token, masterKey, expectPurpose)
 *   - fromArray → entity
 *   - cryptoValidateBinding(entity, bind) (anti-rebinding)
 */
final readonly class GlobalEntityCrypto
{
    public function __construct(
        private Keyring          $keyring,
        private SecureSerializer $secure
    ) {}

    /** ENCRYPT entity → token base64(JSON {iv,value,mac}) */
    public function encrypt(object $entity, ?int $ttlSec = null, array $meta = []): string
    {
        if (!$entity instanceof ArrayEntity || !$entity instanceof CryptoAutoMap) {
            $cn = $entity::class;
            throw new \InvalidArgumentException("$cn harus implements ArrayEntity & CryptoAutoMap");
        }

        $payload = $entity->toArray();
        $purpose = $entity::cryptoPurpose();

        // Bentuk info HKDF dari entity fields
        $infos = $this->fillTemplates($entity::cryptoKeyInfoTemplates(), $payload);

        $masterKey = $this->keyring->deriveChain($infos);

        return $this->secure->encryptPayload(
            payload:   $payload,
            masterKey: $masterKey,
            purpose:   $purpose,
            ttlSec:    $ttlSec,
            meta:      $meta
        );
    }

    /**
     * DECRYPT token → entity
     * @param class-string $className Harus class yang implements ArrayEntity & CryptoAutoMap
     * @param string $token           Token EtM
     * @param array  $bind            Data minimal untuk derive key (mis. ['uuid'=>...])
     */
    public function decrypt(string $className, string $token, array $bind): object
    {
        if (!is_subclass_of($className, ArrayEntity::class) || !is_subclass_of($className, CryptoAutoMap::class)) {
            throw new \InvalidArgumentException("$className harus implements ArrayEntity & CryptoAutoMap");
        }

        // Pastikan semua bind keys tersedia
        $this->ensureBindKeys($className::cryptoBindKeys(), $bind);

        // Isi template info dari $bind
        $infos = $this->fillTemplates($className::cryptoKeyInfoTemplates(), $bind);
        $masterKey = $this->keyring->deriveChain($infos);

        // Purpose binding (token entity "user" tak bisa dipakai sebagai "chat")
        $payload = $this->secure->decryptPayload(
            token:         $token,
            masterKey:     $masterKey,
            expectPurpose: $className::cryptoPurpose()
        );

        // Reconstruct entity + anti-rebinding
        /** @var ArrayEntity&CryptoAutoMap $className */
        $entity = $className::fromArray($payload);
        $className::cryptoValidateBinding($entity, $bind);

        return $entity;
    }

    /**
     * Ganti placeholder dalam template:
     *   'user:{uuid}' dengan $source['uuid']
     *   'chat:{userUuid}' dengan $source['userUuid']
     *
     * @param array<int,string> $templates
     * @param array<string,mixed> $source  nilai pengganti (entity->toArray() saat encrypt, atau $bind saat decrypt)
     * @return array<int,string>
     */
    private function fillTemplates(array $templates, array $source): array
    {
        $out = [];
        foreach ($templates as $tpl) {
            $filled = preg_replace_callback('/\{([A-Za-z0-9_]+)\}/', function ($m) use ($source, $tpl) {
                $key = $m[1];
                if (!array_key_exists($key, $source)) {
                    throw new \InvalidArgumentException("Template '$tpl' membutuhkan field '{$key}' yang tidak ada");
                }
                $val = $source[$key];
                if (!is_string($val)) {
                    // jika bukan string, konversi aman
                    $val = (string)$val;
                }
                return $val;
            }, $tpl);
            $out[] = $filled ?? $tpl;
        }
        return $out;
    }

    /**
     * Validasi bahwa $bind mengandung semua kunci yang diwajibkan.
     * @param array<int,string> $required
     * @param array<string,mixed> $bind
     */
    private function ensureBindKeys(array $required, array $bind): void
    {
        foreach ($required as $k) {
            if (!array_key_exists($k, $bind)) {
                throw new \InvalidArgumentException("Parameter bind['{$k}'] wajib diisi");
            }
        }
    }
}
