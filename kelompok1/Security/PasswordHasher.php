<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Security;

/**
 * Class PasswordHasher
 * --------------------
 * Pembungkus aman untuk hashing password dengan salt menggunakan Argon2id.
 *
 * Kenapa Argon2id?
 * - Argon2id adalah standar modern untuk password hashing (slow + memory-hard).
 * - Secara otomatis menyertakan SALT acak per-hash di dalam string hash.
 * - Password sama → hash berbeda (karena salt & parameter berbeda) → aman dari rainbow table.
 *
 * Fungsi:
 * - hash(string $password): string
 *      Menghasilkan string hash (mis. "$argon2id$v=19$m=65536,t=3,p=2$...").
 * - verify(string $password, string $hash): bool
 *      Memverifikasi password terhadap hash yang disimpan.
 * - needsRehash(string $hash): bool
 *      Mengecek apakah hash lama perlu di-rehash (mis. upgrade parameter cost).
 *
 * Catatan:
 * - Tidak perlu mengelola salt sendiri. password_hash() membuat salt acak secara otomatis.
 * - Simpan HASIL string hash apa adanya di database/berkas.
 * - Saat upgrade policy (mis. naikkan memory_cost/time_cost), gunakan needsRehash()
 *   lalu jalankan hash ulang saat user login (rolling upgrade).
 */
final class PasswordHasher
{
    /** Opsi default Argon2id (reasonable defaults; sesuaikan kemampuan server). */
    private array $options;

    /**
     * @param int|null $memoryCost KiB (default 65536 = 64 MiB)
     * @param int|null $timeCost   Iterasi (default 3)
     * @param int|null $threads    Paralelisme (default 2)
     */
    public function __construct(
        ?int $memoryCost = 65536, // 64 MiB
        ?int $timeCost   = 3,
        ?int $threads    = 2
    ) {
        // fallback ke bcrypt bila Argon2id tidak tersedia (jarang, tapi antisipasi).
        if (!defined('PASSWORD_ARGON2ID')) {
            trigger_error(
                'PASSWORD_ARGON2ID tidak tersedia; fallback ke bcrypt. ' .
                'Pertimbangkan upgrade PHP/extension untuk keamanan optimal.',
                E_USER_NOTICE
            );
        }

        $this->options = [
            'memory_cost' => $memoryCost ?? 65536,
            'time_cost'   => $timeCost   ?? 3,
            'threads'     => $threads    ?? 2,
        ];
    }

    /**
     * Hash password menjadi string Argon2id (dengan salt acak internal).
     *
     * @param  string $password Password plaintext dari user.
     * @return string           String hash (simpan ini di DB/berkas).
     *
     * @throws \RuntimeException Bila hashing gagal.
     */
    public function hash(string $password): string
    {
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        var_dump($algo);die;
        $hash = password_hash($password, $algo, $this->options);
        if ($hash === false) {
            throw new \RuntimeException('Gagal membuat hash password');
        }
        return $hash;
    }

    /**
     * Verifikasi password terhadap hash yang disimpan.
     *
     * @param  string $password Password plaintext dari user.
     * @param  string $hash     String hash yang tersimpan ($argon2id$...).
     * @return bool             True jika cocok.
     */
    public function verify(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    /**
     * Perlu re-hash? (mis. setelah upgrade parameter cost/policy)
     *
     * @param  string $hash Hash lama.
     * @return bool         True jika perlu di-hash ulang dengan policy baru.
     */
    public function needsRehash(string $hash): bool
    {
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        return password_needs_rehash($hash, $algo, $this->options);
    }
}
