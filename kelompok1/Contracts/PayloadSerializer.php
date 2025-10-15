<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Contracts;

/**
 * Interface PayloadSerializer
 * ---------------------------
 * Kontrak serializer payload sebelum dienkripsi (dan sesudah didekripsi).
 *
 * Kenapa ada lapisan ini?
 * - Laravel mengenkripsi hasil "serialize payload". Kita buat abstraction agar
 *   format bisa ditukar (JSON, dsb) tanpa ubah kode keamanan.
 *
 * Rekomendasi:
 * - Gunakan JSON untuk menghindari risiko object injection dari PHP unserialize().
 */
interface PayloadSerializer
{
    /**
     * Ubah struktur payload → biner (string) siap dienkripsi.
     * @param array $payload Data aplikasi (array skalar / nested).
     */
    public function serialize(array $payload): string;

    /**
     * Ubah biner hasil dekripsi → struktur payload aplikasi.
     * @return array Payload sebagai array asosiatif.
     */
    public function deserialize(string $binary): array;
}
