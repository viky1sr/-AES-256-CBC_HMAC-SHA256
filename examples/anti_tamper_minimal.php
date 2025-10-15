<?php
declare(strict_types=1);

// examples/anti_tamper_minimal.php
require __DIR__ . '/../vendor/autoload.php';

use Kelompok1\CryptoGraphy\CryptoService;

/**
 * Demo anti-tamper:
 *  - Token = base64(JSON {iv,value,mac})
 *  - HMAC-SHA256(keyMac, iv||value) diverifikasi SEBELUM decrypt
 *  - Ubah 1 bit saja → MAC mismatch → dekripsi ditolak
 */

// 32B master key (biner). Di produksi simpan aman (env/secret manager/HSM).
$masterKey = random_bytes(32);
$plain     = "Halo rahasia 👋 — ini contoh anti-tamper";

// ENCRYPT → dapat token EtM
$token = CryptoService::encrypt($plain, $masterKey);
echo "Token asli:\n$token\n\n";

// DECRYPT normal (harus sukses)
$dec = CryptoService::decrypt($token, $masterKey);
echo "Decrypt OK: $dec\n\n";

// ===== Tamper 1: Flip 1 bit di payload base64 (acak posisinya) =====
$bad1 = tamper_flip_one_bit_in_base64($token);
echo "Token di-tamper (flip 1 bit):\n$bad1\n\n";

try {
    CryptoService::decrypt($bad1, $masterKey);
    echo "❌ TIDAK DIHARAPKAN: decrypt berhasil padahal token sudah diubah.\n";
} catch (Throwable $e) {
    echo "✅ Sesuai harapan: decrypt GAGAL (MAC mismatch): {$e->getMessage()}\n\n";
}

// ===== Tamper 2: Ubah field 'mac' di JSON =====
$bad2 = tamper_change_mac_field($token);
echo "Token di-tamper (ubah field mac):\n$bad2\n\n";

try {
    CryptoService::decrypt($bad2, $masterKey);
    echo "❌ TIDAK DIHARAPKAN: decrypt berhasil padahal MAC diubah.\n";
} catch (Throwable $e) {
    echo "✅ Sesuai harapan: decrypt GAGAL (MAC mismatch): {$e->getMessage()}\n\n";
}

/* ---------------- Helpers ---------------- */

/** Flip 1 bit di base64 token (random index yang aman). */
function tamper_flip_one_bit_in_base64(string $b64): string
{
    $bin = base64_decode($b64, true);
    if ($bin === false || strlen($bin) < 16) return $b64;

    // balikkan 1 bit di tengah agar hampir pasti mengubah nilai JSON biner
    $i = intdiv(strlen($bin), 2);
    $bin[$i] = $bin[$i] ^ "\x01";
    return base64_encode($bin);
}

/** Ubah field "mac" menjadi semua 0 di JSON base64 (tetap base64url-encode). */
function tamper_change_mac_field(string $b64): string
{
    $json = base64_decode($b64, true);
    if ($json === false) return $b64;

    $obj = json_decode($json, true);
    if (!is_array($obj) || !isset($obj['mac'])) return $b64;

    // timpa 'mac' dengan base64url(32 byte nol)
    $macZeros = rtrim(strtr(base64_encode(str_repeat("\x00", 32)), '+/', '-_'), '=');
    $obj['mac'] = $macZeros;

    $json2 = json_encode($obj, JSON_UNESCAPED_SLASHES);
    if ($json2 === false) return $b64;

    return base64_encode($json2);
}
