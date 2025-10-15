<?php
declare(strict_types=1);

/**
 * tools/verify_user_records.php
 * -----------------------------
 * Verifikasi integritas record user CLEAR JSON + signature (HMAC-SHA256),
 * menggunakan (username, password, passphrase keystore) — TANPA UUID.
 *
 * Alur:
 *  1) Input username + password user + passphrase keystore
 *  2) Cari record user di data/app-user.jsonl (payload.username == input)
 *  3) Hash password input (SHA-256) dan bandingkan dengan payload.passwordHash
 *  4) Ambil uuid dari payload → cari keystore path di data/key-store-user.jsonl
 *  5) Derive masterKey via KeyStorePass::load(keystorePath, passphrase)  // verifikasi auth
 *  6) keyMacClear = HKDF(masterKey, 32, info='signed-clear:mac')
 *  7) Recompute mac = HMAC-SHA256(keyMacClear, canonicalJson(payload))
 *  8) Bandingkan dengan signature (base64 di file) → hasil OK / TAMPER
 *
 * Jalankan:
 *   php tools/verify_user_records.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Kelompok1\CryptoGraphy\Services\KeyStorePass;
use Kelompok1\CryptoGraphy\KDF\HKDF;
use Kelompok1\CryptoGraphy\MAC\HmacSha256;
use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;

use function Laravel\Prompts\{
    intro, outro, text, password, info, warning, note, table, confirm
};

const KS_INDEX = __DIR__ . '/../data/key-store-user.jsonl';   // {uuid, keystore_path, created_at}
const APP_JL   = __DIR__ . '/../data/app-user.jsonl';         // {uuid, payload:{...}, signature, created_at}

intro('🔍 Verify User Record — CLEAR JSON + HMAC (username/password/passphrase)');

// 1) Input kredensial verifikasi
$username   = text('Username:', required: true);
$userPass   = password('Password user:', required: true);
$passphrase = password('Passphrase keystore (min 6 char):', required: true, validate: fn($v)=>strlen($v)<6?'Minimal 6 karakter':null);

// 2) Load record user dari APP_JL berdasar username
$record = findUserRecordByUsername($username);
if ($record === null) {
    warning("Username '{$username}' tidak ditemukan di ".relpath(APP_JL));
    exit(1);
}
$payload   = $record['payload'];         // array
$uuid      = (string)($payload['uuid'] ?? '');
$sigBase64 = (string)($record['signature'] ?? '');
$createdAt = (string)($record['created_at'] ?? '');

// 3) Verifikasi password hash (DEMO: SHA-256)
$hashInput = hash('sha256', $userPass);
$hashFile  = (string)($payload['passwordHash'] ?? '');
$pwdOk     = hash_equals($hashInput, $hashFile);

// 4) Ambil keystore path dari KS_INDEX via uuid
$ksPath = findKeystorePathByUuid($uuid);
if ($ksPath === null) {
    warning("Keystore untuk UUID '{$uuid}' tidak ditemukan di ".relpath(KS_INDEX));
    exit(1);
}

// 5) Derive masterKey dari keystore via passphrase (juga memverifikasi auth di keystore)
try {
    $absKsPath = absolutize_from_project($ksPath);
    $masterKey = KeyStorePass::load($absKsPath, $passphrase); // 32B biner
    $passphraseOk = true;
} catch (\Throwable $e) {
    $passphraseOk = false;
    $masterKey = str_repeat("\x00", 32); // dummy
}

// 6) Derive keyMacClear via HKDF (key separation)
$keyMacClear = HKDF::derive($masterKey, 32, info: 'signed-clear:mac');

// 7) Canonical JSON dari payload → recompute HMAC
$serializer = new JsonSerializer();
$canon      = $serializer->serialize($payload); // deterministik
$macCalc    = HmacSha256::mac($keyMacClear, $canon);
$macFile    = base64_decode($sigBase64, true);
$macOk      = is_string($macFile) && hash_equals($macCalc, $macFile);

// 8) Tabel hasil
table(
    headers: ['Check', 'Result', 'Detail'],
    rows: [
        ['Username ditemukan', 'OK', $username],
        ['Password cocok (SHA-256)', $pwdOk ? 'OK' : 'FAILED', $pwdOk ? 'match' : 'mismatch'],
        ['Passphrase keystore', $passphraseOk ? 'OK' : 'FAILED', $passphraseOk ? 'auth ok' : 'auth gagal / salah passphrase'],
        ['HMAC payload', $macOk ? 'OK' : 'FAILED', $macOk ? 'signature match' : 'mismatch'],
    ]
);

// 9) Kesimpulan + edukasi
if ($pwdOk && $passphraseOk && $macOk) {
    info("✅ VERIFIKASI BERHASIL — Record user VALID (tidak tampered).");
} else {
    warning("🛑 VERIFIKASI GAGAL — TAMPER DETECTED atau kredensial salah.");
}

note(
    "Bagaimana cara kerja verifikasi ini?\n".
    "• Password: kita hash input dengan SHA-256 dan bandingkan dengan passwordHash di payload (DEMO; untuk login nyata gunakan argon2id/bcrypt).\n".
    "• Keystore: dari passphrase + salt + iterations (PBKDF2), kita turunkan masterKey; file keystore menyimpan salt/iter/auth (bukan masterKey).\n".
    "• HMAC: keyMacClear = HKDF(masterKey, 32, info='signed-clear:mac'). MAC = HMAC-SHA256(keyMacClear, canonicalJson(payload)).\n".
    "• Anti-tamper: bila ada byte pada payload di file diubah (username/password/timestamp), HMAC akan mismatch walaupun kamu tahu password.\n\n".
    "Kenapa tanpa UUID?\n".
    "• Script ini mencari user lewat username. Setelah ketemu, kita ambil uuid dari payload untuk menemukan keystore terkait (1:1) di key-store-user.jsonl.\n\n".
    "Catatan keamanan:\n".
    "• Pastikan file JSONL hanya bisa ditulis oleh proses yang berwenang. HMAC mencegah modifikasi *silent*, namun kebijakan akses tetap penting.\n".
    "• Iterations PBKDF2 yang tinggi memperlambat brute-force passphrase.\n"
);

outro('Selesai ✅');

/* ======================================================================
 | Helpers
 * ==================================================================== */

/**
 * Cari record user di APP_JL berdasarkan payload.username == $username.
 * @return array|null
 */
function findUserRecordByUsername(string $username): ?array
{
    if (!is_file(APP_JL)) return null;
    $fh = fopen(APP_JL, 'rb');
    if (!$fh) return null;
    try {
        while (!feof($fh)) {
            $line = trim((string)fgets($fh));
            if ($line === '') continue;
            $obj = json_decode($line, true);
            if (!is_array($obj)) continue;
            $payload = $obj['payload'] ?? null;
            if (is_array($payload) && ($payload['username'] ?? '') === $username) {
                return $obj;
            }
        }
    } finally {
        fclose($fh);
    }
    return null;
}

/**
 * Cari keystore path di KS_INDEX berdasarkan uuid.
 * @return string|null relative/path/to/keystore.json
 */
function findKeystorePathByUuid(string $uuid): ?string
{
    if ($uuid === '' || !is_file(KS_INDEX)) return null;
    $fh = fopen(KS_INDEX, 'rb');
    if (!$fh) return null;
    try {
        while (!feof($fh)) {
            $line = trim((string)fgets($fh));
            if ($line === '') continue;
            $obj = json_decode($line, true);
            if (!is_array($obj)) continue;
            if (($obj['uuid'] ?? '') === $uuid) {
                return (string)($obj['keystore_path'] ?? null);
            }
        }
    } finally {
        fclose($fh);
    }
    return null;
}

/** Tampilan path relatif agar rapi di UI */
function relpath(string $abs): string {
    $root = realpath(__DIR__.'/..');
    $absR = realpath($abs);
    if ($root && $absR && str_starts_with($absR, $root)) {
        return ltrim(substr($absR, strlen($root)), '/\\');
    }
    return $abs;
}

/** Ubah path relatif (dari project root) menjadi absolut */
function absolutize_from_project(string $relOrAbs): string {
    if (str_starts_with($relOrAbs, '/')) return $relOrAbs;
    $root = realpath(__DIR__.'/..');
    return $root ? $root.'/'.ltrim($relOrAbs, '/\\') : $relOrAbs;
}
