<?php
declare(strict_types=1);

/**
 * tools/create_user_and_keystore.php
 * ----------------------------------
 * Buat 1 user + 1 keystore (PBKDF2-SHA256), dan tulis record CLEAR yang
 * ditandatangani HMAC (anti-tamper) ke data/app-user.jsonl.
 *
 * Relasi:
 *   data/key-store-user.jsonl            : index { uuid -> keystore_path }
 *   config/keystore/{uuidHex}.pass.json  : metadata PBKDF2 (salt, iter, auth) TANPA master key
 *   data/app-user.jsonl                  : payload CLEAR + signature (HMAC-SHA256)
 *
 * Jalankan:
 *   php tools/create_user_and_keystore.php
 */

require __DIR__ . '/../vendor/autoload.php';

use Kelompok1\CryptoGraphy\Services\KeyStorePass;
use Kelompok1\CryptoGraphy\KDF\HKDF;
use Kelompok1\CryptoGraphy\MAC\HmacSha256;
use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;
use Kelompok1\CryptoGraphy\Support\Uuid;

use function Laravel\Prompts\{
    intro, outro, text, password, info, note, table, warning, confirm
};

const KS_DIR   = __DIR__ . '/../config/keystore';
const KS_INDEX = __DIR__ . '/../data/key-store-user.jsonl';
const APP_JL   = __DIR__ . '/../data/app-user.jsonl';

intro('👤 Create User + 1:1 Keystore (PBKDF2-SHA256) + Signed CLEAR JSON');

/* ----------------------------------------------------------------------
 | 1) UUID: otomatis 16 byte (128-bit) → HEX32 (tanpa prompt)
 * -------------------------------------------------------------------- */
$uuid = Uuid::generateHex128(); // 32 hex = 16 byte (128-bit)
info('UUID otomatis (16 byte/128-bit, HEX32)');
echo $uuid . PHP_EOL;

/* ----------------------------------------------------------------------
 | 2) Data user
 * -------------------------------------------------------------------- */
$username   = text('Username:', required: true);
$userPass   = password('Password user (akan di-hash SHA-256 di payload):', required: true);
$passphrase = password('Passphrase Keystore (min 6 char):', required: true, validate: fn($v)=>strlen($v)<6?'Minimal 6 karakter':null);

/* ----------------------------------------------------------------------
 | 3) PBKDF2 iterations
 * -------------------------------------------------------------------- */
$iterStr = text('PBKDF2 iterations (>=100000, default 210000):', validate: function($v){
    if ($v === '') return null;
    if (!ctype_digit($v) || (int)$v < 100000) return 'Masukkan angka >= 100000 atau kosong.';
    return null;
});
$iterations = $iterStr === '' ? 210000 : (int)$iterStr;

/* ----------------------------------------------------------------------
 | 4) Keystore path (one-to-one)
 * -------------------------------------------------------------------- */
$uuidKey = $uuid; // HEX32 – aman untuk nama file
$ksPath  = KS_DIR . '/' . $uuidKey . '.pass.json';

/* ----------------------------------------------------------------------
 | 5) Buat keystore PBKDF2 untuk user (salt+iter+auth, tanpa masterKey)
 * -------------------------------------------------------------------- */
try {
    if (!is_dir(KS_DIR)) @mkdir(KS_DIR, 0700, true);
    if (file_exists($ksPath)) {
        if (!confirm("Keystore untuk UUID ini sudah ada. Overwrite?", false)) {
            warning('Dibatalkan.'); exit(1);
        }
        @unlink($ksPath);
    }
    KeyStorePass::init($ksPath, $passphrase, $iterations); // tulis file keystore
    info("✅ Keystore dibuat: " . relpath_from_project($ksPath));
} catch (\Throwable $e) {
    warning('Gagal membuat keystore: '.$e->getMessage()); exit(1);
}

/* ----------------------------------------------------------------------
 | 6) Derive masterKey dari keystore user (verifikasi passphrase via auth)
 * -------------------------------------------------------------------- */
try {
    $masterKey = KeyStorePass::load($ksPath, $passphrase); // 32B biner
} catch (\Throwable $e) {
    warning('Gagal derive masterKey dari keystore: '.$e->getMessage()); exit(1);
}

/* ----------------------------------------------------------------------
 | 7) Buat payload CLEAR & signature HMAC (anti-tamper)
 |    - keyMacClear diturunkan dari masterKey via HKDF (key separation)
 * -------------------------------------------------------------------- */
$keyMacClear = HKDF::derive($masterKey, 32, info: 'signed-clear:mac');
$timestamp   = date('c');

$payload = [
    'uuid'         => $uuid,
    'username'     => $username,
    // DEMO: hash cepat. (Untuk login nyata gunakan argon2id/bcrypt)
    'passwordHash' => hash('sha256', $userPass),
    'timestamp'    => $timestamp,
];

// Canonical JSON (deterministik) → supaya MAC stabil
$serializer = new JsonSerializer();
$canon      = $serializer->serialize($payload);

// Detached signature (Encrypt-then-MAC style untuk CLEAR payload)
$mac = HmacSha256::mac($keyMacClear, $canon);

$recordApp = [
    'uuid'       => $uuid,
    'payload'    => $payload,          // clear JSON
    'signature'  => base64_encode($mac),
    'created_at' => $timestamp,
];

/* ----------------------------------------------------------------------
 | 8) Simpan index keystore & payload user ke JSONL
 * -------------------------------------------------------------------- */
if (!is_dir(dirname(APP_JL))) @mkdir(dirname(APP_JL), 0700, true);
if (!is_dir(dirname(KS_INDEX))) @mkdir(dirname(KS_INDEX), 0700, true);

// index keystore 1:1
$indexLine = json_encode([
        'uuid'          => $uuid,
        'keystore_path' => relpath_from_project($ksPath),
        'created_at'    => $timestamp,
    ], JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE) . PHP_EOL;

if (file_put_contents(KS_INDEX, $indexLine, FILE_APPEND|LOCK_EX) === false) {
    warning('Gagal menulis data/key-store-user.jsonl'); exit(1);
}

// user CLEAR + signature
$appLine = json_encode($recordApp, JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE) . PHP_EOL;
if (file_put_contents(APP_JL, $appLine, FILE_APPEND|LOCK_EX) === false) {
    warning('Gagal menulis data/app-user.jsonl'); exit(1);
}

/* ----------------------------------------------------------------------
 | 9) Tampilkan ringkasan
 * -------------------------------------------------------------------- */
table(headers:['Field','Value'], rows:[
    ['uuid (16 byte/128-bit, HEX32)', $uuid],
    ['username',                      $username],
    ['keystore_path',                 relpath_from_project($ksPath)],
    ['PBKDF2 iterations',             (string)$iterations],
    ['created_at',                    $timestamp],
]);

/* ----------------------------------------------------------------------
 | 10) Edukasi singkat (legend)
 * -------------------------------------------------------------------- */
note(
    "Apa itu PASSHRASE?\n".
    "• Passphrase = kata sandi manusia yang kamu ketik saat membuat keystore.\n".
    "• Dari passphrase + salt + iterations, kita turunkan masterKey (32 byte) via PBKDF2-HMAC-SHA256.\n\n".
    "Apa itu PBKDF2 & kenapa ada iterations?\n".
    "• PBKDF2 adalah Password-Based Key Derivation Function: memperlambat brute-force.\n".
    "• Iterations = berapa kali fungsi hash diulang. Makin besar → makin lambat untuk penyerang.\n".
    "• Salt unik mencegah rainbow table & reuse hasil.\n\n".
    "Anti-tamper dengan HMAC:\n".
    "• Kita simpan payload CLEAR dan signature terpisah: mac = HMAC(keyMacClear, canonicalJson(payload)).\n".
    "• Jika ada yang mengubah payload (username/password/timestamp), signature jadi mismatch saat diverifikasi.\n".
    "• Kunci HMAC diturunkan dari masterKey via HKDF (key separation)."
);

outro('Selesai ✅');

/* ======================================================================
 | Helper: tampilkan path relatif biar rapi di tabel
 * ==================================================================== */
function relpath_from_project(string $abs): string {
    $root = realpath(__DIR__.'/..');
    $absR = realpath($abs);
    if ($root && $absR && str_starts_with($absR, $root)) {
        return ltrim(substr($absR, strlen($root)), '/\\');
    }
    return $abs;
}
