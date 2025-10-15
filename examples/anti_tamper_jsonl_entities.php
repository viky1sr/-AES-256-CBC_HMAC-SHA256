<?php
declare(strict_types=1);

// examples/anti_tamper_jsonl_entities.php
require __DIR__ . '/../vendor/autoload.php';

use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;
use Kelompok1\CryptoGraphy\Secure\SecureSerializer;
use Kelompok1\CryptoGraphy\Services\Keyring;
use Kelompok1\CryptoGraphy\Services\GlobalEntityCrypto;

use Kelompok1\CryptoGraphy\Domain\User;
use Kelompok1\CryptoGraphy\Domain\ChatMessage;

/**
 * Uji anti-tamper dengan penyimpanan JSONL:
 *  - Masing-masing baris: {"class": "Nama\Class", "bind": {...}, "token":"..."}
 *  - Ubah token di file → decrypt gagal
 */

$storePath = __DIR__ . '/tokens.jsonl';

// 1) Wiring
$appSecret = hash('sha256', 'APP_SECRET_DEMO', true); // 32B biner
$keyring   = new Keyring($appSecret);
$secure    = new SecureSerializer(new JsonSerializer());
$gec       = new GlobalEntityCrypto($keyring, $secure);

// 2) Buat data contoh & encrypt
$user = new User('USER-UUID-0001', 'viky', '$argon2id$hash...', date('c'));
$chat = new ChatMessage($user->uuid, 'Halo rahasia 👋', date('c'));

$userToken = $gec->encrypt($user, ttlSec: 3600);
$chatToken = $gec->encrypt($chat, ttlSec: 600);

// 3) Simpan JSONL
$rows = [
    [
        'class' => User::class,
        'bind'  => ['uuid' => $user->uuid],  // dibutuhkan saat decrypt
        'token' => $userToken,
    ],
    [
        'class' => ChatMessage::class,
        'bind'  => ['userUuid' => $user->uuid],
        'token' => $chatToken,
    ],
];
file_put_contents($storePath, implode("", array_map(fn($r) => json_encode($r, JSON_UNESCAPED_SLASHES)."\n", $rows)));
echo "Tersimpan ke JSONL: {$storePath}\n\n";

// 4) Baca kembali & decrypt (harus sukses)
echo "=== Decrypt dari JSONL (asli) ===\n";
foreach (file($storePath, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) as $line) {
    $row = json_decode($line, true);
    try {
        $obj = $gec->decrypt($row['class'], $row['token'], $row['bind']);
        echo "[OK] {$row['class']} → "; var_dump($obj);
    } catch (Throwable $e) {
        echo "[FAIL] {$row['class']} → {$e->getMessage()}\n";
    }
}
echo "\n";

// 5) Tamper baris ke-2 (ubah 1 bit di token)
$lines = file($storePath, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES);
if (count($lines) >= 2) {
    $tampered = json_decode($lines[1], true);
    $tampered['token'] = flip_one_bit_b64($tampered['token']);
    $lines[1] = json_encode($tampered, JSON_UNESCAPED_SLASHES);
    file_put_contents($storePath, implode("\n", $lines)."\n");
    echo "Baris ke-2 di-tamper (flip 1 bit di base64 token) dan ditulis ulang ke JSONL.\n\n";
}

// 6) Coba decrypt lagi (baris ke-2 harus gagal)
echo "=== Decrypt dari JSONL (setelah tamper) ===\n";
foreach (file($storePath, FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES) as $line) {
    $row = json_decode($line, true);
    try {
        $obj = $gec->decrypt($row['class'], $row['token'], $row['bind']);
        echo "[OK] {$row['class']} → "; var_dump($obj);
    } catch (Throwable $e) {
        echo "[FAIL] {$row['class']} → {$e->getMessage()}\n";
    }
}

function flip_one_bit_b64(string $b64): string {
    $bin = base64_decode($b64, true);
    if ($bin === false || strlen($bin) < 16) return $b64;
    $i = intdiv(strlen($bin), 2);
    $bin[$i] = $bin[$i] ^ "\x01";
    return base64_encode($bin);
}
