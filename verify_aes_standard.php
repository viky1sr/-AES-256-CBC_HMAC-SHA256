<?php
require_once __DIR__ . '/vendor/autoload.php';

use Kelompok1\CryptoGraphy\CryptoService;
use Kelompok1\CryptoGraphy\KDF\HKDF;
use Kelompok1\CryptoGraphy\Support\Base64Url;

/**
 * Script to verify that .dat files are standard AES-256-CBC
 */

$masterKey = str_repeat('k', 32); // 32 bytes key for testing
$plaintext = "Ini adalah pesan standar AES-256-CBC untuk dosen.";

echo "--- 1. Encryption via CryptoService ---\n";
$token = CryptoService::encrypt($plaintext, $masterKey);
$unpacked = \Kelompok1\CryptoGraphy\Token\EtmToken::unpack($token);

$iv = $unpacked['iv'];
$ct = $unpacked['value']; // Raw ciphertext
$mac = $unpacked['mac'];

echo "Plaintext: $plaintext\n";
echo "IV (hex): " . bin2hex($iv) . "\n";
echo "Ciphertext size: " . strlen($ct) . " bytes\n";
echo "Ciphertext (hex): " . bin2hex($ct) . "\n";

// Get keys
$keyEnc = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');
echo "Key Enc (hex): " . bin2hex($keyEnc) . "\n";

echo "\n--- 2. Verify with manual openssl_decrypt ---\n";
// Using OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING because we use manual PKCS#7 padding in AESCBC class
// Wait, AESCBC.php uses Padding::pad then openssl_encrypt with OPENSSL_ZERO_PADDING.
// So we should be able to decrypt it with openssl_decrypt.

$decryptedPadded = openssl_decrypt($ct, 'aes-256-cbc', $keyEnc, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
$decrypted = \Kelompok1\CryptoGraphy\Support\Padding::unpad($decryptedPadded);

echo "Manual Decrypted: $decrypted\n";
if ($decrypted === $plaintext) {
    echo "SUCCESS: Manual decryption matches plaintext.\n";
} else {
    echo "FAILED: Manual decryption failed.\n";
}

echo "\n--- 3. Simulate File Storage ---\n";
$storageDir = __DIR__ . '/storage/test/data/standard_test';
if (!is_dir($storageDir)) mkdir($storageDir, 0777, true);

$id = substr(hash('sha256', $ct), 0, 32);
$datPath = $storageDir . '/' . $id . '.dat';
file_put_contents($datPath, $ct);

echo "Saved raw ciphertext to: $datPath\n";
$loadedCt = file_get_contents($datPath);

if ($loadedCt === $ct) {
    echo "SUCCESS: .dat file contains identical raw ciphertext.\n";
} else {
    echo "FAILED: .dat file content mismatch.\n";
}

// Cleanup
@unlink($datPath);
@rmdir($storageDir);
