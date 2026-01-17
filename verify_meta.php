<?php
require_once 'vendor/autoload.php';
use Kelompok1\CryptoGraphy\CryptoPassService;
use Kelompok1\CryptoGraphy\Services\FileSecureStorage;

$pass = 'password123';
$plaintext = 'Test metadata kdf preservation';
$token = CryptoPassService::encryptWithPassphrase($plaintext, $pass);

$tempDir = 'storage/test/meta_verify';
if (!is_dir($tempDir)) mkdir($tempDir, 0777, true);
$storage = new FileSecureStorage($tempDir);
$id = $storage->save($token);

$jsonFile = $tempDir . '/000/' . $id . '.json';
$data = json_decode(file_get_contents($jsonFile), true);

echo "Metadata Check:\n";
print_r($data['meta']['kdf']);

if (isset($data['meta']['kdf']['iter']) && 
    isset($data['meta']['kdf']['salt']) && 
    isset($data['meta']['kdf']['alg'])) {
    echo "SUCCESS: KDF Metadata preserved.\n";
} else {
    echo "FAILURE: KDF Metadata missing fields.\n";
}

$loadedToken = $storage->load($id);
$decrypted = CryptoPassService::decryptWithPassphrase($loadedToken, $pass);
echo "Decrypted: " . $decrypted . "\n";
