<?php

use Kelompok1\CryptoGraphy\CryptoPassService;

require __DIR__.'/vendor/autoload.php';

$passphrase = 'rahasia-kelompok-1';
$plaintext = 'x';

$token = CryptoPassService::encryptWithPassphrase($plaintext, $passphrase);
echo "Token (PBKDF2): $token\n";

$plain = CryptoPassService::decryptWithPassphrase($token, $passphrase);
echo "Plain: $plain\n";
