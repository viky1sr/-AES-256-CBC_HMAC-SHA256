<?php

require_once __DIR__ . '/vendor/autoload.php';

use Kelompok1\CryptoGraphy\Services\Keyring;
use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;
use Kelompok1\CryptoGraphy\Secure\SecureSerializer;
use Kelompok1\CryptoGraphy\Services\GlobalEntityCrypto;

use Kelompok1\CryptoGraphy\Domain\User;
use Kelompok1\CryptoGraphy\Domain\ChatMessage;

$appSecret = hash('sha256', 'APP_SECRET_DEMO', true); // 32B biner
$keyring   = new Keyring($appSecret);
$secure    = new SecureSerializer(new JsonSerializer());
$gecAuto   = new GlobalEntityCrypto($keyring, $secure);

// --- Encrypt
$user = new User('USER-UUID-0001', 'viky', '$argon2id$hash...', date('c'));
$chat = new ChatMessage($user->uuid, 'Halo rahasia 👋', date('c'));

$userToken = $gecAuto->encrypt($user, ttlSec: 3600);
$chatToken = $gecAuto->encrypt($chat, ttlSec: 600);

// --- Decrypt (cukup beri bind, tanpa register mapper!)
$user2 = $gecAuto->decrypt(User::class, $userToken, ['uuid' => $user->uuid]);
$chat2 = $gecAuto->decrypt(ChatMessage::class, $chatToken, ['userUuid' => $user->uuid]);

var_dump($userToken, $chatToken);
echo PHP_EOL;
var_dump($user2, $chat2);

