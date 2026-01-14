<?php

require_once __DIR__ . '/vendor/autoload.php';

use Workerman\Worker;
use Workerman\Connection\TcpConnection;
use Workerman\Protocols\Http\Request;
use Workerman\Protocols\Http\Response;
use Kelompok1\CryptoGraphy\RegisterStorage;
use Kelompok1\CryptoGraphy\RegisterPage;
use Kelompok1\CryptoGraphy\Domain\User;
use Kelompok1\CryptoGraphy\Domain\ChatMessage;
use Kelompok1\CryptoGraphy\ChatStorage;
use Kelompok1\CryptoGraphy\Services\Keyring;
use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;
use Kelompok1\CryptoGraphy\Secure\SecureSerializer;
use Kelompok1\CryptoGraphy\Services\GlobalEntityCrypto;

use Kelompok1\CryptoGraphy\CryptoPassService;

// Setup Storage
$storage = new RegisterStorage();
$chatStorage = new ChatStorage();

// Setup Crypto
$config = @include __DIR__ . '/config/app.php';
$appSecret = \Kelompok1\CryptoGraphy\Crypto::getAppKey();
$keyring   = new Keyring($appSecret);
$secure    = new SecureSerializer(new JsonSerializer());
$gec       = new GlobalEntityCrypto($keyring, $secure);

$host = $config['server']['host'] ?? '0.0.0.0';
$port = $config['server']['port'] ?? 8080;

$worker = new Worker("http://$host:$port");
$worker->count = 1;

// Simple session in-memory for demo (Workerman is persistent)
$sessions = [];

$worker->onMessage = function (TcpConnection $connection, Request $request) use ($storage, $chatStorage, $gec, &$sessions) {
    $path = $request->path();
    $method = $request->method();
    $sid = $request->cookie('sid');
    $currentUser = $sid ? ($sessions[$sid] ?? null) : null;

    if ($path === '/' || $path === '/login') {
        if ($method === 'GET') {
            if ($currentUser) {
                // Redirect to dashboard if logged in
                $connection->send(new Response(302, ['Location' => '/dashboard']));
                return;
            }
            $connection->send(new Response(200, [], RegisterPage::loginForm()));
            return;
        }

        if ($method === 'POST') {
            $username = $request->post('username');
            $password = $request->post('password');

            $user = $storage->findByUsername($username);
            if ($user && password_verify($password, $user->password)) {
                $sid = bin2hex(random_bytes(16));
                $sessions[$sid] = $user;
                $response = new Response(302, ['Location' => '/dashboard']);
                $response->cookie('sid', $sid);
                $connection->send($response);
            } else {
                $connection->send(new Response(200, [], RegisterPage::loginForm('Username atau password salah!')));
            }
            return;
        }
    }

    if ($path === '/register') {
        if ($method === 'GET') {
            $connection->send(new Response(200, [], RegisterPage::registerForm()));
            return;
        }

        if ($method === 'POST') {
            $username = (string)$request->post('username');
            $password = (string)$request->post('password');

            if (!$username || !$password) {
                $connection->send(new Response(200, [], RegisterPage::registerForm('Username dan password wajib diisi!')));
                return;
            }

            try {
                $uuid = bin2hex(random_bytes(16));
                // Argon2id secara otomatis menggunakan salt unik per hash
                $hashedPassword = password_hash($password, PASSWORD_ARGON2ID);
                $user = new User($uuid, $username, $hashedPassword, date('c'));
                
                $storage->save($user);

                // Inisialisasi keystore untuk user baru jika dikonfigurasi
                $config = @include __DIR__ . '/config/app.php';
                if (is_array($config) && isset($config['keystore_dir'])) {
                    $userKeystorePath = $config['keystore_dir'] . '/' . $uuid . '.pass.json';
                    if (!file_exists($userKeystorePath)) {
                        try {
                            // Gunakan password user sebagai passphrase untuk keystore mereka
                            \Kelompok1\CryptoGraphy\Services\KeyStorePass::init($userKeystorePath, $password);
                        } catch (\Exception $e) {
                            // Log error jika gagal
                        }
                    }
                }

                $connection->send(new Response(200, [], RegisterPage::loginForm('Registrasi berhasil! Silakan login.')));
            } catch (\Exception $e) {
                $connection->send(new Response(200, [], RegisterPage::registerForm('Error: ' . $e->getMessage())));
            }
            return;
        }
    }

    if ($path === '/dashboard' || $path === '/api/chat') {
        if (!$currentUser) {
            if ($path === '/api/chat') {
                $connection->send(new Response(401, [], 'Unauthorized'));
            } else {
                $connection->send(new Response(302, ['Location' => '/login']));
            }
            return;
        }

        $viewPassword = $request->get('view_password');
        $allTokens = $chatStorage->getAllTokens();
        $chatHtml = "";
        
        // Dapatkan semua user untuk mapping UUID ke Username
        $allUsers = $storage->getAll();
        $userMap = [];
        foreach ($allUsers as $u) {
            $userMap[$u->uuid] = $u->username;
        }

        foreach ($allTokens as $token) {
            try {
                // Jika ada password dekripsi, gunakan CryptoPassService
                if ($viewPassword) {
                    try {
                        $decryptedJson = CryptoPassService::decryptWithPassphrase($token, $viewPassword);
                        $data = json_decode($decryptedJson, true);
                        if ($data && isset($data['userUuid'], $data['message'], $data['timestamp'])) {
                            $senderName = $userMap[$data['userUuid']] ?? 'Unknown';
                            $time = date('H:i', strtotime($data['timestamp']));
                            $chatHtml .= "<div>[{$time}] <strong>{$senderName}</strong>: " . htmlspecialchars($data['message']) . " <span style='color:green; font-size:0.8em;'>(Decrypted w/ Pass)</span></div>";
                            continue;
                        }
                    } catch (\Exception $e) {
                        // Gagal dekripsi dengan password, lanjut ke pengecekan berikutnya
                    }
                }

                // Cek apakah token ini adalah token GEC standar (App Key)
                // Kita coba decrypt dengan setiap user yang ada sebagai hint bind
                foreach ($userMap as $uuid => $name) {
                    try {
                        $chat = $gec->decrypt(ChatMessage::class, $token, ['userUuid' => $uuid]);
                        if ($chat instanceof ChatMessage) {
                            $time = date('H:i', strtotime($chat->timestamp));
                            $chatHtml .= "<div>[{$time}] <strong>{$name}</strong>: " . htmlspecialchars($chat->message) . " <span style='color:blue; font-size:0.8em;'>(App Key)</span></div>";
                            break; 
                        }
                    } catch (\Exception $e) {
                        continue;
                    }
                }
            } catch (\Exception $e) {
                continue;
            }
        }

        if (!$chatHtml) {
            $chatHtml = $viewPassword ? "<i>Tidak ada pesan yang bisa didekripsi dengan password tersebut.</i>" : "<i>Belum ada pesan atau masukkan password untuk melihat pesan rahasia.</i>";
        }

        if ($path === '/api/chat') {
            $connection->send(new Response(200, ['Content-Type' => 'text/html'], $chatHtml));
        } else {
            $connection->send(new Response(200, [], RegisterPage::welcome($currentUser->username, $chatHtml)));
        }
        return;
    }

    if ($path === '/chat' && $method === 'POST') {
        if (!$currentUser) {
            $connection->send(new Response(403, [], 'Unauthorized'));
            return;
        }

        $messageText = (string)$request->post('message');
        $chatPassword = (string)$request->post('chat_password');

        if ($messageText && $chatPassword) {
            $chatData = [
                'userUuid'  => $currentUser->uuid,
                'message'   => $messageText,
                'timestamp' => date('c')
            ];
            $json = json_encode($chatData);
            $token = CryptoPassService::encryptWithPassphrase($json, $chatPassword);
            $chatStorage->saveToken($token);
        }

        if ($request->header('X-Requested-With') === 'XMLHttpRequest' || $request->header('Accept') === 'application/json' || $request->post('message')) {
             // For AJAX request, just send success
             $connection->send(new Response(200, [], 'OK'));
        } else {
             $connection->send(new Response(302, ['Location' => '/dashboard']));
        }
        return;
    }

    if ($path === '/logout') {
        if ($sid) unset($sessions[$sid]);
        $response = new Response(302, ['Location' => '/login']);
        $response->cookie('sid', '', -1);
        $connection->send($response);
        return;
    }

    $connection->send(new Response(404, [], 'Halaman tidak ditemukan'));
};

Worker::runAll();
