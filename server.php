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
$workerNum = $config['server']['worker_num'] ?? 4;

$worker = new Worker("http://$host:$port");
$worker->count = $workerNum;

// Simple session in-memory for demo (Workerman is persistent)
$sessions = [];

// Helper to get consistent color for username
function getUsernameColor($username) {
    $hash = md5($username);
    // Use the first 6 chars of md5 to get a hex color
    // but we want colors that are not too light (visible on white)
    // so we limit the range
    $r = hexdec(substr($hash, 0, 2)) % 200;
    $g = hexdec(substr($hash, 2, 2)) % 200;
    $b = hexdec(substr($hash, 4, 2)) % 200;
    return sprintf("#%02x%02x%02x", $r, $g, $b);
}

$worker->onMessage = function (TcpConnection $connection, Request $request) use ($storage, $chatStorage, $gec, &$sessions) {
    $path = $request->path();
    $method = $request->method();
    $sid = $request->cookie('sid');
    $currentSession = $sid ? ($sessions[$sid] ?? null) : null;
    $currentUser = $currentSession['user'] ?? null;

    // Bersihkan sesi yang sudah mati (1 jam / 3600 detik)
    if (rand(1, 100) === 1) { // 1% chance
        $now = time();
        foreach ($sessions as $key => $s) {
            // Hanya hapus jika sudah benar-benar lewat 1 jam dari aktivitas terakhir
            if ($now - ($s['last_seen'] ?? 0) > 3600) {
                unset($sessions[$key]);
            }
        }
    }

    // Tambahkan timestamp aktivitas untuk cek online dan menjaga sesi tetap hidup
    if ($sid && isset($sessions[$sid])) {
        $sessions[$sid]['last_seen'] = time();
    }

    if ($path === '/database') {
        $dirs = [
            __DIR__ . '/storage/data',
            __DIR__ . '/storage/config/keystore/usernames'
        ];
        
        $filesData = [];
        foreach ($dirs as $dataDir) {
            if (!is_dir($dataDir)) continue;

            $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dataDir));
            foreach ($iterator as $file) {
                if ($file->isFile()) {
                    $ext = $file->getExtension();
                    if (in_array($ext, ['json', 'dat'])) {
                        $fullPath = $file->getRealPath();
                        $relativePath = str_replace(__DIR__ . DIRECTORY_SEPARATOR, '', $fullPath);
                        $content = file_get_contents($fullPath);
                        
                        // Perbaikan: Jika users.json, pastikan terformat rapi jika itu JSON array
                        if ($file->getFilename() === 'users.json' || $file->getFilename() === 'chats_index.json') {
                            $decoded = json_decode($content, true);
                            if (is_array($decoded)) {
                                $content = json_encode($decoded, JSON_PRETTY_PRINT);
                            }
                        }

                        $filesData[] = [
                            'path' => $relativePath,
                            'name' => $file->getFilename(),
                            'type' => $ext,
                            'content' => $content,
                            'size' => $file->getSize()
                        ];
                    }
                }
            }
        }

        // Urutkan berdasarkan path agar rapi
        usort($filesData, fn($a, $b) => strcmp($a['path'], $b['path']));

        $connection->send(new Response(200, [], RegisterPage::databaseView($filesData)));
        return;
    }

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
                $now = time();
                $sessions[$sid] = [
                    'user' => $user,
                    'last_seen' => $now
                ];
                $response = new Response(302, ['Location' => '/dashboard']);
                // Cookie sid berlaku 1 jam (3600 detik). 
                // Set path ke '/' agar terbaca di semua endpoint.
                $response->cookie('sid', $sid, $now + 3600, '/');
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
        $viewToken = $request->get('view_token');
        // Dapatkan semua user untuk mapping UUID ke Username
        $allUsers = $storage->getAll();
        $userMap = [];
        foreach ($allUsers as $u) {
            $userMap[$u->uuid] = $u->username;
        }

        $allTokens = $chatStorage->getAllTokens();
        $chatHtml = "";
        
        $hasTokens = !empty($allTokens);
        foreach ($allTokens as $token) {
            try {
                // Bersihkan token dari whitespace/newline jika ada
                $token = trim((string)$token);
                if (empty($token)) continue;

                $decryptedText = null;
                $decryptionType = "";

                // 1. Coba dekripsi dengan viewPassword (jika ada)
                // HANYA jika token ini yang sedang diminta (view_token) ATAU jika tidak ada spesifik token
                if ($viewPassword && (!$viewToken || $viewToken === $token)) {
                    try {
                        $decryptedJson = CryptoPassService::decryptWithPassphrase($token, $viewPassword);
                        $data = json_decode($decryptedJson, true);
                        if ($data && isset($data['message'])) {
                            $senderUuid = $data['userUuid'] ?? 'Unknown';
                            $targetUuid = $data['targetUuid'] ?? null;

                            // Filter Privasi untuk Password-based encryption
                            if ($targetUuid !== null && $targetUuid !== $currentUser->uuid && $senderUuid !== $currentUser->uuid) {
                                continue; // Lewati pesan ini jika bukan untuk saya dan saya bukan pengirimnya
                            }

                            $decryptedText = $data['message'];
                            $senderName = $userMap[$senderUuid] ?? 'Unknown';
                            $timeStr = $data['timestamp'] ?? date('c');
                            $decryptionType = ($targetUuid !== null) ? "Private" : "Decrypted";
                        }
                    } catch (\Exception $e) {}
                }

                // 2. Coba dekripsi dengan App Key (GEC) jika belum berhasil
                if ($decryptedText === null) {
                    foreach ($userMap as $uuid => $name) {
                        try {
                            $chat = $gec->decrypt(ChatMessage::class, $token, ['userUuid' => $uuid]);
                            if ($chat instanceof ChatMessage) {
                                // Filter Privasi: Hanya tampilkan jika publik (targetUuid null) 
                                // ATAU jika dikirim ke saya (targetUuid == currentUser->uuid)
                                // ATAU jika saya pengirimnya (uuid == currentUser->uuid)
                                if ($chat->targetUuid !== null && $chat->targetUuid !== $currentUser->uuid && $chat->userUuid !== $currentUser->uuid) {
                                    continue 2; 
                                }

                                $decryptedText = $chat->message;
                                $senderUuid = $chat->userUuid; // Pastikan menggunakan UUID dari entitas
                                $senderName = $userMap[$senderUuid] ?? 'Unknown';
                                $timeStr = $chat->timestamp;
                                $decryptionType = ($chat->targetUuid !== null) ? "Private" : "App Key";
                                break; 
                            }
                        } catch (\Exception $e) {
                            continue;
                        }
                    }
                }

                // 3. Jika masih belum terdekripsi (atau memang sengaja dikunci password), 
                // kita harus memastikan pesan terenkripsi ini memang ditujukan untuk user ini (atau publik)
                if ($decryptedText === null) {
                    // Cek metadata 'targetUuid' di level token jika tersedia
                    try {
                        $unpacked = \Kelompok1\CryptoGraphy\Token\EtmToken::unpack($token);
                        $meta = $unpacked['meta'] ?? [];
                        $tUuid = $meta['targetUuid'] ?? null;
                        $sUuid = $meta['userUuid'] ?? null;

                        // Jika pesan memiliki target dan saya bukan targetnya serta bukan pengirimnya, sembunyikan total
                        if ($tUuid !== null && $tUuid !== $currentUser->uuid && $sUuid !== $currentUser->uuid) {
                             continue;
                        }
                    } catch (\Exception $e) {}
                }

                if ($decryptedText !== null) {
                    $time = date('H:i', strtotime($timeStr));
                    $color = ($decryptionType === "App Key") ? "#007bff" : (($decryptionType === "Private") ? "#6f42c1" : "#28a745");
                    $label = ($decryptionType === "Private") ? " (Private)" : " ({$decryptionType})";
                    $nameColor = getUsernameColor($senderName);
                    
                    $msgStyle = ($decryptionType === "Private") ? "background: #f3e5f5; border-left: 4px solid #6f42c1; padding-left: 8px;" : "";
                    
                    $chatHtml .= "<div class='msg-entry' style='{$msgStyle}'>[{$time}] <strong style='color:{$nameColor}'>{$senderName}</strong>: " . htmlspecialchars($decryptedText) . " <span style='color:{$color}; font-size:0.8em; font-weight: bold;'>{$label}</span></div>";
                } else {
                     // Jika tidak bisa didekripsi, tampilkan tombol klik
                     // Menampilkan 'Value Pointer' dari metadata token
                     $id = substr(hash('sha256', \Kelompok1\CryptoGraphy\Token\EtmToken::unpack($token)['value']), 0, 32);
                     $isSelected = ($viewToken === $token) ? "border: 1px solid #007bff; background: #e7f3ff;" : "";
                     $chatHtml .= "<div class='msg-entry' style='{$isSelected}'><span class='encrypted-msg' data-token='".htmlspecialchars($token)."' onclick='if(typeof openDecryptModal === \"function\") openDecryptModal(\"".addslashes($token)."\")'>🔒 ".htmlspecialchars($id)."</span></div>";
                }
            } catch (\Exception $e) {
                continue;
            }
        }

        if (!$chatHtml) {
            if (!$hasTokens) {
                $chatHtml = "<i>Belum ada pesan di forum ini.</i>";
            } else {
                $chatHtml = "<i>Tidak ada pesan yang bisa didekripsi. Masukkan password yang benar.</i>";
            }
        }

        if ($path === '/api/chat') {
            $connection->send(new Response(200, ['Content-Type' => 'text/html'], $chatHtml));
        } else {
            $connection->send(new Response(200, [], RegisterPage::welcome($currentUser->username, $chatHtml)));
        }
        return;
    }

    if ($path === '/api/users') {
        if (!$currentUser) {
            $connection->send(new Response(401, [], 'Unauthorized'));
            return;
        }
        $onlineUsers = []; // Array of ['uuid' => '...', 'name' => '...']
        $now = time();
        foreach ($sessions as $s) {
            $lastSeen = $s['last_seen'] ?? 0;
            $diff = $now - $lastSeen;
            // Anggap online jika ada aktivitas dalam 2 menit terakhir (120 detik)
            if (isset($s['user']) && $diff < 120) { 
                $onlineUsers[$s['user']->uuid] = (string)$s['user']->username;
            }
        }
        
        if ($request->get('format') === 'json') {
            $connection->send(new Response(200, ['Content-Type' => 'application/json'], json_encode($onlineUsers)));
            return;
        }

        if (empty($onlineUsers)) {
            $html = "<i>Tidak ada user online</i>";
        } else {
            $html = "<ul>";
            foreach ($onlineUsers as $uuid => $name) {
                $status = ($uuid === $currentUser->uuid) ? " (Anda)" : "";
                $nameColor = getUsernameColor($name);
                $html .= "<li><span style='color: green;'>●</span> <strong style='color:{$nameColor}'>" . htmlspecialchars($name) . "</strong>" . $status . "</li>";
            }
            $html .= "</ul>";
        }
        $connection->send(new Response(200, ['Content-Type' => 'text/html'], $html));
        return;
    }

    if ($path === '/chat' && $method === 'POST') {
        if (!$currentUser) {
            $connection->send(new Response(403, [], 'Unauthorized'));
            return;
        }

        $messageText = (string)$request->post('message');
        $chatPassword = (string)$request->post('chat_password');
        $targetUuid = $request->post('target_uuid');
        if ($targetUuid === 'all' || empty($targetUuid)) {
            $targetUuid = null;
        }

        if ($messageText) {
            $meta = [
                'userUuid' => (string)$currentUser->uuid,
                'targetUuid' => $targetUuid ? (string)$targetUuid : null
            ];

            if ($chatPassword) {
                // Enkripsi Berbasis Password
                $chatData = [
                    'userUuid'  => $currentUser->uuid,
                    'message'   => $messageText,
                    'timestamp' => date('c'),
                    'targetUuid' => $targetUuid
                ];
                $json = json_encode($chatData);
                $token = CryptoPassService::encryptWithPassphrase($json, $chatPassword, meta: $meta);
                $chatStorage->saveToken($token);
            } else {
                // Enkripsi Berbasis App Key (GEC)
                $chat = new ChatMessage($currentUser->uuid, $messageText, date('c'), $targetUuid);
                $token = $gec->encrypt($chat, meta: $meta);
                $chatStorage->saveToken($token);
            }
        }

        if ($request->header('X-Requested-With') === 'XMLHttpRequest' || $request->header('Accept') === 'application/json' || $request->post('_ajax')) {
             // For AJAX request, just send success
             $connection->send(new Response(200, [], 'OK'));
        } else {
             $connection->send(new Response(302, ['Location' => '/dashboard']));
        }
        return;
    }

    if ($path === '/logout') {
        if ($sid) {
            // Berikan status offline sebelum hapus sesi
            if (isset($sessions[$sid])) {
                $sessions[$sid]['last_seen'] = 0; 
            }
            unset($sessions[$sid]);
        }
        $response = new Response(302, ['Location' => '/login']);
        $response->cookie('sid', '', -1);
        $connection->send($response);
        return;
    }

    $connection->send(new Response(404, [], 'Halaman tidak ditemukan'));
};

Worker::runAll();
