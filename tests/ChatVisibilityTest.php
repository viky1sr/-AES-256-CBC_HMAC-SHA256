<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Tests;

use Kelompok1\CryptoGraphy\ChatStorage;
use Kelompok1\CryptoGraphy\CryptoService;
use Kelompok1\CryptoGraphy\Domain\ChatMessage;
use Kelompok1\CryptoGraphy\Services\Keyring;
use Kelompok1\CryptoGraphy\Secure\SecureSerializer;
use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;
use Kelompok1\CryptoGraphy\Services\GlobalEntityCrypto;

class ChatVisibilityTest
{
    private string $testDataDir;
    private ChatStorage $storage;
    private GlobalEntityCrypto $gec;
    private string $userA = 'uuid-user-a';
    private string $userB = 'uuid-user-b';
    private string $userC = 'uuid-user-c';

    public function __construct()
    {
        $this->testDataDir = __DIR__ . '/../storage/test/data/chat_test';
        if (!is_dir($this->testDataDir)) {
            mkdir($this->testDataDir, 0777, true);
        }
        
        // Ensure index for tests is in a consistent place
        $this->storage = new ChatStorage($this->testDataDir);

        $appSecret = str_repeat('s', 32);
        $keyring = new Keyring($appSecret);
        $secure = new SecureSerializer(new JsonSerializer());
        $this->gec = new GlobalEntityCrypto($keyring, $secure);
    }

    public function run(): array
    {
        $results = [];
        $results[] = $this->testPublicChatVisibility();
        $results[] = $this->testPrivateChatVisibility();
        
        // $this->cleanup();
        return $results;
    }

    private function testPublicChatVisibility(): array
    {
        $name = "Public Chat Visibility Test";
        try {
            // User A kirim pesan publik
            $msg = new ChatMessage($this->userA, "Halo semua!", date('c'), null);
            $token = $this->gec->encrypt($msg, meta: ['userUuid' => $this->userA, 'targetUuid' => null]);
            $this->storage->saveToken($token);

            // Verifikasi manual (simulasi logika di server.php)
            $unpacked = \Kelompok1\CryptoGraphy\Token\EtmToken::unpack($token);
            $meta = $unpacked['meta'] ?? [];
            
            $visibleForB = ($meta['targetUuid'] === null);
            $visibleForC = ($meta['targetUuid'] === null);

            if ($visibleForB && $visibleForC) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'Pesan publik terlihat oleh semua user (melalui metadata token).'];
            }
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'Pesan publik tidak terlihat oleh user lain.'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function testPrivateChatVisibility(): array
    {
        $name = "Private Chat Visibility Test";
        try {
            // User A kirim pesan privat ke User B
            $msg = new ChatMessage($this->userA, "Halo B, ini rahasia!", date('c'), $this->userB);
            $token = $this->gec->encrypt($msg, meta: ['userUuid' => $this->userA, 'targetUuid' => $this->userB]);
            $this->storage->saveToken($token);

            // Simulasi pengecekan di server.php untuk User B (Penerima)
            $unpacked = \Kelompok1\CryptoGraphy\Token\EtmToken::unpack($token);
            $meta = $unpacked['meta'] ?? [];
            
            $visibleForB = ($meta['targetUuid'] === $this->userB || $meta['userUuid'] === $this->userB);
            $visibleForC = ($meta['targetUuid'] === $this->userC || $meta['userUuid'] === $this->userC);

            if ($visibleForB && !$visibleForC) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'Pesan privat hanya terlihat oleh pengirim dan penerima yang sah.'];
            }
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'Kegagalan isolasi pesan privat (B: ' . ($visibleForB?'Tampak':'Sembunyi') . ', C: ' . ($visibleForC?'Tampak':'Sembunyi') . ')'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function cleanup()
    {
        if (is_dir($this->testDataDir)) {
            $this->recursiveRmdir($this->testDataDir);
        }
    }

    private function recursiveRmdir($dir) {
        $files = array_diff(scandir($dir), array('.','..'));
        foreach ($files as $file) {
            (is_dir("$dir/$file")) ? $this->recursiveRmdir("$dir/$file") : unlink("$dir/$file");
        }
        return rmdir($dir);
    }
}
