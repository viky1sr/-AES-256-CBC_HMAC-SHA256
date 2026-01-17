<?php

namespace Kelompok1\CryptoGraphy;

use Kelompok1\CryptoGraphy\Domain\User;
use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;
use Kelompok1\CryptoGraphy\Services\FileSecureStorage;

final class RegisterStorage
{
    private string $filePath;
    private string $keystoreDir;
    private JsonSerializer $serializer;
    private FileSecureStorage $usernameStorage;

    public function __construct(string $filePath = null, string $keystoreDir = null)
    {
        $config = @include __DIR__ . '/../config/app.php';
        $defaultPath = __DIR__ . '/../data/users.json';
        $defaultKeystore = __DIR__ . '/../config/keystore';
        
        if (is_array($config)) {
            if (isset($config['data_dir'])) {
                $defaultPath = $config['data_dir'] . '/users.json';
            }
            if (isset($config['keystore_dir'])) {
                $defaultKeystore = $config['keystore_dir'];
            }
        }

        $this->filePath = $filePath ?? $defaultPath;
        $this->keystoreDir = $keystoreDir ?? $defaultKeystore;
        $this->serializer = new JsonSerializer();
        
        // Unified Username Storage
        $this->usernameStorage = new FileSecureStorage($this->keystoreDir . '/usernames', 'usernames_index.json');

        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        if (!file_exists($this->filePath)) {
            @file_put_contents($this->filePath, json_encode([]));
        }
    }

    private function getMasterKey(): string
    {
        return \Kelompok1\CryptoGraphy\Crypto::getAppKey();
    }

    private function encryptUsername(string $username): string
    {
        $masterKey = $this->getMasterKey();
        $keyEnc = \Kelompok1\CryptoGraphy\KDF\HKDF::derive($masterKey, 32, info: 'user:username:enc');
        $keyMac = \Kelompok1\CryptoGraphy\KDF\HKDF::derive($masterKey, 32, info: 'user:username:mac');

        $token = \Kelompok1\CryptoGraphy\CryptoService::encrypt($username, $masterKey, [
            'purpose' => 'user:username'
        ]);

        $id = $this->usernameStorage->save($token);
        
        return $id . '.user.json';
    }

    private function decryptUsername(string $filename): ?string
    {
        $id = str_replace('.user.json', '', $filename);
        $token = $this->usernameStorage->load($id);
        
        if (!$token) return null;

        try {
            return \Kelompok1\CryptoGraphy\CryptoService::decrypt($token, $this->getMasterKey());
        } catch (\Exception $e) {
            return null;
        }
    }

    /**
     * @return User[]
     */
    public function getAll(): array
    {
        if (!file_exists($this->filePath) || !is_readable($this->filePath)) {
            return [];
        }
        $content = @file_get_contents($this->filePath);
        if (!$content) return [];
        
        $data = $this->serializer->deserialize($content);
        $users = [];
        foreach ($data as $userData) {
            // Decrypt username jika berupa filename keystore
            if (isset($userData['username']) && str_ends_with($userData['username'], '.user.json')) {
                $decrypted = $this->decryptUsername($userData['username']);
                if ($decrypted) {
                    $userData['username'] = $decrypted;
                }
            }
            $users[] = User::fromArray($userData);
        }
        return $users;
    }

    public function save(User $user): void
    {
        $users = $this->getAll();
        
        // Cek jika username sudah ada
        foreach ($users as $existingUser) {
            if ($existingUser->username === $user->username) {
                throw new \RuntimeException("Username sudah terdaftar");
            }
        }

        // Encrypt username sebelum simpan
        $encryptedUsername = $this->encryptUsername($user->username);
        
        // Buat clone user dengan username terenkripsi untuk disimpan
        $storedUser = new User($user->uuid, $encryptedUsername, $user->password, $user->timestamp);
        
        // Ambil data mentah yang tersimpan (untuk menjaga format asli jika ada user lama yang belum terenkripsi)
        $rawContent = @file_get_contents($this->filePath);
        $allData = $rawContent ? $this->serializer->deserialize($rawContent) : [];
        $allData[] = $storedUser->toArray();

        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        file_put_contents($this->filePath, $this->serializer->serialize($allData), LOCK_EX);
    }

    public function findByUsername(string $username): ?User
    {
        $users = $this->getAll();
        foreach ($users as $user) {
            if ($user->username === $username) {
                return $user;
            }
        }
        return null;
    }
}
