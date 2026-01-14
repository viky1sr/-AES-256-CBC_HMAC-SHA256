<?php

namespace Kelompok1\CryptoGraphy;

use Kelompok1\CryptoGraphy\Domain\User;
use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;

final class RegisterStorage
{
    private string $filePath;
    private JsonSerializer $serializer;

    public function __construct(string $filePath = null)
    {
        $config = @include __DIR__ . '/../config/app.php';
        $defaultPath = __DIR__ . '/../data/users.json';
        if (is_array($config) && isset($config['data_dir'])) {
            $defaultPath = $config['data_dir'] . '/users.json';
        }

        $this->filePath = $filePath ?? $defaultPath;
        $this->serializer = new JsonSerializer();
        
        $dir = dirname($this->filePath);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        if (!file_exists($this->filePath)) {
            @file_put_contents($this->filePath, json_encode([]));
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

        $users[] = $user;
        
        $data = [];
        foreach ($users as $u) {
            $data[] = $u->toArray();
        }

        file_put_contents($this->filePath, $this->serializer->serialize($data));
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
