<?php

namespace Kelompok1\CryptoGraphy;

use Kelompok1\CryptoGraphy\Domain\ChatMessage;
use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;
use Kelompok1\CryptoGraphy\Services\FileSecureStorage;

final class ChatStorage
{
    private string $dataDir;
    private FileSecureStorage $secureStorage;
    private JsonSerializer $serializer;

    public function __construct(string $dataDir = null)
    {
        $config = @include __DIR__ . '/../config/app.php';
        $defaultDataDir = __DIR__ . '/../data';
        
        if (is_array($config) && isset($config['data_dir'])) {
            $defaultDataDir = $config['data_dir'];
        }

        $this->dataDir = $dataDir ?? $defaultDataDir;
        $this->serializer = new JsonSerializer();
        
        // Unified Secure Storage for Chats
        $this->secureStorage = new FileSecureStorage($this->dataDir . '/chats', 'chats_index.json');
    }

    /**
     * @return array Array of encrypted tokens
     */
    public function getAllTokens(): array
    {
        $tokens = [];
        $ids = $this->secureStorage->getAllIds();
        
        foreach ($ids as $id) {
            $token = $this->secureStorage->load($id);
            if ($token) {
                $tokens[] = $token;
            }
        }
        
        return $tokens;
    }

    public function loadTokenById(string $id): ?string
    {
        return $this->secureStorage->load($id);
    }

    public function saveToken(string $token): string
    {
        return $this->secureStorage->save($token);
    }
}
