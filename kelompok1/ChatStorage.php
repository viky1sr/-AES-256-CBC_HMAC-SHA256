<?php

namespace Kelompok1\CryptoGraphy;

use Kelompok1\CryptoGraphy\Domain\ChatMessage;
use Kelompok1\CryptoGraphy\Serialization\JsonSerializer;

final class ChatStorage
{
    private string $filePath;
    private JsonSerializer $serializer;

    public function __construct(string $filePath = null)
    {
        $config = @include __DIR__ . '/../config/app.php';
        $defaultPath = __DIR__ . '/../data/chats.json';
        if (is_array($config) && isset($config['data_dir'])) {
            $defaultPath = $config['data_dir'] . '/chats.json';
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
     * @return array Array of encrypted tokens
     */
    public function getAllTokens(): array
    {
        if (!file_exists($this->filePath) || !is_readable($this->filePath)) {
            return [];
        }
        $content = @file_get_contents($this->filePath);
        if (!$content) return [];
        
        try {
            return $this->serializer->deserialize($content);
        } catch (\Exception $e) {
            return [];
        }
    }

    public function saveToken(string $token): void
    {
        $tokens = $this->getAllTokens();
        $tokens[] = $token;
        file_put_contents($this->filePath, $this->serializer->serialize($tokens));
    }
}
