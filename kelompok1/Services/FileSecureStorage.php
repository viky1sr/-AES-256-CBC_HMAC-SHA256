<?php

namespace Kelompok1\CryptoGraphy\Services;

use Kelompok1\CryptoGraphy\Support\Base64Url;
use Kelompok1\CryptoGraphy\Token\EtmToken;

/**
 * FileSecureStorage
 * ----------------
 * Layanan terpadu untuk menyimpan data terenkripsi ke dalam sistem file
 * dengan struktur folder terbagi (100 file per folder) dan identitas unik 16-byte.
 */
final class FileSecureStorage
{
    private string $baseDir;
    private string $indexFile;

    public function __construct(string $baseDir, string $indexFileName = 'index.json')
    {
        $this->baseDir = rtrim($baseDir, '/\\');
        $this->indexFile = $this->baseDir . '/' . $indexFileName;

        if (!is_dir($this->baseDir)) {
            @mkdir($this->baseDir, 0777, true);
        }
    }

    /**
     * Menyimpan token EtM ke dalam file JSON.
     * @param string $token Token base64(JSON {iv,value,mac,meta})
     * @return string ID unik (16-byte hex)
     */
    public function save(string $token): string
    {
        $unpacked = EtmToken::unpack($token);
        
        // _id adalah 16 byte hasil hash ciphertext (32 char hex)
        $id = substr(hash('sha256', $unpacked['value']), 0, 32);
        
        $indexData = $this->loadIndex();
        if (!in_array($id, $indexData)) {
            $indexData[] = $id;
            $this->saveIndex($indexData);
        }

        $folder = $this->getFolderName($id, $indexData);
        $dir = $this->baseDir . '/' . $folder;
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }

        $payload = [
            '_id' => $id,
            'iv' => Base64Url::encode($unpacked['iv']),
            'mac' => Base64Url::encode($unpacked['mac']),
            'value' => Base64Url::encode($id), // Value sekarang hanya ID 16-byte
            'meta' => $unpacked['meta'] ?? null
        ];

        file_put_contents($dir . '/' . $id . '.json', json_encode($payload, JSON_PRETTY_PRINT));
        
        // Simpan ciphertext asli di file terpisah
        file_put_contents($dir . '/' . $id . '.dat', $unpacked['value']);
        
        return $id;
    }

    /**
     * Memuat token EtM berdasarkan ID.
     */
    public function load(string $id): ?string
    {
        $indexData = $this->loadIndex();
        $folder = $this->getFolderName($id, $indexData);
        $basePath = $this->baseDir . '/' . $folder . '/' . $id;
        $jsonPath = $basePath . '.json';
        $datPath = $basePath . '.dat';
        
        if (!file_exists($jsonPath) || !file_exists($datPath)) {
            return null;
        }
        
        $data = json_decode(file_get_contents($jsonPath), true);
        if (!$data || !isset($data['iv'], $data['mac'])) {
            return null;
        }

        $ciphertext = file_get_contents($datPath);
        
        return EtmToken::pack(
            Base64Url::decode($data['iv']),
            $ciphertext,
            Base64Url::decode($data['mac']),
            $data['meta'] ?? null
        );
    }

    /**
     * Menghapus data berdasarkan ID.
     */
    public function delete(string $id): bool
    {
        $indexData = $this->loadIndex();
        $pos = array_search($id, $indexData);
        if ($pos === false) return false;

        $folder = $this->getFolderName($id, $indexData);
        $basePath = $this->baseDir . '/' . $folder . '/' . $id;
        
        if (file_exists($basePath . '.json')) {
            @unlink($basePath . '.json');
        }
        if (file_exists($basePath . '.dat')) {
            @unlink($basePath . '.dat');
        }

        unset($indexData[$pos]);
        $this->saveIndex(array_values($indexData));
        return true;
    }

    /**
     * Mengambil semua ID yang tersimpan.
     */
    public function getAllIds(): array
    {
        return $this->loadIndex();
    }

    private function loadIndex(): array
    {
        if (!file_exists($this->indexFile)) {
            return [];
        }
        $content = @file_get_contents($this->indexFile);
        return json_decode($content ?: '[]', true) ?: [];
    }

    private function saveIndex(array $index): void
    {
        file_put_contents($this->indexFile, json_encode($index));
    }

    private function getFolderName(string $id, array $indexData): string
    {
        $pos = array_search($id, $indexData);
        if ($pos === false) {
            $pos = count($indexData);
        }
        
        $folderNum = floor($pos / 100);
        return sprintf("%03d", $folderNum);
    }
}
