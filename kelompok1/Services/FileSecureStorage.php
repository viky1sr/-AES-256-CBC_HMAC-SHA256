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
     * Menghasilkan Iter Code (itc) acak seperti pola dadu (1-6 unik).
     */
    public function getRandomItc(int $count = 6): array
    {
        $numbers = range(1, 6);
        shuffle($numbers);
        return $numbers;
    }

    /**
     * Menghasilkan ID 16-byte (32 char hex) dengan pola shuffle dan chunking.
     */
    private function generateId(string $ciphertext, array $itc): array
    {
        $hash = hash('sha256', $ciphertext);
        
        $chunks = [];
        $offset = 0;
        foreach ($itc as $len) {
            // Pastikan offset tidak melebihi panjang hash
            if ($offset >= strlen($hash)) break;
            $chunks[] = substr($hash, $offset, $len);
            $offset += $len;
        }

        // Shuffling berdasarkan pola dadu
        $shuffled = implode('', $chunks);
        
        // Permintaan: "pola ganjil ambil dari string first, dan genap ambil dari string end"
        $res = '';
        $left = 0;
        $right = strlen($hash) - 1;
        for ($i = 0; $i < 32; $i++) {
            if ($i % 2 === 0) { 
                $res .= $hash[$left++];
            } else {
                $res .= $hash[$right--];
            }
        }

        return [
            'id' => $res,
            'itc' => implode(',', $itc),
            'pct' => implode('', $itc) // pct sekarang 6 digit sesuai itc
        ];
    }

    /**
     * Menyimpan token EtM ke dalam file JSON.
     * @param string $token Token base64(JSON {iv,value,mac,meta})
     * @return string ID unik (16-byte hex)
     */
    public function save(string $token): string
    {
        $unpacked = EtmToken::unpack($token);
        
        // Gunakan itc acak dinamis
        $itc = $this->getRandomItc();
        $gen = $this->generateId($unpacked['value'], $itc);
        $id = $gen['id'];
        
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

        // Simpan ciphertext asli di file terpisah dengan mekanisme chunking & marking
        $datPath = $dir . '/' . $id . '.dat';
        $fp = fopen($datPath, 'wb');
        
        $ciphertext = $unpacked['value'];
        $totalLen = strlen($ciphertext);
        $chunkSize = (int)ceil($totalLen / 6);
        $offsets = [];

        // Bagi menjadi 6 chunk sesuai itc
        for ($i = 0; $i < 6; $i++) {
            // Tulis "Dice Marker" (hex value dari itc[$i])
            fwrite($fp, chr($itc[$i]));
            
            // Catat offset ciphertext (posisi setelah marker)
            $offsets[] = ftell($fp);
            
            // Tulis chunk ciphertext
            $start = $i * $chunkSize;
            $chunk = substr($ciphertext, $start, $chunkSize);
            if ($chunk !== false) {
                fwrite($fp, $chunk);
            }
        }
        fclose($fp);

        // Konversi itc dan offsets ke hexadecimal untuk metadata
        $itcHex = array_map(fn($v) => dechex($v), $itc);
        $offsetsHex = array_map(fn($v) => dechex($v), $offsets);

        $payload = [
            '_id' => $id,
            'pct' => implode(',', $offsetsHex), // Daftar offset byte pointer dalam format HEX
            'itc' => implode(',', $itcHex),     // Daftar dadu marker dalam format HEX
            'iv' => Base64Url::encode($unpacked['iv']),
            'mac' => Base64Url::encode($unpacked['mac']),
            'value' => Base64Url::encode($id),
            'meta' => $unpacked['meta'] ?? null 
        ];

        file_put_contents($dir . '/' . $id . '.json', json_encode($payload, JSON_PRETTY_PRINT));
        
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
        if (!$data || !isset($data['iv'], $data['mac'], $data['value'], $data['pct'], $data['itc'])) {
            return null;
        }

        // Verifikasi bahwa value di JSON sesuai dengan ID yang diminta (sebagai pointer)
        $pointer = Base64Url::decode($data['value']);
        if ($pointer !== $id) {
            return null;
        }

        $datPath = $this->baseDir . '/' . $folder . '/' . $pointer . '.dat';
        if (!file_exists($datPath)) {
            return null;
        }

        // Ambil daftar offset dan itc
        $offsets = array_map('hexdec', explode(',', $data['pct']));
        $itcValues = array_map('hexdec', explode(',', $data['itc']));
        
        $fp = fopen($datPath, 'rb');
        $fullCiphertext = "";
        
        // Baca ukuran file untuk mengetahui batas pembacaan chunk terakhir
        $stats = fstat($fp);
        $totalSize = $stats['size'];

        for ($i = 0; $i < count($offsets); $i++) {
            $offset = (int)$offsets[$i];
            
            // Verifikasi Marker sebelum offset
            fseek($fp, $offset - 1);
            $markerBytes = fread($fp, 1);
            if ($markerBytes === false || strlen($markerBytes) === 0) {
                fclose($fp);
                return null;
            }
            $marker = ord($markerBytes);
            if ($marker !== (int)$itcValues[$i]) {
                fclose($fp);
                return null; // Marker tampered atau mismatch
            }

            // Tentukan panjang chunk
            // Jika bukan chunk terakhir, panjangnya adalah selisih offset berikutnya - 1 (marker berikutnya) - offset saat ini
            if (isset($offsets[$i+1])) {
                $len = ((int)$offsets[$i+1] - 1) - $offset;
            } else {
                $len = $totalSize - $offset;
            }

            if ($len > 0) {
                fseek($fp, $offset);
                $fullCiphertext .= fread($fp, $len);
            }
        }
        fclose($fp);
        
        return EtmToken::pack(
            Base64Url::decode($data['iv']),
            $fullCiphertext,
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
        $dir = dirname($this->indexFile);
        if (!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        file_put_contents($this->indexFile, json_encode($index), LOCK_EX);
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
