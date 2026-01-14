<?php

namespace Kelompok1\CryptoGraphy\Tests;

require_once __DIR__ . '/../vendor/autoload.php';

use Kelompok1\CryptoGraphy\Services\FileSecureStorage;
use Kelompok1\CryptoGraphy\CryptoService;
use Kelompok1\CryptoGraphy\Token\EtmToken;
use Kelompok1\CryptoGraphy\Support\Base64Url;

class AntiTamperTest
{
    private string $testDataDir;
    private FileSecureStorage $storage;
    private string $masterKey;

    public function __construct()
    {
        $this->testDataDir = __DIR__ . '/../storage/test/data/tamper_test';
        if (!is_dir($this->testDataDir)) {
            mkdir($this->testDataDir, 0777, true);
        }
        $this->storage = new FileSecureStorage($this->testDataDir, 'tamper_index.json');
        $this->masterKey = str_repeat('k', 32); // 32 bytes key
    }

    public function run(): array
    {
        $results = [];
        $results[] = $this->testPositiveStorage();
        $results[] = $this->testNegativeTamperId();
        $results[] = $this->testNegativeTamperFileContent();
        $results[] = $this->testNegativeTamperMAC();
        
        // $this->cleanup(); // Biarkan data tetap ada untuk inspeksi
        return $results;
    }

    private function testPositiveStorage(): array
    {
        $name = "Positive Storage Test";
        try {
            $plaintext = "Pesan Rahasia Banget";
            $token = CryptoService::encrypt($plaintext, $this->masterKey);
            $id = $this->storage->save($token);
            
            $loadedToken = $this->storage->load($id);
            $decrypted = CryptoService::decrypt($loadedToken, $this->masterKey);
            
            if ($decrypted === $plaintext) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'Data disimpan dan dimuat dengan benar.'];
            }
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'Data dekripsi tidak cocok.'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function testNegativeTamperId(): array
    {
        $name = "Negative Tamper ID Test";
        try {
            $plaintext = "Pesan Jangan Di-Tamper";
            $token = CryptoService::encrypt($plaintext, $this->masterKey);
            $id = $this->storage->save($token);
            
            // Coba load dengan ID yang salah satu karakternya diganti
            $tamperedId = $id;
            $tamperedId[0] = ($tamperedId[0] === 'a') ? 'b' : 'a';
            
            $loadedToken = $this->storage->load($tamperedId);
            
            if ($loadedToken === null) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'Sistem menolak ID yang dimodifikasi (tidak ditemukan).'];
            }
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'Sistem mengembalikan data untuk ID yang salah!'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function testNegativeTamperFileContent(): array
    {
        $name = "Negative Tamper File Content Test";
        try {
            $plaintext = "Integritas Penting";
            $token = CryptoService::encrypt($plaintext, $this->masterKey);
            $id = $this->storage->save($token);
            
            // Temukan file payload asli di disk (.dat)
            $index = json_decode(file_get_contents($this->testDataDir . '/tamper_index.json'), true);
            $pos = array_search($id, $index);
            $folder = sprintf("%03d", floor($pos / 100));
            $datPath = $this->testDataDir . '/' . $folder . '/' . $id . '.dat';
            
            // Tamper isi file .dat (ubah ciphertext asli)
            $rawCiphertext = file_get_contents($datPath);
            $rawCiphertext[0] = chr(ord($rawCiphertext[0]) ^ 0xFF); // Flip bits
            file_put_contents($datPath, $rawCiphertext);
            
            // Coba load dan decrypt
            $loadedToken = $this->storage->load($id);
            try {
                CryptoService::decrypt($loadedToken, $this->masterKey);
                return ['name' => $name, 'status' => 'FAIL', 'message' => 'Dekripsi berhasil meskipun ciphertext di-tamper! (Sangat Bahaya)'];
            } catch (\RuntimeException $e) {
                if (str_contains($e->getMessage(), 'MAC verification failed')) {
                    return ['name' => $name, 'status' => 'PASS', 'message' => 'MAC gagal verifikasi karena ciphertext di-tamper. Aman.'];
                }
                throw $e;
            }
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function testNegativeTamperMAC(): array
    {
        $name = "Negative Tamper MAC Test";
        try {
            $token = CryptoService::encrypt("Data MAC", $this->masterKey);
            $id = $this->storage->save($token);
            
            $index = json_decode(file_get_contents($this->testDataDir . '/tamper_index.json'), true);
            $pos = array_search($id, $index);
            $folder = sprintf("%03d", floor($pos / 100));
            $filePath = $this->testDataDir . '/' . $folder . '/' . $id . '.json';
            
            // Tamper MAC di file
            $data = json_decode(file_get_contents($filePath), true);
            $data['mac'][0] = ($data['mac'][0] === 'a') ? 'b' : 'a';
            file_put_contents($filePath, json_encode($data));
            
            $loadedToken = $this->storage->load($id);
            try {
                CryptoService::decrypt($loadedToken, $this->masterKey);
                return ['name' => $name, 'status' => 'FAIL', 'message' => 'Dekripsi berhasil meskipun MAC di-tamper!'];
            } catch (\RuntimeException $e) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'Sistem menolak MAC yang tidak valid.'];
            }
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
