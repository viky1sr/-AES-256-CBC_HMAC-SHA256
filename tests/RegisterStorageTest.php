<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Tests;

use Kelompok1\CryptoGraphy\RegisterStorage;
use Kelompok1\CryptoGraphy\Domain\User;

class RegisterStorageTest
{
    private string $testFile;
    private string $testKeystore;
    private RegisterStorage $storage;

    public function __construct()
    {
        $this->testFile = __DIR__ . '/../storage/test/data/reg_test/users_test.json';
        $this->testKeystore = __DIR__ . '/../storage/test/config/reg_test/keystore';
        
        if (!is_dir(dirname($this->testFile))) {
            mkdir(dirname($this->testFile), 0777, true);
        }
        
        if (!is_dir($this->testKeystore)) {
            mkdir($this->testKeystore, 0777, true);
        }

        // Pass both paths to RegisterStorage
        $this->storage = new RegisterStorage($this->testFile, $this->testKeystore);
    }

    public function run(): array
    {
        $results = [];
        $results[] = $this->testSaveAndLoadUser();
        $results[] = $this->testDuplicateUser();
        $results[] = $this->testUsernameEncryptionInStorage();
        
        // $this->cleanup();
        return $results;
    }

    private function testSaveAndLoadUser(): array
    {
        $name = "Register Save & Load Test";
        try {
            $user = new User(bin2hex(random_bytes(16)), "testuser_" . time(), "hash_pwd", date('c'));
            $this->storage->save($user);
            
            $found = $this->storage->findByUsername($user->username);
            
            if ($found && $found->username === $user->username && $found->uuid === $user->uuid) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'User berhasil disimpan dan ditemukan kembali (username otomatis didekripsi).'];
            }
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'User tidak ditemukan atau data tidak cocok.'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function testDuplicateUser(): array
    {
        $name = "Duplicate Register Test";
        try {
            $username = "duplicate_user_" . time();
            $user1 = new User(bin2hex(random_bytes(16)), $username, "hash1", date('c'));
            $user2 = new User(bin2hex(random_bytes(16)), $username, "hash2", date('c'));
            
            $this->storage->save($user1);
            try {
                $this->storage->save($user2);
                return ['name' => $name, 'status' => 'FAIL', 'message' => 'Sistem mengizinkan pendaftaran username duplikat!'];
            } catch (\RuntimeException $e) {
                if (str_contains($e->getMessage(), 'terdaftar')) {
                    return ['name' => $name, 'status' => 'PASS', 'message' => 'Sistem menolak username duplikat dengan benar.'];
                }
                throw $e;
            }
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function testUsernameEncryptionInStorage(): array
    {
        $name = "Username Storage Encryption Test";
        try {
            $username = "secret_user_" . time();
            $user = new User(bin2hex(random_bytes(16)), $username, "pwd", date('c'));
            $this->storage->save($user);
            
            // Baca file JSON mentah
            $rawJson = file_get_contents($this->testFile);
            if (str_contains($rawJson, $username)) {
                return ['name' => $name, 'status' => 'FAIL', 'message' => 'Username asli ditemukan dalam teks terang di users.json!'];
            }
            
            if (str_contains($rawJson, '.user.json')) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'Username tersimpan terenkripsi sebagai referensi file user.json.'];
            }
            
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'Format penyimpanan username tidak dikenali.'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function cleanup()
    {
        $dir = dirname($this->testFile);
        if (is_dir($dir)) {
            $this->recursiveRmdir($dir);
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
