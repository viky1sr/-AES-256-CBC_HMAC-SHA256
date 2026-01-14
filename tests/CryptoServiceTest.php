<?php
declare(strict_types=1);

namespace Kelompok1\CryptoGraphy\Tests;

use Kelompok1\CryptoGraphy\CryptoService;
use Kelompok1\CryptoGraphy\CryptoPassService;
use Kelompok1\CryptoGraphy\KDF\HKDF;

class CryptoServiceTest
{
    private string $masterKey;

    public function __construct()
    {
        $this->masterKey = str_repeat('k', 32);
    }

    public function run(): array
    {
        $results = [];
        $results[] = $this->testCoreEtM();
        $results[] = $this->testPassphraseEtM();
        $results[] = $this->testKeySeparation();
        $results[] = $this->testInvalidKey();
        return $results;
    }

    private function testCoreEtM(): array
    {
        $name = "Core EtM Test";
        try {
            $plain = "Hello World Cryptography";
            $token = CryptoService::encrypt($plain, $this->masterKey);
            $decrypted = CryptoService::decrypt($token, $this->masterKey);

            if ($decrypted === $plain) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'Enkripsi/Dekripsi EtM berhasil.'];
            }
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'Hasil dekripsi tidak cocok.'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function testPassphraseEtM(): array
    {
        $name = "Passphrase EtM Test";
        try {
            $plain = "Passphrase Secret";
            $pass = "password-kita-semua";
            $token = CryptoPassService::encryptWithPassphrase($plain, $pass);
            $decrypted = CryptoPassService::decryptWithPassphrase($token, $pass);

            if ($decrypted === $plain) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'Enkripsi/Dekripsi berbasis Passphrase berhasil.'];
            }
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'Hasil dekripsi passphrase tidak cocok.'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function testKeySeparation(): array
    {
        $name = "Key Separation Test";
        try {
            $k1 = HKDF::derive($this->masterKey, 32, info: 'test:purpose:1');
            $k2 = HKDF::derive($this->masterKey, 32, info: 'test:purpose:2');

            if ($k1 !== $k2 && strlen($k1) === 32 && strlen($k2) === 32) {
                return ['name' => $name, 'status' => 'PASS', 'message' => 'HKDF berhasil menurunkan kunci yang berbeda untuk tujuan berbeda.'];
            }
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'HKDF gagal memisahkan kunci.'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => $e->getMessage()];
        }
    }

    private function testInvalidKey(): array
    {
        $name = "Invalid Key Test";
        try {
            $shortKey = "pendek";
            CryptoService::encrypt("data", $shortKey);
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'Sistem menerima kunci yang terlalu pendek!'];
        } catch (\InvalidArgumentException $e) {
            return ['name' => $name, 'status' => 'PASS', 'message' => 'Sistem menolak kunci yang tidak aman (terlalu pendek).'];
        } catch (\Exception $e) {
            return ['name' => $name, 'status' => 'FAIL', 'message' => 'Error tidak terduga: ' . $e->getMessage()];
        }
    }
}
