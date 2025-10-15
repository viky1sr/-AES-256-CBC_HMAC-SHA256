<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Kelompok1\CryptoGraphy\CryptoService;
use Kelompok1\CryptoGraphy\Services\KeyStorePass;

use function Laravel\Prompts\{
    intro, outro, password, text, info, note, table, warning
};

$keyPath = __DIR__ . '/../config/app_key.pass.json';

intro('Demo Encrypt/Decrypt (PassphraseKDF) — AES-256-CBC + HMAC-SHA256 (EtM)');

// ===== Legend / Glossary singkat =====
info('📚 LEGEND — Sekilas Konsep');
table(
    headers: ['Istilah', 'Penjelasan'],
    rows: [
        [
            'Passphrase',
            'Kata sandi/kalimat rahasia yang kamu input. Akan di-derivasi → masterKey.'
        ],
        [
            'PBKDF2 (Derive)',
            'DK = PBKDF2(HMAC-SHA256, passphrase, salt, iter, 32B). Iterations memperlambat brute force.'
        ],
        [
            'HKDF (Key Split)',
            'Dari masterKey → keyEnc (enkripsi) & keyMac (MAC) agar aman secara komposisi (key separation).'
        ],
        [
            'AES-256-CBC',
            'Block cipher 128-bit blok, kunci 256-bit, mode CBC dengan IV 16B unik/acak.'
        ],
        [
            'HMAC-SHA256 (EtM)',
            'MAC = HMAC(keyMac, IV || ciphertext). Diverifikasi dulu sebelum dekripsi.'
        ],
    ]
);

note(
    "📂 Keystore yang dipakai: {$keyPath}\n".
    "• File menyimpan salt + iter + auth, BUKAN masterKey.\n".
    "• masterKey dihitung ulang saat kamu input passphrase."
);

$pass  = password('Masukkan passphrase:', required: true);
$plain = text('Plaintext:', required: true);

// ===== Edukasi tambahan PBKDF2 Iterations =====
info('ℹ️ PBKDF2 Iterations — Kenapa & Bagaimana Memilihnya');
note(
    "• Iterations = jumlah loop HMAC per-derivasi. Semakin besar ⇒ semakin mahal dihitung.\n".
    "• Fungsi: memperlambat brute-force terhadap passphrase yang lemah.\n".
    "• Rekomendasi awal: ≥ 100.000. Banyak sistem modern nyaman di 200k—1M.\n".
    "• Ukur performa di servermu dan pilih angka yang memberi ~100–500 ms per derivasi."
);

try {
    // 1) Rekonstruksi masterKey dari passphrase (pakai metadata di keystore).
    $masterKey = KeyStorePass::load($keyPath, $pass);

    // 2) Encrypt → token base64(JSON {iv,value,mac})
    $token = CryptoService::encrypt($plain, $masterKey);

    info('🔐 Token (base64 JSON {iv,value,mac}):');
    echo $token . PHP_EOL . PHP_EOL;

    // 3) Decrypt (verifikasi MAC dulu)
    $back = CryptoService::decrypt($token, $masterKey);

    info('🔓 Hasil dekripsi (valid):');
    echo $back . PHP_EOL;

    // 4) Flow & Rumus
    info('🧠 Flow & Rumus Inti');
    note(
        "Derive:\n".
        "  DK = PBKDF2(HMAC-SHA256, passphrase, salt, iter, 32B)  → masterKey\n\n".
        "Split Key (HKDF):\n".
        "  keyEnc = HKDF(masterKey, 32, info='aes-256-cbc:enc')\n".
        "  keyMac = HKDF(masterKey, 32, info='aes-256-cbc:mac')\n\n".
        "Encrypt-then-MAC:\n".
        "  C = AES-256-CBC(keyEnc, IV; P)\n".
        "  M = HMAC-SHA256(keyMac, IV || C)\n".
        "  Token = base64(JSON {iv,value,mac})\n\n".
        "Dekripsi:\n".
        "  Validasi MAC dulu. Jika M ≠ HMAC(keyMac, IV||C) → TOLAK. Jika cocok, P = AES-DEC(keyEnc, IV; C)."
    );

    // 5) Tips keamanan passphrase
    info('🔒 Tips Memilih Passphrase');
    note(
        "• Jangan pakai yang gampang ditebak (nama, tanggal lahir, 'password', dsb).\n".
        "• Minimal 10–12 karakter; campur huruf besar/kecil, angka, simbol.\n".
        "• Bisa pakai 4–6 kata acak (diceware) untuk memudahkan ingat tapi tetap kuat."
    );

    outro('Selesai ✅');
} catch (\Throwable $e) {
    warning('❌ Operasi gagal: '.$e->getMessage());
    exit(1);
}
