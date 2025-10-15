<?php
declare(strict_types=1);

require __DIR__ . '/../vendor/autoload.php';

use Kelompok1\CryptoGraphy\Services\KeyStorePass;

use function Laravel\Prompts\{
    intro, outro, password, text, info, note, table, warning
};

$keyPath = __DIR__ . '/../config/app_key.pass.json';

intro('Init KeyStore (PBKDF2-SHA256 via PassphraseKDF)');

// ===== Legend / Glossary (ditampilkan dulu biar tim paham) =====
info('📚 LEGEND — Passphrase, PBKDF2 & Iterations');
table(
    headers: ['Istilah', 'Penjelasan Singkat'],
    rows: [
        [
            'Passphrase',
            'Kata sandi/kalimat rahasia yang kamu input (contoh: "rahasia@123!"). Ini TIDAK langsung dipakai sbg key; harus di-derivasi dulu.'
        ],
        [
            'PBKDF2',
            'Password-Based Key Derivation Function v2 — rumus yang mengubah passphrase menjadi key kuat: '
            .'DK = PBKDF2(HMAC-SHA256, passphrase, salt, iter, dkLen).'
        ],
        [
            'Salt',
            'Angka acak tambahan (per keystore) untuk mencegah rainbow-table & collision antar user.'
        ],
        [
            'Iterations',
            'Banyaknya pengulangan hash. Semakin besar ⇒ semakin lambat brute force. Direkomendasikan >= 100k.'
        ],
        [
            'masterKey (32B)',
            'Kunci utama hasil PBKDF2 (32 byte = 256-bit). Inilah yang dipakai HKDF→keyEnc/keyMac.'
        ],
    ]
);

note(
    "📂 Lokasi file keystore: {$keyPath}\n".
    "File ini **tidak menyimpan masterKey**. Hanya metadata: alg, salt, iter, auth.\n".
    "Saat load, masterKey dihitung ulang dari passphrase yang kamu ketik."
);

$pass = password(
    label: 'Masukkan passphrase (contoh: rahasia@123!)',
    required: true,
    validate: fn($v) => strlen((string)$v) < 6 ? 'Minimal 6 karakter' : null
);

$iterStr = text(
    label: 'PBKDF2 iterations (>=100000, kosong=210000):',
    validate: function($v){
        if ($v === '') return null;
        if (!ctype_digit($v) || (int)$v < 100000) return 'Masukkan angka >= 100000 atau kosong';
        return null;
    }
);
$iter = ($iterStr === '') ? 210000 : (int)$iterStr;

// ===== Edukasi tambahan tentang Iterations =====
info('ℹ️ Kenapa Iterations Penting?');
note(
    "• PBKDF2 memanggil HMAC-SHA256 berulang (\"iterations\").\n".
    "• Tujuan: memperlambat penyerang yang coba brute-force passphrase.\n".
    "• Pilih angka yang memberikan ~100–500 ms per-derivasi di server kamu.\n".
    "• Semakin kuat CPU/GPU penyerang, semakin tinggi iterations yang kamu butuhkan."
);

// ===== Inisialisasi keystore =====
try {
    KeyStorePass::init($keyPath, $pass, $iter);

    info('✅ Keystore berhasil dibuat');
    table(
        headers: ['Kunci', 'Nilai'],
        rows: [
            ['Algoritma KDF', 'PBKDF2-HMAC-SHA256'],
            ['Iterations', (string)$iter],
            ['Salt', 'acak (disimpan di file)'],
            ['Auth', 'HMAC(masterKey, "auth-check") untuk verifikasi passphrase']
        ]
    );

    note(
        "Format file JSON:\n".
        "{\n".
        "  \"alg\": \"pbkdf2-sha256\",\n".
        "  \"salt\": \"<base64url>\",\n".
        "  \"iter\": {$iter},\n".
        "  \"auth\": \"<base64url>\"\n".
        "}\n\n".
        "Tanpa passphrase yang benar, kalkulasi ulang masterKey akan salah ⇒ 'auth' gagal ⇒ tidak bisa dipakai."
    );

    outro('Selesai ✅');
} catch (\Throwable $e) {
    warning('❌ Gagal inisialisasi: '.$e->getMessage());
    exit(1);
}
