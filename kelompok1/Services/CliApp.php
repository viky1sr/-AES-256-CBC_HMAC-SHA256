<?php
namespace Kelompok1\CryptoGraphy\Services;

use Kelompok1\CryptoGraphy\CryptoService;
use Kelompok1\CryptoGraphy\KDF\HKDF;
use Kelompok1\CryptoGraphy\Support\Padding;
use Kelompok1\CryptoGraphy\Token\EtmToken;
use Kelompok1\CryptoGraphy\Trace\AES256BlockTracer;
use Kelompok1\CryptoGraphy\Trace\CBCTracer;

use function Laravel\Prompts\{
    intro, outro, text, password, select, table, info, note, warning
};

/**
 * CLI EDUKATIF untuk AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
 * ---------------------------------------------------------------
 * Fitur:
 *  - 🔐 Encrypt (master key teks → token) + tampil IV, Char→Hex, masterKey, keyEnc
 *  - 🔓 Decrypt (token + master key teks)
 *  - 🧩 Trace 1 Round (0..14) — SATU tabel per round
 *  - 🧩 Trace All — per BLOCK × per ROUND (tabel per round, cantik)
 *  - 🔬 Trace CBC per-blok (P, X=P⊕IV/Cprev, C)
 *
 * PENTING (edukasi):
 * - Menampilkan kunci/IV hanya untuk demo. **JANGAN** dilakukan di produksi!
 * - “Round 0” = AddRoundKey awal (whitening). AES-256 punya 14 round inti (1..14).
 */
final class CliApp
{
    public static function run(): void
    {
        intro('Kelompok1 Cryptography — AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)');

        $action = select(
            label: 'Pilih aksi:',
            options: [
                'encrypt'   => '🔐 Encrypt (Master Key teks → Token) + tampil IV/Key/Plain',
                'decrypt'   => '🔓 Decrypt (Token + Master Key teks)',
                'trace_one' => '🧩 Trace 1 Round (0..14) — satu tabel per round',
                'trace_all' => '🧩 Trace All — per BLOCK × per ROUND (tabel per round)',
                'trace_cbc' => '🔬 Trace CBC per-blok (P, X=P⊕IV/Cprev, C)',
            ],
            default: 'encrypt'
        );

        match ($action) {
            'encrypt'   => self::doEncrypt(),
            'decrypt'   => self::doDecrypt(),
            'trace_one' => self::doTraceOneRound(),
            'trace_all' => self::doTraceAll(),
            'trace_cbc' => self::doTraceCBC(),
        };

        outro('Selesai. 🙌');
    }

    /* =========================================================
     * ENCRYPT (EDUKASI)
     * ========================================================= */
    private static function doEncrypt(): void
    {
        $plaintext  = text('Masukkan plaintext:', required: true);
        $mkText     = password('Masukkan master key (teks):', required: true, validate: fn($v) =>
        strlen($v) < 6 ? 'Minimal 6 karakter' : null
        );

        // Master key (32B) dari teks pakai SHA-256 (EDUKASI)
        $masterKey = hash('sha256', $mkText, true);
        $keyEnc    = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');

        // Legend/kamus + padding demo
        self::legendDictionary();

        // Diagnostik panjang/padding/blok (input aktual)
        self::diagnoseLengthBlocks($plaintext);

        // Plaintext Char→Hex (16 byte pertama)
        info('🖹 Plaintext (Char → Hex, 16 byte pertama sebelum padding)');
        $chars = str_split(substr($plaintext, 0, 16));
        $rowsCharHex = [];
        foreach ($chars as $ch) $rowsCharHex[] = [ printable_char($ch), strtoupper(bin2hex($ch)) ];
        if (empty($rowsCharHex)) $rowsCharHex[] = ['(kosong)', '(padding saja)'];
        table(headers: ['Char', 'Hex'], rows: $rowsCharHex);

        // Master Key & keyEnc (EDUKASI)
        info('🔑 Master Key & Sub-key (EDUKASI — JANGAN print di produksi)');
        table(
            headers: ['Label', 'Hex (32 byte)'],
            rows: [
                ['Master Key = SHA-256(pass)', strtoupper(bin2hex($masterKey))],
                ['keyEnc = HKDF(masterKey,"aes-256-cbc:enc")', strtoupper(bin2hex($keyEnc))]
            ]
        );

        // Encrypt-then-MAC
        $token = CryptoService::encrypt($plaintext, $masterKey);

        info('🎫 Token (base64 JSON {iv,value,mac})');
        echo $token . PHP_EOL;

        // IV dari token (print untuk edukasi)
        try {
            $obj = EtmToken::unpack($token);
            info('🧊 Initialization Vector (IV) — hex');
            echo chunk_hex_group($obj['iv']) . PHP_EOL;
            self::legendIvCbc();
        } catch (\Throwable $e) {
            warning('Tidak bisa unpack token untuk menampilkan IV: '.$e->getMessage());
        }
    }

    /* =========================================================
     * DECRYPT
     * ========================================================= */
    private static function doDecrypt(): void
    {
        $token  = text('Masukkan token (base64 JSON {iv,value,mac}):', required: true);
        $mkText = password('Masukkan master key (teks):', required: true);

        try {
            $masterKey = hash('sha256', $mkText, true);
            $plain = CryptoService::decrypt($token, $masterKey);
            table(headers: ['Plaintext'], rows: [[ $plain ]]);
        } catch (\Throwable $e) {
            warning('Gagal dekripsi: '.$e->getMessage());
        }
    }

    /* =========================================================
     * TRACE 1 ROUND — Satu tabel per round
     * ========================================================= */
    private static function doTraceOneRound(): void
    {
        $plaintext = text('Plaintext (akan diproses blok pertama):', required: true);
        $mkText    = password('Master key (teks):', required: true);
        $roundStr  = text('Round yang ingin ditrace (0..14):', required: true, validate: function($v){
            if (!ctype_digit($v)) return 'Wajib angka 0..14';
            $n=(int)$v; return ($n<0||$n>14)?'Harus di rentang 0..14':null;
        });
        $useCBC    = select(
            label: 'Input state untuk round ini pakai?',
            options: [
                'ecb' => 'P (ECB/tracer murni, tanpa IV)',
                'cbc' => 'X = P ⊕ IV (CBC, IV acak ditampilkan)'
            ],
            default: 'cbc'
        );

        $round     = (int)$roundStr;
        $masterKey = hash('sha256', $mkText, true);
        $keyEnc    = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');

        self::legendDictionary();
        self::diagnoseLengthBlocks($plaintext);

        // Plaintext Char→Hex (16B pertama)
        info('🖹 Plaintext (Char → Hex, 16 byte pertama sebelum padding)');
        $chars = str_split(substr($plaintext, 0, 16));
        $rowsCharHex = [];
        foreach ($chars as $ch) $rowsCharHex[] = [ printable_char($ch), strtoupper(bin2hex($ch)) ];
        if (empty($rowsCharHex)) $rowsCharHex[] = ['(kosong)', '(padding saja)'];
        table(headers: ['Char', 'Hex'], rows: $rowsCharHex);

        // Master Key & keyEnc (EDUKASI)
        info('🔑 Master Key & keyEnc (EDUKASI — JANGAN print di produksi)');
        table(
            headers: ['Label', 'Hex (32 byte)'],
            rows: [
                ['Master Key = SHA-256(pass)', strtoupper(bin2hex($masterKey))],
                ['keyEnc = HKDF(masterKey,"aes-256-cbc:enc")', strtoupper(bin2hex($keyEnc))]
            ]
        );

        // Blok pertama (PKCS#7) → pilih input state
        $padded     = pkcs7_pad16_local($plaintext);
        $firstBlock = substr($padded, 0, 16);

        // IV jika CBC
        $iv = null;
        if ($useCBC === 'cbc') {
            $iv = random_bytes(16);
            info('🧊 Initialization Vector (IV) — hex');
            echo chunk_hex_group($iv) . PHP_EOL;
            self::legendIvCbc();
        } else {
            note("ECB/tracer: **Input = P** (tanpa XOR IV).");
        }

        // Detail per round (butuh tracePerRound)
        $detail = AES256BlockTracer::tracePerRound($firstBlock, $keyEnc, $round, $iv);

        // Tabel satu per round
        info("🧩 ROUND {$round} — Langkah");
        $rows = [
            ['Step',         'State (row-wise hex, 16 bytes)'],
            ['Input source', $detail['input_source']],
            ['Input',        $detail['input_state']],
        ];
        if ($round === 0) {
            $rows[] = ['AddRoundKey (RK-0)', $detail['addroundkey']];
        } else {
            $rows[] = ['SubBytes',           $detail['subbytes']];
            $rows[] = ['ShiftRows',          $detail['shiftrows']];
            if (isset($detail['mixcolumns'])) {
                $rows[] = ['MixColumns',     $detail['mixcolumns']];
            }
            $rows[] = ["AddRoundKey (RK-{$detail['rk_index']})", $detail['addroundkey']];
        }
        table(headers: array_shift($rows), rows: $rows);

        // RK-i yang dipakai + catatan hex
        $rk = AES256BlockTracer::roundKeysHex($keyEnc);
        note("RK-i dipakai pada ARK round ini: **i = {$detail['rk_index']}**\n"
            . "Hex RK-i (4 word): {$rk[$round]}");
        print_hex_footnote();
    }

    /* =========================================================
     * TRACE ALL — Per BLOCK × per ROUND (tabel per round)
     * ========================================================= */
    private static function doTraceAll(): void
    {
        $plaintext = text('Plaintext (semua blok akan di-trace):', required: true);
        $mkText    = password('Master key (teks):', required: true);

        $masterKey = hash('sha256', $mkText, true);
        $keyEnc    = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');

        self::legendDictionary();
        self::diagnoseLengthBlocks($plaintext);

        self::legendPaddingDemo($plaintext); // ← TABEL TAMBAHAN: panjang vs padding vs blok

        // Padding & split per 16B
        $padded    = pkcs7_pad16_local($plaintext);
        $blocks    = str_split($padded, 16);
//        var_dump($blocks);die;
        $numBlocks = count($blocks);

        // IV acak (demo CBC)
        $iv = random_bytes(16);

        // Sekali di awal: IV + Key info
        info('🧊 Initialization Vector (IV) — hex');
        echo chunk_hex_group($iv) . PHP_EOL;
        self::legendIvCbc();

        info('🔑 Master Key & keyEnc (EDUKASI — JANGAN print di produksi)');
        table(
            headers: ['Label', 'Hex (32 byte)'],
            rows: [
                ['Master Key = SHA-256(pass)', strtoupper(bin2hex($masterKey))],
                ['keyEnc = HKDF(masterKey,"aes-256-cbc:enc")', strtoupper(bin2hex($keyEnc))]
            ]
        );

        // Contoh round keys
        $rkAll = AES256BlockTracer::roundKeysHex($keyEnc);
        info('🧷 Round Key contoh (K0, K1, K14)');
        table(headers: ['RK', 'Hex (4 word)'], rows: [
            ['K0',  $rkAll[0]],
            ['K1',  $rkAll[1]],
            ['K14', $rkAll[14]],
        ]);

        // Loop blok CBC
        $prevC = $iv;
        foreach ($blocks as $i => $Pi) {
            $bIndex = $i + 1;

            echo PHP_EOL;
            info("📦 BLOCK {$bIndex}/{$numBlocks} — Plaintext (Char→Hex)");
            $rowsCharHex=[];
            foreach (str_split($Pi) as $ch) {
                $rowsCharHex[] = [ printable_char($ch), strtoupper(bin2hex($ch)) ];
            }
            table(headers:['Char','Hex'], rows:$rowsCharHex);

            // Deteksi blok padding murni (mis. \x10 × 16)
            $padVal = ord(substr($padded, -1));
            $isPurePadding = ($i === $numBlocks - 1) && ($Pi === str_repeat(chr($padVal), 16));
            if ($isPurePadding) {
                note("ℹ️ BLOCK {$bIndex} adalah blok PKCS#7 padding murni (byte 0x".strtoupper(dechex($padVal))." × 16).");
            }

            // Chaining CBC: X = P ⊕ (IV/Cprev), C = AES_Enc(X) (ECB internal untuk ilustrasi)
            $X = $Pi ^ $prevC;
            $C = openssl_encrypt($X,'aes-256-ecb',$keyEnc,OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);
            if ($C === false) { warning('ECB encrypt gagal'); return; }

            info("🔗 BLOCK {$bIndex} — Chaining CBC");
            table(headers:['Label','Hex'], rows: [
                ['P',                chunk_hex_group($Pi)],
                [$bIndex===1?'X=P⊕IV':'X=P⊕Cprev', chunk_hex_group($X)],
                ['C=AES_Enc(X)',     chunk_hex_group($C)],
            ]);

            // Untuk setiap ROUND 0..14 → SATU tabel per round
            for ($r=0; $r<=14; $r++) {
                $detail = AES256BlockTracer::tracePerRound($Pi, $keyEnc, $r, $prevC);

                info("🧩 BLOCK {$bIndex} — ROUND {$r} — Langkah");
                $rows = [
                    ['Step',         'State (row-wise hex, 16 bytes)'],
                    ['Input source', $detail['input_source']],
                    ['Input',        $detail['input_state']],
                ];
                if ($r === 0) {
                    $rows[] = ['AddRoundKey (RK-0)', $detail['addroundkey']];
                } else {
                    $rows[] = ['SubBytes',           $detail['subbytes']];
                    $rows[] = ['ShiftRows',          $detail['shiftrows']];
                    if (isset($detail['mixcolumns'])) {
                        $rows[] = ['MixColumns',     $detail['mixcolumns']];
                    }
                    $rows[] = ["AddRoundKey (RK-{$detail['rk_index']})", $detail['addroundkey']];
                }

                table(headers: array_shift($rows), rows: $rows);

                // tampilkan RK-i dipakai + footnote HEX
                note("RK-i dipakai pada ARK round ini: **i = {$detail['rk_index']}**\n"
                    . "Hex RK-i (4 word): {$rkAll[$r]}");
                print_hex_footnote();
            }

            // update chaining untuk blok berikutnya
            $prevC = $C;
        }

        note("Konsep: SB → confusion (non-linear), SR+MC → difusi (penyebaran bit).");
    }

    /* =========================================================
     * TRACE CBC per-blok (ringkas P, X, C)
     * ========================================================= */
    private static function doTraceCBC(): void
    {
        $plaintext = text('Plaintext untuk CBC trace:', required: true);
        $mkText    = password('Master key (teks):', required: true);

        $masterKey = hash('sha256', $mkText, true);
        $keyEnc    = HKDF::derive($masterKey, 32, info: 'aes-256-cbc:enc');

        $iv = random_bytes(16);
        $rows = CBCTracer::trace($plaintext, $keyEnc, $iv);

        self::legendDictionary();
        self::diagnoseLengthBlocks($plaintext);

        info('🧊 Initialization Vector (IV) — hex');
        echo chunk_hex_group($iv) . PHP_EOL;
        self::legendIvCbc();

        foreach ($rows as $b) {
            echo PHP_EOL;
            info('Block ' . str_pad((string)$b['block'], 2, '0', STR_PAD_LEFT));
            table(headers: ['Label', 'Hex'], rows: [
                ['P',            chunk_hex_group(hex2bin($b['P']))],
                ['X=P⊕IV/Cprev', chunk_hex_group(hex2bin($b['X']))],
                ['C',            chunk_hex_group(hex2bin($b['C']))],
            ]);
        }
    }

    /* ================= Legend / Kamus (ditampilkan di awal) ================= */

    /** Kamus simbol/istilah & ikon agar semua paham sebelum output. */
    private static function legendDictionary(): void
    {
        info('📘 Kamus Simbol, Operator, Istilah (dibaca dulu ya!)');
        table(headers:['Simbol/Term','Arti'], rows:[
            ['⊕',        'XOR (exclusive OR) di notasi kriptografi (bitwise)'],
            ['^',        'Operator XOR di PHP. Contoh: $x ^ $y'],
            ['Hex digit','1 digit hex = 4 bit = 1 nibble'],
            ['Nibble',   '4 bit (setengah byte)'],
            ['Byte',     '8 bit = 2 digit hex (contoh: "AF")'],
            ['Word',     '32 bit = 4 byte = 8 digit hex (contoh: "08476B49")'],
            ['4 word',   '4 × 32 bit = 128 bit = 16 byte (RK-i satu round)'],
            ['State',    'Matriks 4×4 byte. Dicetak “row-wise hex, 16 bytes”'],
            ['P',        'Plaintext block (16 byte) setelah padding PKCS#7'],
            ['C',        'Ciphertext block (16 byte) hasil AES_Enc(X)'],
            ['IV',       'Initialization Vector 16 byte acak/unik untuk CBC (tidak rahasia)'],
            ['X',        'Input state ke AES. Blok-1: X₁=P₁⊕IV; Blok-i>1: Xᵢ=Pᵢ⊕Cᵢ₋₁'],
            ['S(b)',     'SubBytes: substitusi byte b via S-box (non-linear) → confusion'],
            ['SB',       'SubBytes (pakai S-box)'],
            ['SR',       'ShiftRows (rotasi baris: 0,1,2,3 kiri-siklik) → difusi'],
            ['MC',       'MixColumns (matriks GF(2⁸)): campur kolom → difusi'],
            ['ARK',      'AddRoundKey: state ⊕ RK-i (XOR dengan round key indeks i)'],
            ['RK-i',     'Round Key ke-i (K0..K14) dari key schedule AES-256 (tiap RK = 4 word)'],
            ['K0..K14',  '16-byte key per round (4 word). K0 dipakai di “Round 0/whitening”'],
            ['Whitening','AddRoundKey awal (Round 0)'],
            ['Confusion','Menutupi relasi kunci-plaintext (SubBytes)'],
            ['Difusi',   'Menyebar perubahan ke seluruh state (ShiftRows + MixColumns)'],
            ['GF(2⁸)',   'Ruang bilangan biner 8-bit; operasi MC dilakukan di sini'],
            ['xtime(x)', 'Perkalian x dengan 02 di GF(2⁸) (dengan reduksi polinomial)'],
            ['02⊗x',     'Sama dengan xtime(x)'],
            ['03⊗x',     'xtime(x) ⊕ x'],
            ['ECB',      'AES-ECB (dipakai internal tracer; bukan mode produksi)'],
            ['CBC',      'Cipher Block Chaining: X = P ⊕ (IV atau Cprev)'],
            ['Row-wise', 'Cara cetak state per baris (untuk tampilan saja)'],
        ]);

        self::legendWordHexExamples();
        self::legendRounds();
    }

    /** Contoh konkret konversi hex → byte/bit + ilustrasi word & 4 word. */
    private static function legendWordHexExamples(): void
    {
        info('🔎 Ilustrasi Hex/Word (biar gak rancu bit vs byte)');
        table(headers:['Contoh','Penjelasan'], rows:[
            ['08476B49',   '8 digit hex = 32 bit = 4 byte → 1 word (AddRoundKey kolom tunggal)'],
            ['04C0DD9A C66248DA 40C20464 08476B49',
                '4 word (masing-masing 8 digit hex) = 16 byte = 128 bit → RK-i untuk 1 round'],
            ['AF',         '2 digit hex = 1 byte = 8 bit'],
            ['04 C0',      '2 byte (04 dan C0) = 16 bit (ini BUKAN 1 word; 1 word butuh 4 byte)'],
        ]);
    }

    /** Penjelasan chaining CBC (X = P⊕IV/Cprev). */
    private static function legendIvCbc(): void
    {
        note("CBC chaining:\n"
            . "• Blok-1:  X₁ = P₁ ⊕ IV  → C₁ = AES_Enc(X₁)\n"
            . "• Blok-i:  Xᵢ = Pᵢ ⊕ Cᵢ₋₁ → Cᵢ = AES_Enc(Xᵢ)\n"
            . "IV 16B acak/unik, tidak rahasia namun JANGAN di-reuse untuk key yang sama.");
    }

    /** Ringkasan langkah round + rumus matematika singkat. */
    private static function legendRounds(): void
    {
        info('📐 Rangkuman Langkah Round & Rumus');
        echo <<<TXT
• Round 0       : AddRoundKey(K0)                → state ← state ⊕ K0
• Round 1..13   : SubBytes → ShiftRows → MixColumns → AddRoundKey(Kr)
• Round 14      : SubBytes → ShiftRows → AddRoundKey(K14) (tanpa MixColumns)

Rumus (GF(2⁸), m(x)=x⁸+x⁴+x³+x+1):
- ARK : state ← state ⊕ Kᵣ
- SB  : S(b) = A·(b⁻¹) ⊕ c     (b⁻¹ = invers multiplikatif di GF(2⁸))
- SR  : baris-0:0, baris-1:1, baris-2:2, baris-3:3 (geser kiri siklik)
- MC  : untuk kolom [a0..a3]^T:
    [02 03 01 01]   [a0]
    [01 02 03 01] * [a1]   (02⊗x = xtime(x); 03⊗x = xtime(x) ⊕ x)
    [01 01 02 03]   [a2]
    [03 01 01 02]   [a3]

Konsep: SB → confusion (non-linear), SR+MC → difusi (penyebaran bit).
TXT . PHP_EOL;
    }

    /** TABEL: Panjang plaintext vs padding vs total vs jumlah blok (PKCS#7, AES 16B). */
    /** Tabel PKCS#7 (contoh konstan) + demo dinamis sesuai plaintext user. */
    private static function legendPaddingDemo(string $plaintext): void
    {
        // Bagian “contoh umum” (tetap sama seperti punyamu)
        info('📏 PKCS#7 Padding (AES block = 16 byte) — Contoh Panjang → Blok');
        table(
            headers: ['Panjang plaintext (byte)', 'Padding (byte)', 'Total setelah pad', 'Jumlah blok'],
            rows: [
                ['1',   '15', '16',  '1'],
                ['15',  '1',  '16',  '1'],
                ['16',  '16', '32',  '2'],
                ['17',  '15', '32',  '2'],
                ['31',  '1',  '32',  '2'],
                ['32',  '16', '48',  '3'],
                ['48',  '16', '64',  '4'],
                ['100', '12', '112', '7'],
            ]
        );

        // ======= DEMO DINAMIS BERDASARKAN INPUT KAMU =======
        $bs  = 16;
        $len = strlen($plaintext);
        $r   = $len % $bs;
        $pad = $bs - $r;
        if ($pad === 0) $pad = 16;              // aturan PKCS#7 saat pas kelipatan
        $total  = $len + $pad;
        $blocks = intdiv($total, $bs);

        // Susun penjelasan contoh sesuai input aktual
        $examples = [];
        if ($r === 0) {
            // len pas 16n  → blok-akhir = padding penuh 0x10 × 16
            $examples[] = sprintf("• len=%d  → pad=%d ⇒ blok-%d = 0x%02X × 16 (padding penuh)", $len, $pad, $blocks, $pad);
        } else {
            // len tidak pas → blok-akhir = data sisa + (pad)×nilaiPad
            // Ambil 1 byte terakhir agar contoh lebih “hidup”
            $lastChar = $len > 0 ? substr($plaintext, -1) : '';
            $lastShow = $lastChar === '' ? '(kosong)' : printable_char($lastChar);
            $examples[] = sprintf(
                "• len=%d  → pad=%d ⇒ blok-%d = '%s' + 0x%02X × %d (data+padding)",
                $len, $pad, $blocks, $lastShow, $pad, $pad
            );
        }

        // Tampilkan ringkasan dinamis
        note(
            "Aturan PKCS#7: pad = 16 − (len % 16), namun bila len%16=0 maka pad=16 (tambah 1 blok penuh).\n"
            . "Jumlah blok = (len + pad) / 16.\n\n"
            . "Contoh efek (berdasarkan input kamu):\n"
            . implode("\n", $examples)
        );

        // Bonus: preview blok hasil pad dalam HEX + label padding agar makin jelas
        $padded = \Kelompok1\CryptoGraphy\Support\Padding::pad($plaintext);
        $chunks = str_split($padded, 16);
        info('🔎 Preview blok hasil padding (HEX)');
        $rows = [];
        foreach ($chunks as $i => $blk) {
            $idx = $i + 1;
            $hex = strtoupper(implode(' ', str_split(bin2hex($blk), 2)));
            $label = '';
            $isLast = ($idx === count($chunks));
            $padVal = ord(substr($padded, -1));
            $isPurePadding = $isLast && ($blk === str_repeat(chr($padVal), 16));
            if ($isPurePadding) {
                $label = sprintf('← PKCS#7 padding murni (0x%02X × 16)', $padVal);
            } elseif ($isLast && $padVal >= 1 && $padVal <= 15) {
                $label = sprintf('← Data + padding (0x%02X × %d)', $padVal, $padVal);
            }
            $rows[] = [ "Block {$idx}", $hex, $label ];
        }
        table(headers:['Block','Hex (16B)','Keterangan'], rows:$rows);
    }


    /** Diagnostik real-time untuk input user: panjang → pad → total → jumlah blok. */
    private static function diagnoseLengthBlocks(string $plaintext): void
    {
        $bs = 16;
        $lenBytes    = strlen($plaintext);
        $pad         = $bs - ($lenBytes % $bs);
        if ($pad === 0) $pad = 16;
        $totalPadded = $lenBytes + $pad;
        $blocks      = intdiv($totalPadded, $bs);

        info('ℹ️ Diagnostik Panjang/Blok (input kamu)');
        table(headers:['Kunci','Nilai'], rows:[
            ['Panjang plaintext (byte)', (string)$lenBytes],
            ['Nilai padding (PKCS#7)',   sprintf('%d (0x%02X)', $pad, $pad)],
            ['Total setelah padding',    (string)$totalPadded],
            ['Jumlah blok (16B/blok)',   (string)$blocks],
        ]);
    }
}

/* ================= Helper fungsi lokal ================= */

function pkcs7_pad16_local(string $data): string
{
    $bs=16;
    return Padding::pad($data,$bs);
}

/** Format biner → HEX berkelompok (tiap 8 byte beri spasi ekstra) */
function chunk_hex_group(string $bin): string
{
    $hex   = strtoupper(bin2hex($bin));
    $parts = str_split($hex, 4); // 2 byte per kelompok
    $out   = [];
    foreach ($parts as $i => $p) {
        $out[] = $p;
        if (($i+1)%4===0 && ($i+1)<count($parts)) $out[] = ' ';
    }
    return implode(' ', $out);
}

/** Render karakter agar terlihat saat non-printable. */
function printable_char(string $ch): string
{
    $o = ord($ch);
    if ($o >= 32 && $o <= 126) return $ch; // printable ASCII
    if ($ch === "\n") return '\\n';
    if ($ch === "\r") return '\\r';
    if ($ch === "\t") return '\\t';
    return sprintf('\\x%02X', $o);
}

/** Catatan di bawah tabel: apa itu HEX, word, RK-i, dan notasi XOR. */
function print_hex_footnote(): void
{
    note("Catatan HEX:\n"
        . "• Semua state dicetak sebagai “row-wise hex, 16 bytes”.\n"
        . "• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.\n"
        . "• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.\n"
        . "• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.\n"
        . "• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.\n"
        . "• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.");
}
