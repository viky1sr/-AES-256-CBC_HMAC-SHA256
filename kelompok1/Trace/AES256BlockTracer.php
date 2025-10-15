<?php

namespace Kelompok1\CryptoGraphy\Trace;

/**
 * Tracer internal round AES-256 untuk satu blok (tanpa CBC, tapi bisa diberi IV
 * agar "Input" menjadi X = P ⊕ IV seperti CBC).
 *
 * ROUND FLOW (AES-256):
 *  - Round 0 : AddRoundKey (initial whitening)  → pakai RK-0
 *  - Round 1..13 : SubBytes → ShiftRows → MixColumns → AddRoundKey  → pakai RK-r
 *  - Round 14 : SubBytes → ShiftRows → AddRoundKey (tanpa MixColumns) → pakai RK-14
 *
 * Tujuan: edukasi/visualisasi, bukan performa/produksi.
 */
final class AES256BlockTracer
{
    /* ===================== S-Box & Rcon ===================== */
    private static function sbox(): array
    {
        static $S = null;

        if ($S) {
            return $S;
        }

        return $S = [
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
        ];
    }

    private static function rcon(): array
    {
        return [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A];
    }

    /* ===================== Key schedule AES-256 ===================== */
    private static function keyExpansion256(string $key32): array
    {
        if (strlen($key32) !== 32) {
            throw new \InvalidArgumentException('Key harus 32 byte');
        }
        $w = [];
        for ($i = 0; $i < 8; $i++) {
            $w[$i] = [ord($key32[4 * $i]), ord($key32[4 * $i + 1]), ord($key32[4 * $i + 2]), ord($key32[4 * $i + 3])];
        }
        for ($i = 8; $i < 60; $i++) {
            $temp = $w[$i - 1];
            if ($i % 8 === 0) {
                $temp = self::subWord(self::rotWord($temp));
                $temp[0] ^= self::rcon()[$i / 8];
            } elseif ($i % 8 === 4) {
                $temp = self::subWord($temp);
            }
            $w[$i] = [
                $w[$i - 8][0] ^ $temp[0],
                $w[$i - 8][1] ^ $temp[1],
                $w[$i - 8][2] ^ $temp[2],
                $w[$i - 8][3] ^ $temp[3],
            ];
        }

        return $w; // 60 word (w[0..59]); RoundKey r = w[4r..4r+3]
    }

    private static function rotWord(array $w): array
    {
        return [$w[1], $w[2], $w[3], $w[0]];
    }

    private static function subWord(array $w): array
    {
        $S = self::sbox();

        return [$S[$w[0]], $S[$w[1]], $S[$w[2]], $S[$w[3]]];
    }

    /* ===================== State helpers ===================== */
    private static function bytesToState(string $b): array
    {
        $s = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]];
        for ($i = 0; $i < 16; $i++) {
            $s[$i % 4][intdiv($i, 4)] = ord($b[$i]);
        }

        return $s;
    }

    private static function stateToHex(array $s): string
    {
        $hex = '';
        for ($r = 0; $r < 4; $r++) {
            for ($c = 0; $c < 4; $c++) {
                $hex .= sprintf('%02X', $s[$r][$c]);
                if (! ($r === 3 && $c === 3)) {
                    $hex .= ' ';
                }
            } if ($r < 3) {
                $hex .= '  ';
            }
        }

        return $hex;
    }

    private static function addRoundKey(array &$s, array $w, int $round): void
    {
        for ($c = 0; $c < 4; $c++) {
            $word = $w[4 * $round + $c];
            for ($r = 0; $r < 4; $r++) {
                $s[$r][$c] ^= $word[$r];
            }
        }
    }

    private static function subBytes(array &$s): void
    {
        $S = self::sbox();
        for ($r = 0; $r < 4; $r++) {
            for ($c = 0; $c < 4; $c++) {
                $s[$r][$c] = $S[$s[$r][$c]];
            }
        }
    }

    private static function shiftRows(array &$s): void
    {
        $s[1] = [$s[1][1], $s[1][2], $s[1][3], $s[1][0]];
        $s[2] = [$s[2][2], $s[2][3], $s[2][0], $s[2][1]];
        $s[3] = [$s[3][3], $s[3][0], $s[3][1], $s[3][2]];
    }

    private static function gmul(int $a, int $b): int
    {
        $p = 0;
        for ($i = 0; $i < 8; $i++) {
            if ($b & 1) {
                $p ^= $a;
            } $hi = $a & 0x80;
            $a = ($a << 1) & 0xFF;
            if ($hi) {
                $a ^= 0x1B;
            } $b >>= 1;
        }

        return $p & 0xFF;
    }

    private static function mixColumns(array &$s): void
    {
        for ($c = 0; $c < 4; $c++) {
            $a = [$s[0][$c], $s[1][$c], $s[2][$c], $s[3][$c]];
            $s[0][$c] = self::gmul(0x02, $a[0]) ^ self::gmul(0x03, $a[1]) ^ $a[2] ^ $a[3];
            $s[1][$c] = $a[0] ^ self::gmul(0x02, $a[1]) ^ self::gmul(0x03, $a[2]) ^ $a[3];
            $s[2][$c] = $a[0] ^ $a[1] ^ self::gmul(0x02, $a[2]) ^ self::gmul(0x03, $a[3]);
            $s[3][$c] = self::gmul(0x03, $a[0]) ^ $a[1] ^ $a[2] ^ self::gmul(0x02, $a[3]);
        }
    }

    /* =========================================================
     * 1) BACK-COMPAT: trace() lama (semua langkah semua round)
     * ========================================================= */
    /**
     * @return array<int,array{round:int,step:string,state:string}>
     */
    public static function trace(string $block16, string $key32): array
    {
        if (strlen($block16) !== 16) {
            throw new \InvalidArgumentException('Blok harus 16 byte');
        }
        if (strlen($key32) !== 32) {
            throw new \InvalidArgumentException('Key harus 32 byte');
        }
        $w = self::keyExpansion256($key32);
        $s = self::bytesToState($block16);
        $out = [];
        self::addRoundKey($s, $w, 0);
        $out[] = ['round' => 0, 'step' => 'AddRoundKey', 'state' => self::stateToHex($s)];
        for ($r = 1; $r <= 13; $r++) {
            self::subBytes($s);
            $out[] = ['round' => $r, 'step' => 'SubBytes', 'state' => self::stateToHex($s)];
            self::shiftRows($s);
            $out[] = ['round' => $r, 'step' => 'ShiftRows', 'state' => self::stateToHex($s)];
            self::mixColumns($s);
            $out[] = ['round' => $r, 'step' => 'MixColumns', 'state' => self::stateToHex($s)];
            self::addRoundKey($s, $w, $r);
            $out[] = ['round' => $r, 'step' => 'AddRoundKey', 'state' => self::stateToHex($s)];
        }
        $r = 14;
        self::subBytes($s);
        $out[] = ['round' => $r, 'step' => 'SubBytes', 'state' => self::stateToHex($s)];
        self::shiftRows($s);
        $out[] = ['round' => $r, 'step' => 'ShiftRows', 'state' => self::stateToHex($s)];
        self::addRoundKey($s, $w, $r);
        $out[] = ['round' => $r, 'step' => 'AddRoundKey', 'state' => self::stateToHex($s)];

        return $out;
    }

    /* =========================================================
     * 2) BARU: roundKeysHex() → cetak K0..K14 (4 word/round key)
     * ========================================================= */
    /**
     * Mengembalikan K0..K14 sebagai string "WWWW WWWW WWWW WWWW" (hex 4 word).
     * index 0 = K0, ... , 14 = K14
     *
     * @return array<int,string>
     */
    public static function roundKeysHex(string $key32): array
    {
        if (strlen($key32) !== 32) {
            throw new \InvalidArgumentException('Key harus 32 byte (AES-256)');
        }
        $w = self::keyExpansion256($key32);
        $out = [];
        for ($r = 0; $r <= 14; $r++) {
            $words = [];
            for ($c = 0; $c < 4; $c++) {
                $wd = $w[4 * $r + $c]; // 4 byte
                $words[] = sprintf('%02X%02X%02X%02X', $wd[0], $wd[1], $wd[2], $wd[3]);
            }
            $out[$r] = implode(' ', $words); // "XXXX XXXX XXXX XXXX"
        }

        return $out;
    }

    /* =========================================================
     * 3) BARU: tracePerRound() → JELAS per-round (Input, SB, SR, MC?, ARK + RK-i)
     *    Opsional $iv: bila diisi, Input = P ⊕ IV (konteks CBC).
     * ========================================================= */
    /**
     * Trace SATU round AES-256 dengan detail:
     *  - Input (state sebelum round ini): untuk r=0 adalah (P atau P⊕IV), untuk r>0 adalah state sesudah ARK round sebelumnya
     *  - SubBytes, ShiftRows, (MixColumns), AddRoundKey
     *  - RK index yang dipakai: r (ARK round ke-r), dan hex K_r
     *
     * @param  string  $block16  16 byte plaintext blok (sesudah padding)
     * @param  string  $key32  32 byte AES-256 key (keyEnc)
     * @param  int  $round  0..14
     * @param  string|null  $iv  16 byte (opsional). Jika diisi → Input awal = P⊕IV
     * @return array{
     *   round:int,
     *   rk_index:int,
     *   rk_hex:string,
     *   input_source:string,
     *   input_state:string,
     *   subbytes?:string,
     *   shiftrows?:string,
     *   mixcolumns?:string,
     *   addroundkey:string
     * }
     */
    public static function tracePerRound(string $block16, string $key32, int $round, ?string $iv = null): array
    {
        if ($round < 0 || $round > 14) {
            throw new \InvalidArgumentException('round harus 0..14');
        }
        if (strlen($block16) !== 16) {
            throw new \InvalidArgumentException('Blok harus 16 byte');
        }
        if (strlen($key32) !== 32) {
            throw new \InvalidArgumentException('Key harus 32 byte');
        }
        if ($iv !== null && strlen($iv) !== 16) {
            throw new \InvalidArgumentException('IV harus 16 byte');
        }

        // 1) siapkan state awal (dengan konteks CBC bila $iv diberikan)
        $inputSource = ($iv === null) ? 'Input=P (ECB/tracer)' : 'Input=X=P⊕IV (CBC)';
        $blockForAES = ($iv === null) ? $block16 : ($block16 ^ $iv);

        $w = self::keyExpansion256($key32);
        $rkHexAll = self::roundKeysHex($key32);

        // advance state sampai awal round yang diminta
        $s = self::bytesToState($blockForAES);

        // Round 0: Input adalah sebelum ARK(K0)
        // Untuk round >0, kita jalankan round sebelumnya penuh agar "input" round ini benar.
        // Jalankan ARK(0) dulu (initial whitening), lalu r=1..(round-1)
        self::addRoundKey($s, $w, 0);
        for ($r = 1; $r < $round; $r++) {
            self::subBytes($s);
            self::shiftRows($s);
            if ($r <= 13) {
                self::mixColumns($s);
            }
            self::addRoundKey($s, $w, $r);
        }

        // Siapkan output detail untuk round yang diminta
        $out = [
            'round' => $round,
            'rk_index' => $round,                   // RK-i yang dipakai di ARK pada round ini
            'rk_hex' => $rkHexAll[$round] ?? '(n/a)',
            'input_source' => $inputSource,
            'input_state' => null,
            'addroundkey' => null,
        ];

        // Rekonstruksi "input state" round ini:
        // - Untuk r=0, input = (P atau P⊕IV) sebelum ARK(0)
        // - Untuk r>=1, input = state SETELAH ARK(round-1)
        if ($round === 0) {
            $s0 = self::bytesToState($blockForAES);    // sebelum ARK(0)
            $out['input_state'] = self::stateToHex($s0);
            // Round 0 hanya ARK(K0)
            self::addRoundKey($s0, $w, 0);
            $out['addroundkey'] = self::stateToHex($s0);

            return $out;
        }

        // round >= 1:
        // state $s saat ini sudah berada di "setelah ARK(round-1)"
        $out['input_state'] = self::stateToHex($s);

        // langkah round ini:
        self::subBytes($s);
        $out['subbytes'] = self::stateToHex($s);
        self::shiftRows($s);
        $out['shiftrows'] = self::stateToHex($s);
        if ($round <= 13) {
            self::mixColumns($s);
            $out['mixcolumns'] = self::stateToHex($s);
        }
        self::addRoundKey($s, $w, $round);
        $out['addroundkey'] = self::stateToHex($s);

        return $out;
    }

    /* =========================================================
     * 4) BARU: traceAllRoundsDetailed() → array per-round (0..14)
     *    (memakai format yang sama seperti tracePerRound)
     * ========================================================= */
    /**
     * @return array<int,array<string,string|int|null>>
     */
    public static function traceAllRoundsDetailed(string $block16, string $key32, ?string $iv = null): array
    {
        $all = [];
        for ($r = 0; $r <= 14; $r++) {
            $all[] = self::tracePerRound($block16, $key32, $r, $iv);
        }

        return $all;
    }
}
