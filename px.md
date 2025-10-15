root@JMKSL-140:/home/visry/tugas_crytop# php cli/crypto.php

Kelompok1 Cryptography — AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)

┌ Pilih aksi: ─────────────────────────────────────────────────┐
│ 🧩 Trace All — per BLOCK × per ROUND (tabel per round)       │
└──────────────────────────────────────────────────────────────┘

┌ Plaintext (semua blok akan di-trace): ───────────────────────┐
│ abcdefghijklmnop                                             │
└──────────────────────────────────────────────────────────────┘

┌ Master key (teks): ──────────────────────────────────────────┐
│ •••••••                                                      │
└──────────────────────────────────────────────────────────────┘

📘 Kamus Simbol, Operator, Istilah (dibaca dulu ya!)

┌─────────────┬───────────────────────────────────────────────────────────────────────┐
│ Simbol/Term │ Arti                                                                  │
├─────────────┼───────────────────────────────────────────────────────────────────────┤
│ ⊕           │ XOR (exclusive OR) di notasi kriptografi (bitwise)                    │
│ ^           │ Operator XOR di PHP. Contoh: $x ^ $y                                  │
│ Hex digit   │ 1 digit hex = 4 bit = 1 nibble                                        │
│ Nibble      │ 4 bit (setengah byte)                                                 │
│ Byte        │ 8 bit = 2 digit hex (contoh: "AF")                                    │
│ Word        │ 32 bit = 4 byte = 8 digit hex (contoh: "08476B49")                    │
│ 4 word      │ 4 × 32 bit = 128 bit = 16 byte (RK-i satu round)                      │
│ State       │ Matriks 4×4 byte. Dicetak “row-wise hex, 16 bytes”                    │
│ P           │ Plaintext block (16 byte) setelah padding PKCS#7                      │
│ C           │ Ciphertext block (16 byte) hasil AES_Enc(X)                           │
│ IV          │ Initialization Vector 16 byte acak/unik untuk CBC (tidak rahasia)     │
│ X           │ Input state ke AES. Blok-1: X₁=P₁⊕IV; Blok-i>1: Xᵢ=Pᵢ⊕Cᵢ₋₁            │
│ S(b)        │ SubBytes: substitusi byte b via S-box (non-linear) → confusion        │
│ SB          │ SubBytes (pakai S-box)                                                │
│ SR          │ ShiftRows (rotasi baris: 0,1,2,3 kiri-siklik) → difusi                │
│ MC          │ MixColumns (matriks GF(2⁸)): campur kolom → difusi                    │
│ ARK         │ AddRoundKey: state ⊕ RK-i (XOR dengan round key indeks i)             │
│ RK-i        │ Round Key ke-i (K0..K14) dari key schedule AES-256 (tiap RK = 4 word) │
│ K0..K14     │ 16-byte key per round (4 word). K0 dipakai di “Round 0/whitening”     │
│ Whitening   │ AddRoundKey awal (Round 0)                                            │
│ Confusion   │ Menutupi relasi kunci-plaintext (SubBytes)                            │
│ Difusi      │ Menyebar perubahan ke seluruh state (ShiftRows + MixColumns)          │
│ GF(2⁸)      │ Ruang bilangan biner 8-bit; operasi MC dilakukan di sini              │
│ xtime(x)    │ Perkalian x dengan 02 di GF(2⁸) (dengan reduksi polinomial)           │
│ 02⊗x        │ Sama dengan xtime(x)                                                  │
│ 03⊗x        │ xtime(x) ⊕ x                                                          │
│ ECB         │ AES-ECB (dipakai internal tracer; bukan mode produksi)                │
│ CBC         │ Cipher Block Chaining: X = P ⊕ (IV atau Cprev)                        │
│ Row-wise    │ Cara cetak state per baris (untuk tampilan saja)                      │
└─────────────┴───────────────────────────────────────────────────────────────────────┘

🔎 Ilustrasi Hex/Word (biar gak rancu bit vs byte)

┌─────────────────────────────────────┬─────────────────────────────────────────────────────────────────────────────┐
│ Contoh                              │ Penjelasan                                                                  │
├─────────────────────────────────────┼─────────────────────────────────────────────────────────────────────────────┤
│ 08476B49                            │ 8 digit hex = 32 bit = 4 byte → 1 word (AddRoundKey kolom tunggal)          │
│ 04C0DD9A C66248DA 40C20464 08476B49 │ 4 word (masing-masing 8 digit hex) = 16 byte = 128 bit → RK-i untuk 1 round │
│ AF                                  │ 2 digit hex = 1 byte = 8 bit                                                │
│ 04 C0                               │ 2 byte (04 dan C0) = 16 bit (ini BUKAN 1 word; 1 word butuh 4 byte)         │
└─────────────────────────────────────┴─────────────────────────────────────────────────────────────────────────────┘

📐 Rangkuman Langkah Round & Rumus

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
ℹ️ Diagnostik Panjang/Blok (input kamu)

┌──────────────────────────┬───────────┐
│ Kunci                    │ Nilai     │
├──────────────────────────┼───────────┤
│ Panjang plaintext (byte) │ 16        │
│ Nilai padding (PKCS#7)   │ 16 (0x10) │
│ Total setelah padding    │ 32        │
│ Jumlah blok (16B/blok)   │ 2         │
└──────────────────────────┴───────────┘

📏 PKCS#7 Padding (AES block = 16 byte) — Contoh Panjang → Blok

┌──────────────────────────┬────────────────┬───────────────────┬─────────────┐
│ Panjang plaintext (byte) │ Padding (byte) │ Total setelah pad │ Jumlah blok │
├──────────────────────────┼────────────────┼───────────────────┼─────────────┤
│ 1                        │ 15             │ 16                │ 1           │
│ 15                       │ 1              │ 16                │ 1           │
│ 16                       │ 16             │ 32                │ 2           │
│ 17                       │ 15             │ 32                │ 2           │
│ 31                       │ 1              │ 32                │ 2           │
│ 32                       │ 16             │ 48                │ 3           │
│ 48                       │ 16             │ 64                │ 4           │
│ 100                      │ 12             │ 112               │ 7           │
└──────────────────────────┴────────────────┴───────────────────┴─────────────┘

Aturan PKCS#7: pad = 16 − (len % 16), namun bila len%16=0 maka pad=16 (tambah 1 blok penuh).
Jumlah blok = (len + pad) / 16.

Contoh efek (berdasarkan input kamu):
• len=16  → pad=16 ⇒ blok-2 = 0x10 × 16 (padding penuh)

🔎 Preview blok hasil padding (HEX)

┌─────────┬─────────────────────────────────────────────────┬────────────────────────────────────┐
│ Block   │ Hex (16B)                                       │ Keterangan                         │
├─────────┼─────────────────────────────────────────────────┼────────────────────────────────────┤
│ Block 1 │ 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 │                                    │
│ Block 2 │ 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 10 │ ← PKCS#7 padding murni (0x10 × 16) │
└─────────┴─────────────────────────────────────────────────┴────────────────────────────────────┘

🧊 Initialization Vector (IV) — hex

60FD 7BF1 100A B22C   0CE0 4623 023E 77B1
CBC chaining:
• Blok-1:  X₁ = P₁ ⊕ IV  → C₁ = AES_Enc(X₁)
• Blok-i:  Xᵢ = Pᵢ ⊕ Cᵢ₋₁ → Cᵢ = AES_Enc(Xᵢ)
IV 16B acak/unik, tidak rahasia namun JANGAN di-reuse untuk key yang sama.

🔑 Master Key & keyEnc (EDUKASI — JANGAN print di produksi)

┌────────────────────────────────────────────┬──────────────────────────────────────────────────────────────────┐
│ Label                                      │ Hex (32 byte)                                                    │
├────────────────────────────────────────────┼──────────────────────────────────────────────────────────────────┤
│ Master Key = SHA-256(pass)                 │ 8BB0CF6EB9B17D0F7D22B456F121257DC1254E1F01665370476383EA776DF414 │
│ keyEnc = HKDF(masterKey,"aes-256-cbc:enc") │ 971A24CC74D086B62A0210A3A5BBE70F449BB588B220975F7952EA113EBD97BF │
└────────────────────────────────────────────┴──────────────────────────────────────────────────────────────────┘

🧷 Round Key contoh (K0, K1, K14)

┌─────┬─────────────────────────────────────┐
│ RK  │ Hex (4 word)                        │
├─────┼─────────────────────────────────────┤
│ K0  │ 971A24CC 74D086B6 2A0210A3 A5BBE70F │
│ K1  │ 449BB588 B220975F 7952EA11 3EBD97BF │
│ K14 │ 66525211 FF062BA9 0B156869 DB32A0A6 │
└─────┴─────────────────────────────────────┘


📦 BLOCK 1/2 — Plaintext (Char→Hex)

┌──────┬─────┐
│ Char │ Hex │
├──────┼─────┤
│ a    │ 61  │
│ b    │ 62  │
│ c    │ 63  │
│ d    │ 64  │
│ e    │ 65  │
│ f    │ 66  │
│ g    │ 67  │
│ h    │ 68  │
│ i    │ 69  │
│ j    │ 6A  │
│ k    │ 6B  │
│ l    │ 6C  │
│ m    │ 6D  │
│ n    │ 6E  │
│ o    │ 6F  │
│ p    │ 70  │
└──────┴─────┘

🔗 BLOCK 1 — Chaining CBC

┌──────────────┬───────────────────────────────────────────┐
│ Label        │ Hex                                       │
├──────────────┼───────────────────────────────────────────┤
│ P            │ 6162 6364 6566 6768   696A 6B6C 6D6E 6F70 │
│ X=P⊕IV       │ 019F 1895 756C D544   658A 2D4F 6F50 18C1 │
│ C=AES_Enc(X) │ 52EA 860A A765 6442   7A98 66D3 E8DE E4EB │
└──────────────┴───────────────────────────────────────────┘

🧩 BLOCK 1 — ROUND 0 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 01 75 65 6F   9F 6C 8A 50   18 D5 2D 18   95 44 4F C1 │
│ AddRoundKey (RK-0) │ 96 01 4F CA   85 BC 88 EB   3C 53 3D FF   59 F2 EC CE │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 0**
Hex RK-i (4 word): 971A24CC 74D086B6 2A0210A3 A5BBE70F

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 1 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 96 01 4F CA   85 BC 88 EB   3C 53 3D FF   59 F2 EC CE │
│ SubBytes           │ 90 7C 84 74   97 65 C4 E9   EB ED 27 16   CB 89 CE 8B │
│ ShiftRows          │ 90 7C 84 74   65 C4 E9 97   27 16 EB ED   8B CB 89 CE │
│ MixColumns         │ 38 72 51 69   B8 1E E2 A3   3D D2 20 6B   E4 DB 9C 61 │
│ AddRoundKey (RK-1) │ 7C C0 28 57   23 3E B0 1E   88 45 CA FC   6C 84 8D DE │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 1**
Hex RK-i (4 word): 449BB588 B220975F 7952EA11 3EBD97BF

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 2 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 7C C0 28 57   23 3E B0 1E   88 45 CA FC   6C 84 8D DE │
│ SubBytes           │ 10 BA 34 5B   26 B2 E7 72   C4 6E 74 B0   50 5F 5D 1D │
│ ShiftRows          │ 10 BA 34 5B   B2 E7 72 26   74 B0 C4 6E   1D 50 5F 5D │
│ MixColumns         │ 84 BD 65 EF   EE F4 D8 F8   6D D6 34 46   CC 22 54 1F │
│ AddRoundKey (RK-2) │ 68 25 D7 F8   7C B6 98 03   41 7C 8E 1B   B2 EA 3F 7B │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 2**
Hex RK-i (4 word): EC922C7E 9842AAC8 B240BA6B 17FB5D64

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 3 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 68 25 D7 F8   7C B6 98 03   41 7C 8E 1B   B2 EA 3F 7B │
│ SubBytes           │ 45 3F 0E 41   10 4E 46 7B   83 10 19 AF   37 87 75 21 │
│ ShiftRows          │ 45 3F 0E 41   4E 46 7B 10   19 AF 83 10   21 37 87 75 │
│ MixColumns         │ 60 2C 95 D7   D3 6E E1 24   5A 65 FA EE   DA C6 FF 29 │
│ AddRoundKey (RK-3) │ D4 2A EA 96   47 DA 07 7F   A3 0B 7E FD   11 52 7A 13 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 3**
Hex RK-i (4 word): B494F9CB 06B46E94 7FE68485 415B133A

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 4 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ D4 2A EA 96   47 DA 07 7F   A3 0B 7E FD   11 52 7A 13 │
│ SubBytes           │ 48 E5 87 90   A0 57 C5 D2   0A 2B F3 54   82 00 DA 7D │
│ ShiftRows          │ 48 E5 87 90   57 C5 D2 A0   F3 54 0A 2B   7D 82 00 DA │
│ MixColumns         │ E7 53 72 31   95 0A 26 6C   65 15 41 13   86 BA 4A 8F │
│ AddRoundKey (RK-4) │ 30 1C 8F DB   7A A7 CB 7A   C9 13 FD F2   7B 8F 14 B5 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 4**
Hex RK-i (4 word): D7EFACFD 4FAD0635 FDEDBC5E EA16E13A

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 5 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 30 1C 8F DB   7A A7 CB 7A   C9 13 FD F2   7B 8F 14 B5 │
│ SubBytes           │ 04 9C 73 B9   DA 5C 1F DA   DD 7D 54 89   21 73 FA D5 │
│ ShiftRows          │ 04 9C 73 B9   5C 1F DA DA   54 89 DD 7D   D5 21 73 FA │
│ MixColumns         │ 6D AA 3D 9B   95 03 D3 6B   94 E9 9D 8C   B5 6B 74 98 │
│ AddRoundKey (RK-5) │ 5E 9F 77 90   46 64 52 B1   95 86 76 74   FE B4 2E F8 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 5**
Hex RK-i (4 word): 33D3014B 35676FDF 4A81EB5A 0BDAF860

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 6 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 5E 9F 77 90   46 64 52 B1   95 86 76 74   FE B4 2E F8 │
│ SubBytes           │ 58 DB F5 60   5A 43 00 C8   2A 44 38 92   BB 8D 31 41 │
│ ShiftRows          │ 58 DB F5 60   43 00 C8 5A   38 92 2A 44   41 BB 8D 31 │
│ MixColumns         │ 0C 84 15 5B   D7 CD 8D 29   A8 32 E5 E1   11 89 E7 DC │
│ AddRoundKey (RK-6) │ 88 4F 23 87   79 CE 63 D1   D4 48 23 C6   C7 6A 5A 5B │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 6**
Hex RK-i (4 word): 84AE7CD6 CB037AE3 36EEC6BD DCF82787

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 7 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 88 4F 23 87   79 CE 63 D1   D4 48 23 C6   C7 6A 5A 5B │
│ SubBytes           │ C4 84 26 17   B6 8B FB 3E   48 52 26 B4   C6 02 BE 39 │
│ ShiftRows          │ C4 84 26 17   8B FB 3E B6   26 B4 48 52   39 C6 02 BE │
│ MixColumns         │ 0A 77 44 03   9A 68 80 28   48 5D 8E DC   88 4F 18 BA │
│ AddRoundKey (RK-7) │ BF F7 8E C2   08 9D F4 86   85 FF C7 6D   D4 CC C1 03 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 7**
Hex RK-i (4 word): B592CD5C 80F5A283 CA7449D9 C1AEB1B9

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 8 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ BF F7 8E C2   08 9D F4 86   85 FF C7 6D   D4 CC C1 03 │
│ SubBytes           │ 08 68 19 25   30 5E BF 44   97 16 C6 3C   48 4B 78 7B │
│ ShiftRows          │ 08 68 19 25   5E BF 44 30   C6 3C 97 16   7B 48 4B 78 │
│ MixColumns         │ 4F 7E 22 74   9E 01 78 07   4C 77 B5 B1   76 AB 6E B9 │
│ AddRoundKey (RK-8) │ 27 DD B7 3D   F8 64 F3 74   66 27 23 00   D8 E6 9E CE │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 8**
Hex RK-i (4 word): 68662AAE A365504D 958B96F0 4973B177

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 9 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 27 DD B7 3D   F8 64 F3 74   66 27 23 00   D8 E6 9E CE │
│ SubBytes           │ CC C1 A9 27   41 43 0D 92   33 CC 26 63   61 8E 0B 8B │
│ ShiftRows          │ CC C1 A9 27   43 0D 92 41   26 63 33 CC   8B 61 8E 0B │
│ MixColumns         │ EB 8C 59 4A   AB 1F 4D E1   45 A9 D4 F8   27 F4 46 F2 │
│ AddRoundKey (RK-9) │ 65 82 9D 4F   B6 F7 D1 D3   40 0E 3A A7   8E DE B5 B8 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 9**
Hex RK-i (4 word): 8E1D05A9 0EE8A72A C49CEEF3 05325F4A

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 10 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ 65 82 9D 4F   B6 F7 D1 D3   40 0E 3A A7   8E DE B5 B8 │
│ SubBytes            │ 4D 13 5E 84   4E 68 3E 66   09 AB 80 5C   19 1D D5 6C │
│ ShiftRows           │ 4D 13 5E 84   68 3E 66 4E   80 5C 09 AB   6C 19 1D D5 │
│ MixColumns          │ CE 21 02 BF   6A 92 94 2B   8A BE 0D E3   E7 65 B7 C3 │
│ AddRoundKey (RK-10) │ 95 D9 6F 9B   C3 5E D3 1F   76 12 37 68   22 ED CF CC │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 10**
Hex RK-i (4 word): 5BA9FCC5 F8CCAC88 6D473A78 24348B0F

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 11 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ 95 D9 6F 9B   C3 5E D3 1F   76 12 37 68   22 ED CF CC │
│ SubBytes            │ 2A 35 A8 14   2E 58 66 C0   38 C9 9A 45   93 55 8A 4B │
│ ShiftRows           │ 2A 35 A8 14   58 66 C0 2E   9A 45 38 C9   4B 93 55 8A │
│ MixColumns          │ 6D 16 7D 19   64 A5 2E 82   80 77 E7 36   2A 41 B1 D4 │
│ AddRoundKey (RK-11) │ D5 A0 0F 6E   61 48 5F C1   B8 E8 96 18   F5 B4 B7 98 │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 11**
Hex RK-i (4 word): B80538DF B6ED9FF5 72717106 77432E4C

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 12 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ D5 A0 0F 6E   61 48 5F C1   B8 E8 96 18   F5 B4 B7 98 │
│ SubBytes            │ 03 E0 76 9F   EF 52 CF 78   6C 9B 90 AD   E6 8D A9 46 │
│ ShiftRows           │ 03 E0 76 9F   52 CF 78 EF   90 AD 6C 9B   46 E6 8D A9 │
│ MixColumns          │ 26 DA 85 3D   4A 6F BF 45   A0 5F 5A BD   4B 8E 8F 87 │
│ AddRoundKey (RK-12) │ 47 43 71 ED   D2 3B AC 62   75 26 19 75   7B 36 4F 48 │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 12**
Hex RK-i (4 word): 6198D530 995479B8 F41343C0 D027C8CF

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 13 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ 47 43 71 ED   D2 3B AC 62   75 26 19 75   7B 36 4F 48 │
│ SubBytes            │ A0 1A A3 55   B5 E2 91 AA   9D F7 D4 9D   21 05 84 52 │
│ ShiftRows           │ A0 1A A3 55   E2 91 AA B5   D4 9D 9D F7   52 21 05 84 │
│ MixColumns          │ E0 20 20 1D   4A BE 55 A2   07 C9 27 82   69 60 C3 AE │
│ AddRoundKey (RK-13) │ 28 5E 2C 66   83 9A 00 B4   D7 86 19 92   3C C0 65 44 │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 13**
Hex RK-i (4 word): C8C9D055 7E244FA0 0C553EA6 7B1610EA

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 1 — ROUND 14 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ 28 5E 2C 66   83 9A 00 B4   D7 86 19 92   3C C0 65 44 │
│ SubBytes            │ 34 58 71 33   EC B8 63 8D   0E 44 D4 4F   EB BA 4D 1B │
│ ShiftRows           │ 34 58 71 33   B8 63 8D EC   D4 4F 0E 44   1B EB BA 4D │
│ AddRoundKey (RK-14) │ 52 A7 7A E8   EA 65 98 DE   86 64 66 E4   0A 42 D3 EB │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 14**
Hex RK-i (4 word): 66525211 FF062BA9 0B156869 DB32A0A6

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.


📦 BLOCK 2/2 — Plaintext (Char→Hex)

┌──────┬─────┐
│ Char │ Hex │
├──────┼─────┤
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
│ \x10 │ 10  │
└──────┴─────┘

ℹ️ BLOCK 2 adalah blok PKCS#7 padding murni (byte 0x10 × 16).

🔗 BLOCK 2 — Chaining CBC

┌──────────────┬───────────────────────────────────────────┐
│ Label        │ Hex                                       │
├──────────────┼───────────────────────────────────────────┤
│ P            │ 1010 1010 1010 1010   1010 1010 1010 1010 │
│ X=P⊕Cprev    │ 42FA 961A B775 7452   6A88 76C3 F8CE F4FB │
│ C=AES_Enc(X) │ FD17 05A8 DCE9 A693   942E AE93 8882 3AE5 │
└──────────────┴───────────────────────────────────────────┘

🧩 BLOCK 2 — ROUND 0 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 42 B7 6A F8   FA 75 88 CE   96 74 76 F4   1A 52 C3 FB │
│ AddRoundKey (RK-0) │ D5 C3 40 5D   E0 A5 8A 75   B2 F2 66 13   D6 E4 60 F4 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 0**
Hex RK-i (4 word): 971A24CC 74D086B6 2A0210A3 A5BBE70F

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 1 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ D5 C3 40 5D   E0 A5 8A 75   B2 F2 66 13   D6 E4 60 F4 │
│ SubBytes           │ 03 2E 09 4C   E1 06 7E 9D   37 89 33 7D   F6 69 D0 BF │
│ ShiftRows          │ 03 2E 09 4C   06 7E 9D E1   33 7D 37 89   BF F6 69 D0 │
│ MixColumns         │ 80 55 F0 F9   E5 A3 18 C5   B9 AB 41 CF   55 86 63 07 │
│ AddRoundKey (RK-1) │ C4 E7 89 C7   7E 83 4A 78   0C 3C AB 58   DD D9 72 B8 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 1**
Hex RK-i (4 word): 449BB588 B220975F 7952EA11 3EBD97BF

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 2 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ C4 E7 89 C7   7E 83 4A 78   0C 3C AB 58   DD D9 72 B8 │
│ SubBytes           │ 1C 94 A7 C6   F3 EC D6 BC   FE EB 62 6A   C1 35 40 6C │
│ ShiftRows          │ 1C 94 A7 C6   EC D6 BC F3   62 6A FE EB   6C C1 35 40 │
│ MixColumns         │ 19 F9 41 32   15 5C E8 5D   80 CE A3 38   72 82 DA C9 │
│ AddRoundKey (RK-2) │ F5 61 F3 25   87 1E A8 A6   AC 64 19 65   0C 4A B1 AD │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 2**
Hex RK-i (4 word): EC922C7E 9842AAC8 B240BA6B 17FB5D64

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 3 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ F5 61 F3 25   87 1E A8 A6   AC 64 19 65   0C 4A B1 AD │
│ SubBytes           │ E6 EF 0D 3F   17 72 C2 24   91 43 D4 4D   FE D6 C8 95 │
│ ShiftRows          │ E6 EF 0D 3F   72 C2 24 17   D4 4D 91 43   95 FE D6 C8 │
│ MixColumns         │ 00 2B 31 CC   F0 59 3B 1C   83 AE 71 ED   A6 42 15 9E │
│ AddRoundKey (RK-3) │ B4 2D 4E 8D   64 ED DD 47   7A C0 F5 FE   6D D6 90 A4 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 3**
Hex RK-i (4 word): B494F9CB 06B46E94 7FE68485 415B133A

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 4 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ B4 2D 4E 8D   64 ED DD 47   7A C0 F5 FE   6D D6 90 A4 │
│ SubBytes           │ 8D D8 2F 5D   43 55 C1 A0   DA BA E6 BB   3C F6 60 49 │
│ ShiftRows          │ 8D D8 2F 5D   55 C1 A0 43   E6 BB DA BA   49 3C F6 60 │
│ MixColumns         │ 51 74 89 A5   5F AB F7 6E   D4 30 21 D1   AD 71 FC DE │
│ AddRoundKey (RK-4) │ 86 3B 74 4F   B0 06 1A 78   78 36 9D 30   50 44 A2 E4 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 4**
Hex RK-i (4 word): D7EFACFD 4FAD0635 FDEDBC5E EA16E13A

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 5 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 86 3B 74 4F   B0 06 1A 78   78 36 9D 30   50 44 A2 E4 │
│ SubBytes           │ 44 E2 92 84   E7 6F A2 BC   BC 05 5E 04   53 1B 3A 69 │
│ ShiftRows          │ 44 E2 92 84   6F A2 BC E7   5E 04 BC 05   69 53 1B 3A │
│ MixColumns         │ 0E 75 47 1E   11 E2 35 64   2C BD 60 27   2F 3D 9B 01 │
│ AddRoundKey (RK-5) │ 3D 40 0D 15   C2 85 B4 BE   2D D2 8B DF   64 E2 C1 61 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 5**
Hex RK-i (4 word): 33D3014B 35676FDF 4A81EB5A 0BDAF860

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 6 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 3D 40 0D 15   C2 85 B4 BE   2D D2 8B DF   64 E2 C1 61 │
│ SubBytes           │ 27 09 D7 59   25 97 8D AE   D8 B5 3D 9E   43 98 78 EF │
│ ShiftRows          │ 27 09 D7 59   97 8D AE 25   3D 9E D8 B5   EF 43 98 78 │
│ MixColumns         │ 3E 43 1C 10   BA F2 7B AF   E0 66 61 85   06 8E 3F 8B │
│ AddRoundKey (RK-6) │ BA 88 2A CC   14 F1 95 57   9C 1C A7 A2   D0 6D 82 0C │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 6**
Hex RK-i (4 word): 84AE7CD6 CB037AE3 36EEC6BD DCF82787

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 7 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ BA 88 2A CC   14 F1 95 57   9C 1C A7 A2   D0 6D 82 0C │
│ SubBytes           │ F4 C4 E5 4B   FA A1 2A 5B   DE 9C 5C 3A   70 3C 13 FE │
│ ShiftRows          │ F4 C4 E5 4B   A1 2A 5B FA   5C 3A DE 9C   FE 70 3C 13 │
│ MixColumns         │ A9 A7 DE 0C   B7 AE 16 08   F4 0A 5D A7   1D A7 C9 9D │
│ AddRoundKey (RK-7) │ 1C 27 14 CD   25 5B 62 A6   39 A8 14 16   41 24 10 24 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 7**
Hex RK-i (4 word): B592CD5C 80F5A283 CA7449D9 C1AEB1B9

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 8 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ 1C 27 14 CD   25 5B 62 A6   39 A8 14 16   41 24 10 24 │
│ SubBytes           │ 9C CC FA BD   3F 39 AA 24   12 C2 FA 47   83 36 CA 36 │
│ ShiftRows          │ 9C CC FA BD   39 AA 24 3F   FA 47 12 C2   36 83 36 CA │
│ MixColumns         │ A4 A2 A7 28   CD C9 B2 54   10 76 A0 58   10 BF 4F AE │
│ AddRoundKey (RK-8) │ CC 01 32 61   AB AC 39 27   3A 26 36 E9   BE F2 BF D9 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 8**
Hex RK-i (4 word): 68662AAE A365504D 958B96F0 4973B177

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 9 — Langkah

┌────────────────────┬───────────────────────────────────────────────────────┐
│ Step               │ State (row-wise hex, 16 bytes)                        │
├────────────────────┼───────────────────────────────────────────────────────┤
│ Input source       │ Input=X=P⊕IV (CBC)                                    │
│ Input              │ CC 01 32 61   AB AC 39 27   3A 26 36 E9   BE F2 BF D9 │
│ SubBytes           │ 4B 7C 23 EF   62 91 12 CC   80 F7 05 1E   AE 89 08 35 │
│ ShiftRows          │ 4B 7C 23 EF   91 12 CC 62   05 1E 80 F7   35 AE 89 08 │
│ MixColumns         │ 0E 7E 00 9C   48 D4 B2 21   8F BB 74 60   23 CF 20 AF │
│ AddRoundKey (RK-9) │ 80 70 C4 99   55 3C 2E 13   8A 1C 9A 3F   8A E5 D3 E5 │
└────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 9**
Hex RK-i (4 word): 8E1D05A9 0EE8A72A C49CEEF3 05325F4A

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 10 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ 80 70 C4 99   55 3C 2E 13   8A 1C 9A 3F   8A E5 D3 E5 │
│ SubBytes            │ CD 51 1C EE   FC EB 31 7D   7E 9C B8 75   7E D9 66 D9 │
│ ShiftRows           │ CD 51 1C EE   EB 31 7D FC   B8 75 7E 9C   D9 7E D9 66 │
│ MixColumns          │ C6 FA 18 22   0A D2 BD D4   3D 08 ED 9B   B6 4B 8E 85 │
│ AddRoundKey (RK-10) │ 9D 02 75 06   A3 1E FA E0   C1 A4 D7 10   73 C3 F6 8A │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 10**
Hex RK-i (4 word): 5BA9FCC5 F8CCAC88 6D473A78 24348B0F

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 11 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ 9D 02 75 06   A3 1E FA E0   C1 A4 D7 10   73 C3 F6 8A │
│ SubBytes            │ 5E 77 9D 6F   0A 72 2D E1   78 49 0E CA   8F 2E 42 7E │
│ ShiftRows           │ 5E 77 9D 6F   72 2D E1 0A   0E CA 78 49   7E 8F 2E 42 │
│ MixColumns          │ 5A DC 4F CB   D6 E7 E2 E2   B2 5F FE 31   62 7B 79 76 │
│ AddRoundKey (RK-11) │ E2 6A 3D BC   D3 0A 93 A1   8A C0 8F 1F   BD 8E 7F 3A │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 11**
Hex RK-i (4 word): B80538DF B6ED9FF5 72717106 77432E4C

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 12 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ E2 6A 3D BC   D3 0A 93 A1   8A C0 8F 1F   BD 8E 7F 3A │
│ SubBytes            │ 98 02 27 65   66 67 DC 32   7E BA 73 C0   7A 19 D2 80 │
│ ShiftRows           │ 98 02 27 65   67 DC 32 66   73 C0 7E BA   80 7A 19 D2 │
│ MixColumns          │ 71 C1 7F 08   43 80 D8 AE   82 CB C2 01   BC EE 17 CC │
│ AddRoundKey (RK-12) │ 10 58 8B D8   DB D4 CB 89   57 B2 81 C9   8C 56 D7 03 │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 12**
Hex RK-i (4 word): 6198D530 995479B8 F41343C0 D027C8CF

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 13 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ 10 58 8B D8   DB D4 CB 89   57 B2 81 C9   8C 56 D7 03 │
│ SubBytes            │ CA 6A 3D 61   B9 48 1F A7   5B 37 0C DD   64 B1 0E 7B │
│ ShiftRows           │ CA 6A 3D 61   48 1F A7 B9   0C DD 5B 37   7B 64 B1 0E │
│ MixColumns          │ 20 4C 62 2B   35 4C 34 5F   17 78 E4 A4   F7 B4 C2 31 │
│ AddRoundKey (RK-13) │ E8 32 6E 50   FC 68 61 49   C7 37 DA B4   A2 14 64 DB │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 13**
Hex RK-i (4 word): C8C9D055 7E244FA0 0C553EA6 7B1610EA

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

🧩 BLOCK 2 — ROUND 14 — Langkah

┌─────────────────────┬───────────────────────────────────────────────────────┐
│ Step                │ State (row-wise hex, 16 bytes)                        │
├─────────────────────┼───────────────────────────────────────────────────────┤
│ Input source        │ Input=X=P⊕IV (CBC)                                    │
│ Input               │ E8 32 6E 50   FC 68 61 49   C7 37 DA B4   A2 14 64 DB │
│ SubBytes            │ 9B 23 9F 53   B0 45 EF 3B   C6 9A 57 8D   3A FA 43 B9 │
│ ShiftRows           │ 9B 23 9F 53   45 EF 3B B0   57 8D C6 9A   B9 3A FA 43 │
│ AddRoundKey (RK-14) │ FD DC 94 88   17 E9 2E 82   05 A6 AE 3A   A8 93 93 E5 │
└─────────────────────┴───────────────────────────────────────────────────────┘

RK-i dipakai pada ARK round ini: **i = 14**
Hex RK-i (4 word): 66525211 FF062BA9 0B156869 DB32A0A6

Catatan HEX:
• Semua state dicetak sebagai “row-wise hex, 16 bytes”.
• 2 digit hex = 1 byte (8 bit). Contoh: 'AF' = 1 byte.
• 8 digit hex = 1 word (32 bit = 4 byte). Contoh: '08476B49' = 1 word.
• 4 word = 16 byte (128 bit) = Round Key (RK-i) untuk 1 round.
• AddRoundKey: setiap kolom state (4 byte) di-XOR dengan 1 word dari RK-i.
• Notasi: ⊕ = XOR (kriptografi), '^' = operator XOR di PHP.

Konsep: SB → confusion (non-linear), SR+MC → difusi (penyebaran bit).

Selesai. 🙌

root@JMKSL-140:/home/visry/tugas_crytop# 