# Kelompok 1 - Sistem Kriptografi Terintegrasi (AES-256-CBC & HMAC-SHA256)

Proyek ini mendemonstrasikan implementasi **Metode Kriptografi Modern** menggunakan standar industri untuk mengamankan data pengguna dan komunikasi chat. Fokus utama adalah pada kerahasiaan (*Confidentiality*), integritas (*Integrity*), dan keaslian (*Authenticity*).

## Spesifikasi Metode Kriptografi

| Komponen | Algoritma / Metode | Detail Teknik |
| :--- | :--- | :--- |
| **Cipher** | **AES-256-CBC** | Advanced Encryption Standard dengan kunci 256-bit dan mode CBC. |
| **Integritas** | **HMAC-SHA256** | Hash-based Message Authentication Code untuk mencegah manipulasi. |
| **Konstruksi** | **Encrypt-then-MAC (EtM)** | Menghitung MAC dari ciphertext (Standar Keamanan Tertinggi). |
| **Key Derivation** | **PBKDF2-SHA256** | Penguatan password dengan **210.000 iterasi** + Salt unik. |
| **Key Splitting** | **HKDF** | Memisahkan kunci enkripsi dan kunci MAC dari satu master key. |

---

## Logika & Flow Kriptografi

### 1. Mengapa Ciphertext "Hanya" Terlihat 16-Byte?
Salah satu fitur unik dalam sistem ini adalah penggunaan **16-Byte Reference ID** (32 karakter hex).

- **Root Folder & ID**: Saat data disimpan, sistem menghasilkan hash 16-byte dari ciphertext. Hash ini berfungsi sebagai "Root Folder Pointer" dan nama file.
- **Abstraksi Payload**: Apa yang Anda lihat di dashboard (misal: `🔒 bfc50ca0...`) adalah **Value Pointer** yang diambil dari metadata JSON.
- **Keunggulan Keamanan**:
    - **Panjang Tetap**: Apapun panjang pesan aslinya, ID/Pointer yang tampil selalu 16-byte. Ini mencegah penyerang mengetahui ukuran data asli (*Traffic Analysis Resistance*).
    - **Indireksi & Verifikasi**: User yang tidak memiliki otoritas hanya melihat ID acak tanpa pola. Sistem melakukan verifikasi ketat antara metadata `.json` dan payload `.dat` menggunakan pointer `value` tersebut. Jika pointer ini dimanipulasi (misal: di-null), proses dekripsi akan ditolak.

### 2. Mekanisme Encrypt-then-MAC (EtM)
Sistem ini menggunakan alur EtM yang direkomendasikan secara kriptografis:
1.  **Enkripsi**: Data diubah menjadi ciphertext menggunakan AES-256-CBC.
2.  **Otentikasi**: Ciphertext + IV dimasukkan ke dalam mesin HMAC untuk menghasilkan "Segel Integritas".
3.  **Verifikasi Ketat**: Saat proses dekripsi, sistem akan memeriksa MAC **terlebih dahulu**. Jika ada perubahan data walau 1 bit (Tampering), sistem akan menolak proses sebelum fungsi dekripsi dijalankan. Ini mencegah serangan *Padding Oracle*.

### 3. Arsitektur Penyimpanan Terfragmentasi
Untuk meningkatkan keamanan fisik data, kami membagi penyimpanan menjadi dua bagian:
- **File Metadata (`.json`)**: Berisi IV, MAC, dan ID referensi.
- **File Payload (`.dat`)**: Berisi **ciphertext biner asli (Raw AES-256-CBC)**. Data ini adalah hasil langsung dari algoritma enkripsi tanpa pembungkus tambahan, sehingga dapat diverifikasi menggunakan alat standar industri seperti OpenSSL CLI (asalkan kunci dan IV diketahui).
- **Directory Splitting**: Folder dibagi secara otomatis (000, 001, dst) untuk performa dan menyulitkan pelacakan manual jika folder diintip secara langsung.

#### Struktur & Field Metadata JSON
Berikut adalah penjelasan fungsi setiap field dalam file `.json` metadata:

| Field | Deskripsi | Peran dalam Sistem |
| :--- | :--- | :--- |
| `_id` | Unique ID 16-byte (32 char hex). | Berfungsi sebagai nama file dan pointer referensi data di disk. |
| `iv` | Initialization Vector (Base64Url). | Vektor acak 16-byte yang memastikan ciphertext selalu unik meskipun plaintext sama. |
| `mac` | Message Authentication Code. | Tag integritas HMAC-SHA256 untuk memvalidasi bahwa data tidak diubah (anti-tamper). |
| `value` | Pointer Payload (Base64Url). | Berisi pointer ID referensi yang diverifikasi secara ketat untuk mengambil payload asli dari file `.dat`. |
| `meta` | Objek Metadata Tambahan. | Menyimpan konteks data seperti pengirim, penerima, dan parameter algoritma. |
| `meta.userUuid` | UUID Pengirim. | Identitas unik pengirim pesan untuk keperluan filter privasi dan mapping nama. |
| `meta.targetUuid` | UUID Penerima (Null/ID). | Menentukan audiens pesan. Jika `null`, pesan bersifat publik (Global). |
| `meta.kdf` | Key Derivation Function. | Informasi algoritma yang digunakan untuk menurunkan kunci dari password. |
| `meta.kdf.alg` | Nama Algoritma KDF. | Menggunakan `pbkdf2-sha256` untuk penguatan password yang aman. |
| `meta.kdf.salt` | Salt (Base64Url). | Nilai acak unik agar hasil hash password berbeda untuk setiap pesan. |
| `meta.kdf.iter` | Jumlah Iterasi. | Diset pada **210.000 kali** untuk mencegah serangan brute-force secara efektif. |

### 4. Definisi & Logika Pointer 16-Byte
Pointer dalam sistem ini adalah **Reference ID** yang digunakan untuk menghubungkan metadata kontrol dengan payload ciphertext asli.

#### Mengapa Harus 16-Byte (32 Karakter Hex)?
1.  **Anonimitas & Privasi**: ID ini tidak memiliki kaitan logis dengan isi pesan. Seseorang yang melihat folder penyimpanan hanya melihat deretan karakter acak tanpa mengetahui ukuran atau jenis data di dalamnya.
2.  **Panjang Tetap (Fixed Length)**: Menghasilkan tampilan UI yang seragam dan mencegah *Traffic Analysis* (analisis ukuran data).
3.  **Unique File Identifier**: Digunakan sebagai nama file `.json` dan `.dat` serta menentukan struktur folder (*Directory Splitting*).

#### Implementasi dalam Kode (Functions)
Logika pointer ini tersebar di beberapa fungsi utama:

| Fungsi | File | Peran Pointer |
| :--- | :--- | :--- |
| `save(token)` | `FileSecureStorage.php` | Menghasilkan ID 16-byte menggunakan `substr(hash('sha256', ciphertext), 0, 32)` dan menyimpannya ke field `value`. |
| `load(id)` | `FileSecureStorage.php` | Mengambil data dari JSON, lalu memverifikasi apakah field `value` (pointer) cocok dengan ID file yang sedang diakses untuk mencegah manipulasi referensi. |
| `getFolderName(id)` | `FileSecureStorage.php` | Menggunakan urutan index ID untuk menentukan folder penyimpanan (000, 001, dst). |
| UI Rendering | `server.php` | Mengambil field `value` dari token untuk ditampilkan sebagai label `🔒 [Pointer ID]` di dashboard chat. |

---

## Bahan Presentasi: Transparansi Kriptografi
Sesuai dengan kebutuhan audit akademis, sistem ini menjamin:
1. **Integritas Data Mentah**: File `.dat` menyimpan data yang sepenuhnya sesuai dengan standar **NIST FIPS 197 (AES)**.
2. **Keterlacakan**: Metadata `.json` menyediakan IV dan MAC yang diperlukan untuk membuktikan keaslian ciphertext tersebut.
3. **Audit**: Dosen atau penguji dapat memvalidasi bahwa sistem tidak melakukan "obfuscation" tambahan pada data rahasia selain dari proses enkripsi standar.
4. **Database Explorer**: Fitur visualisasi data di `/database` untuk mempermudah presentasi data JSON dan biner DAT langsung dari browser.

## Fitur Keamanan Tambahan
- **Encrypted Username**: Username tidak disimpan sebagai teks biasa, melainkan dienkripsi di level storage menggunakan App Key.
- **RAM-Only Policy**: Kunci dekripsi chat disimpan dalam RAM browser (JavaScript Variable) dan tidak pernah menyentuh Storage/Cookies. Segera hilang saat refresh.
- **Isolasi Pesan**: Metadata penerima (`targetUuid`) ikut dilindungi oleh HMAC, memastikan pesan privat tidak bisa "diintip" ID-nya oleh user lain.

## Panduan Penggunaan

### Instalasi & Menjalankan
1.  **Install Dependensi**: `composer install`
2.  **Jalankan Server**: `php server.php start`
3.  **Akses UI**: `http://localhost:8000`

### Pengujian Keamanan (Tests)
Kami menyediakan suite pengujian otomatis untuk membuktikan kekuatan sistem:
```bash
php tests/run_tests.php
```
Test ini mencakup:
- **Positive Test**: Verifikasi enkripsi/dekripsi normal.
- **Anti-Tamper Test**: Simulasi peretasan file data (mengubah ciphertext atau MAC) dan membuktikan sistem menolaknya.
- **Visibility Test**: Memastikan pesan privat benar-benar terisolasi.

---
**Kelompok 1 - Cryptography Project 2026**
*Keamanan Tanpa Kompromi, Integritas Tanpa Celah.*
