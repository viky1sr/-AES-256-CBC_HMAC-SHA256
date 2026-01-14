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
- **Abstraksi Payload**: Apa yang Anda lihat di dashboard (misal: `🔒 bfc50ca0...`) **bukanlah** data rahasia aslinya, melainkan ID referensi.
- **Keunggulan Keamanan**:
    - **Panjang Tetap**: Apapun panjang pesan aslinya, ID yang tampil selalu 16-byte. Ini mencegah penyerang mengetahui ukuran data asli (*Traffic Analysis Resistance*).
    - **Indireksi**: User yang tidak memiliki otoritas hanya melihat ID acak tanpa pola, sedangkan payload asli tersimpan aman di file `.dat`.

### 2. Mekanisme Encrypt-then-MAC (EtM)
Sistem ini menggunakan alur EtM yang direkomendasikan secara kriptografis:
1.  **Enkripsi**: Data diubah menjadi ciphertext menggunakan AES-256-CBC.
2.  **Otentikasi**: Ciphertext + IV dimasukkan ke dalam mesin HMAC untuk menghasilkan "Segel Integritas".
3.  **Verifikasi Ketat**: Saat proses dekripsi, sistem akan memeriksa MAC **terlebih dahulu**. Jika ada perubahan data walau 1 bit (Tampering), sistem akan menolak proses sebelum fungsi dekripsi dijalankan. Ini mencegah serangan *Padding Oracle*.

### 3. Arsitektur Penyimpanan Terfragmentasi
Untuk meningkatkan keamanan fisik data, kami membagi penyimpanan menjadi dua bagian:
- **File Metadata (`.json`)**: Berisi IV, MAC, dan ID referensi.
- **File Payload (`.dat`)**: Berisi ciphertext asli yang dipisahkan dari metadatanya.
- **Directory Splitting**: Folder dibagi secara otomatis (000, 001, dst) untuk performa dan menyulitkan pelacakan manual jika folder diintip secara langsung.

---

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
