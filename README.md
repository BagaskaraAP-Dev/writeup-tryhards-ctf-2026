# Writeup TryHards CTF: Tim Ruy

Repositori ini memuat dokumentasi penyelesaian (*writeup*) challenge Capture The Flag (CTF) dengan format flag resmi `TryHards{...}` yang dikerjakan oleh **Tim Ruy**.

- **Tim:** Tim Ruy
- **Pencipta / Penulis:** Mooncrust ([Bagaskara Amukti Palapa](https://github.com/BagaskaraAP-Dev))
- **Password Arsip Soal:** `tryhards`

---

## Daftar Challenge yang Berhasil Diselesaikan

| No | Challenge | Kategori | Flag | Writeup |
|:---:|---|---|---|:---:|
| 1 | A Flag for Two Bucks | Reverse Engineering | `TryHards{r3v3r53_D_p4wn_sh0p_l0g1c1337}` | [Baca Writeup](A-Flag-for-Two-Bucks/README.md) |
| 2 | FlagChecker | Reverse Engineering | `TryHards{https://youtu.be/k4V3Mo61fJM?si=eNDAJecKDMhedHnU&t=25}` | [Baca Writeup](FlagChecker/README.md) |
| 3 | Kept Inside | Forensics / Network | `TryHards{4n_t01_tru0c_g0k4n4_r4m3n_t3pp4n}` | [Baca Writeup](Kept-Inside/README.md) |
| 4 | lotu5 | Cryptography / Video | `TryHards{lotu5_i_spy_through_the_frames}` | [Baca Writeup](lotu5/README.md) |

---

## Ringkasan Teknis Solved Challenges

### 1. A Flag for Two Bucks
- **Kategori:** Reverse Engineering
- **Vulnerability / Inti:** Binary ELF 64-bit stripped dengan fungsi hashing state 32-bit kustom per 2 karakter input.
- **Solusi:** Analisis konstanta perkalian pada instruksi assembly, rekonstruksi state transformation di Python, lalu eksekusi pencarian karakter cetak ASCII yang memadankan 39 byte nilai target.
- **File:** [A-Flag-for-Two-Bucks/solve.py](A-Flag-for-Two-Bucks/solve.py)

### 2. FlagChecker
- **Kategori:** Reverse Engineering
- **Vulnerability / Inti:** Binary Linux ELF yang dikompresi dengan UPX dan dibangun menggunakan .NET Native AOT (`FlagChecker.dll`).
- **Solusi:** Unpacking layer UPX, dekompilasi dan analisis alur validasi input Native AOT yang menghasilkan respons `:)`.
- **File:** [FlagChecker/README.md](FlagChecker/README.md)

### 3. Kept Inside
- **Kategori:** Forensics / Network Forensics
- **Vulnerability / Inti:** File PCAP didominasi 13.000+ paket DNS sebagai noise. Transaksi HTTP port 80 memuat dokumen PDF menu restoran dan transmisi state terenkripsi.
- **Solusi:** Ekstraksi passphrase `sumo-broth-2026` dari PDF, derivasi kunci SHA-256, dan dekripsi AES-256-CBC terhadap payload POST `/control` dan respons GET `/status`.
- **File:** [Kept-Inside/solve.py](Kept-Inside/solve.py)

### 4. lotu5
- **Kategori:** Cryptography / Video Steganography
- **Vulnerability / Inti:** File video MP4 640 frame (24 FPS) dengan visual background noise. Pojok kanan bawah menampilkan QR code yang berganti setiap 16 frame.
- **Solusi:** Pemrosesan sekuensial 40 segmen QR code menggunakan `cv2.QRCodeDetector()` dari OpenCV untuk menyatukan 40 karakter flag secara utuh.
- **File:** [lotu5/solve.py](lotu5/solve.py)

---

## Catatan Challenge dalam Proses (Partial Solves)

Untuk menjaga akurasi dokumentasi dan menghindari flag fiktif, challenge berikut dicatat status analisisnya:

| Challenge | Kategori | Status Analisis | Lokasi |
|---|---|---|---|
| Tropical Island | Cryptography | Exploit tropical polynomial signature malleability terverifikasi lokal (10/10 voucher); flag server remote belum tersimpan | [partial/Tropical-Island](partial/Tropical-Island/README.md) |
| Will Call | Cryptography / ECDSA | Pemulihan kunci private window via relasi nonce kuadratik berhasil membuka pintu staff; tahap allaccess / box office belum terpecahkan | [partial/Will-Call](partial/Will-Call/README.md) |

---

## Dependensi Solver

Semua script solver ditulis menggunakan Python 3. Paket dependensi yang dibutuhkan:

```bash
pip install opencv-python cryptography pwntools sympy
```
