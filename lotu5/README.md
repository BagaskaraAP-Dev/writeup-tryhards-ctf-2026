# lotu5: Writeup

| Parameter | Keterangan |
| --- | --- |
| Soal | lotu5 |
| Kategori | Cryptography / Video Steganography |
| Poin | 147 |
| File Soal | `lotu5.zip` |
| Video Target | `lotu5.mp4` |
| Password Arsip | `tryhards` |
| Format Flag | `TryHards{...}` |
| Flag | `TryHards{lotu5_i_spy_through_the_frames}` |
| Status | Solved (terverifikasi ekstraksi frame video) |

## Deskripsi Soal

> A noisy signal archive contains a message hidden in its frame-to-frame changes. Recover the sequence and submit the flag.
>
> Archive password: tryhards

Tantangan mengarahkan pencarian data rahasia pada dinamika perubahan antar-frame dari sebuah rekaman video.

## 1. Identifikasi dan Ekstraksi File

Ekstrak arsip:

```bash
unzip -P tryhards lotu5.zip
```

Dua file yang diperoleh:
- `README.txt` (instruksi pengulangan)
- `lotu5.mp4` (file video utama)

Karakteristik teknis `lotu5.mp4`:
- Resolusi: 640x360 piksel
- Kecepatan: 24 FPS
- Total frame: 640 frame
- Durasi: ~26,67 detik

## 2. Analisis Perubahan Frame

Pemeriksaan visual video menunjukkan latar belakang penuh noise dinamis. Di sudut kanan bawah (koordinat vertikal 215-360, horizontal 440-630) terdapat barcode QR code yang berubah secara berkala.

Periode pergantian QR code:
- Interval: setiap 16 frame
- Jumlah karakter total: 640 / 16 = 40 karakter
- Setiap QR code menyandikan 1 karakter penyusun flag.

## 3. Ekstraksi Otomatis dengan OpenCV

Untuk memproses 640 frame tanpa kesalahan manual, ekstraksi dilakukan menggunakan `cv2.QRCodeDetector()` dari OpenCV. Program memotong area pojok kanan bawah, membaca payload QR code saat berganti, lalu menyusunnya secara sekuensial.

Eksekusi solver:

```bash
python3 solve.py lotu5.mp4
```

Hasil eksekusi:

```text
Total frame diproses: 640
Karakter ditemukan: 40
Flag: TryHards{lotu5_i_spy_through_the_frames}
```

## 4. Flag

Flag lengkap yang dipulihkan:

```text
TryHards{lotu5_i_spy_through_the_frames}
```
