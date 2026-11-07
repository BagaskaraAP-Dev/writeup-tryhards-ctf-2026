# Will Call: Writeup (Partial Solve)

| Parameter | Keterangan |
| --- | --- |
| Soal | Will Call |
| Kategori | Cryptography / ECDSA |
| Target Layanan | `109.123.232.54:1344` (TCP) |
| File Soal | `will-call.zip` |
| Password Arsip | `tryhards` |
| Status | Partial Solve (tier staff terbuka via pemulihan kunci window, tier allaccess belum terpecahkan) |

## Deskripsi Soal

Layanan Will Call menerbitkan pass dengan tingkatan `tier=ga` yang ditandatangani menggunakan kurva secp256k1 dan hash SHA-256. Pass `tier=staff` membuka antrean quote, sementara pass `tier=allaccess` membuka pintu backstage yang memuat flag.

## 1. Analisis Tahap 1: Relasi Kuadratik Nonce Window

Pada layanan awal, generator nonce memenuhi hubungan polinomial kuadratik:

$$ k_{i+1} = a k_i^2 + b k_i + c \pmod n $$

Dengan mengumpulkan 6 signature ECDSA berurutan, relasi tersebut menghasilkan sistem persamaan polinomial yang dapat direduksi menggunakan Resultant / GCD di medan $\mathbb{F}_n$ untuk memulihkan private key window.

Dengan private key window, pass `name=solver&tier=staff` dapat dipalsukan dan berhasil membuka pintu staff:

```text
[+] 6 window signatures received
[+] Window private key recovered
[+] staff door opens. The box office is awake.
```

## 2. Status Tahap 2: Box Office

Setelah tahap staff terbuka, layanan menggunakan kunci terpisah (`box_pub`) dan implementasi nonce tidak disertakan dalam arsip soal. Pendekatan Hidden Number Problem (HNP) dan lattice reduction (LLL) pada 80 quote yang dikumpulkan belum menemukan private key box office.

Script `will_call_auto_v4.py` mengintegrasikan alur otomatis hingga tahap pemulihan staff.
