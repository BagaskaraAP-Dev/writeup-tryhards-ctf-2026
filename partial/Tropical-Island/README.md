# Tropical Island: Writeup (Partial Solve)

| Parameter | Keterangan |
| --- | --- |
| Soal | Tropical Island |
| Kategori | Cryptography |
| Target Layanan | `109.123.232.54:4003` (TCP) |
| File Soal | `chall.py`, `tropical.py` |
| Password Arsip | `tryhards` |
| Status | Partial Solve (exploit aljabar diverifikasi lokal, flag remote belum tersimpan) |

## Deskripsi Soal

> This is your chance to get your tropical island vacation voucher - enjoy the unusual feeling of being in an unusual place.

Layanan memberikan satu voucher $10 secara gratis. Pemain diminta mengumpulkan saldo $100 untuk mendapatkan kode liburan (flag), namun opsi pengambilan voucher gratis hanya diizinkan satu kali per sesi koneksi.

## 1. Analisis Kerentanan: Tropical Polynomial Malleability

Voucher tersusun atas 3 polinomial `(A, B, N)` yang diserialisasi ke JSON lalu di-encode dengan Base64. Operasi perkalian polinomial tropis menggunakan aljabar min-plus:

$$ (F \otimes G)_t = \min_{i+j=t} (F_i + G_j) $$

Jika koefisien polinomial $F$ digeser sebesar konstanta $k$, maka:

$$ (F+k) \otimes (G+\ell) = (F \otimes G) + (k+\ell) $$

Server hanya memeriksa apakah hash SHA-256 dari representasi JSON polinomial pernah dilihat sebelumnya:

```python
def validate_voucher(sig_vec):
    for vec in sig_vec:
        temp = json.dumps(vec).encode("utf-8")
        hashed = hashlib.sha256(temp).hexdigest()
        if hashed in seen_voucher:
            return False
        seen_voucher.add(hashed)
    return verify("10$ voucher", sig_vec, M)
```

Karena signature memiliki sifat malleability, kita dapat menghasilkan voucher baru yang ekuivalen secara aljabar dengan menggeser koefisien polinomial:
- $A' = A + k$
- $B' = B + k$
- $N' = N + 2k$

Dengan variasi nilai $k$ dari 1 hingga 9, diperoleh 9 voucher tambahan yang lolos verifikasi tanda tangan dan lolos filter keunikan hash.

## 2. Status Solver

Script `solve_tropical.py` mengotomatisasi koneksi dan penukaran 10 voucher hingga saldo mencapai $100. Pengujian lokal membuktikan 10/10 voucher valid. Flag remote belum tercatat karena server remote saat penulisan tidak lagi dapat diakses.
