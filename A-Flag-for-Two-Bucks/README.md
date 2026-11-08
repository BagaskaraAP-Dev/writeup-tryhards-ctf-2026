# A Flag for Two Bucks: Writeup

| Parameter | Keterangan |
| --- | --- |
| Soal | A Flag for Two Bucks |
| Tim | Tim Ruy |
| Solver / Penulis | Mooncrust |
| Kategori | Reverse Engineering |
| File Soal | `a-flag-for-two-bucks.zip` |
| Binary | `aflagfortwobucks` (ELF 64-bit x86-64, stripped) |
| Password Arsip | `tryhards` |
| Format Flag | `TryHards{...}` |
| Flag | `TryHards{r3v3r53_D_p4wn_sh0p_l0g1c1337}` |
| Status | Solved (terverifikasi pada executable asli) |

## Deskripsi Soal

> Welcome to my Pawn Shop. The clerk says this flag is authentic, but the appraisal program has hidden the original. Can you recover it?

Tujuan tantangan ini adalah menemukan string flag asli yang diterima oleh program verifikator keaslian barang pegadaian.

## 1. Identifikasi File

Ekstrak file arsip dengan password `tryhards`:

```bash
unzip -P tryhards a-flag-for-two-bucks.zip
file aflagfortwobucks
chmod +x aflagfortwobucks
```

Pemeriksaan binary:
- Format: ELF 64-bit LSB executable, x86-64.
- Linking: dynamically linked.
- Simbol: stripped (tabel fungsi dan simbol lokal dihapus).

Saat dijalankan tanpa input valid:

```text
Welcome to my Pawn Shop, go ahead and show me the flag you want appraised: test
Unfortunately, your flag here looks to be a counterfeit.
```

## 2. Analisis Alur Program

Pemeriksaan disassembly menunjukkan fungsi utama membaca masukan user dengan `fgets`, memotong karakter newline (`\r` atau `\n`) melalui `strcspn`, lalu meneruskan buffer ke fungsi transformasi pada alamat `0x401176`.

Hasil transformasi sebanyak 39 byte (0x27) dibandingkan secara langsung dengan data konstanta di seksi `.rodata` mulai alamat `0x402020` menggunakan `strncmp`:

```text
feb6ef6004fd471df65f1b87e2bb7068
1bae94f0bbdb9681ed090da94e43f551
736585474d6690
```

Array tersebut bukan representasi ASCII langsung, melainkan akumulasi hash transformasional.

## 3. Logika Transformasi

Fungsi verifikasi memproses karakter masukan berpasangan (2 byte per iterasi):

```asm
shl  eax, 0x8         ; char1 * 256
add  edx, eax         ; total = char1 * 257
imul eax, eax, 0x1fd  ; char2 * 509
xor  ecx, eax
shl  eax, 0x5         ; state * 32
add  eax, edx         ; state * 33
xor  eax, ecx
```

Persamaan recurrence yang dieksekusi:

```python
state = 0
# Untuk setiap pasangan karakter (a, b):
state = ((state * 33) ^ (a * 257) ^ (b * 509)) & 0xffffffff
output_bytes += bytes([state & 0xff, (state >> 8) & 0xff])
```

Jika panjang input ganjil, karakter terakhir diproses tunggal:

```python
state = ((state * 33) ^ (last_char * 257)) & 0xffffffff
output_bytes += bytes([state & 0xff])
```

Karena ruang pencarian setiap langkah dibatasi karakter ASCII cetak (32 hingga 126), pemulihan dapat diselesaikan secara deterministik melalui pencarian kombinasi 2 karakter yang menghasilkan nilai target 16-bit terendah yang cocok.

## 4. Rekonstruksi dan Solver

Script `solve.py` mengeksekusi pencarian pasangan karakter untuk setiap 2 byte target:

```bash
python3 solve.py
```

Output eksekusi:

```text
TryHards{r3v3r53_D_p4wn_sh0p_l0g1c1337}
```

## 5. Validasi Flag

Menguji string yang dipulihkan langsung ke binary `aflagfortwobucks`:

```bash
printf '%s\n' 'TryHards{r3v3r53_D_p4wn_sh0p_l0g1c1337}' | ./aflagfortwobucks
```

Respons program:

```text
Welcome to my Pawn Shop, go ahead and show me the flag you want appraised: Well good news, your flag looks to be authentic! Best I can do is $2.
```

Keluaran `your flag looks to be authentic` memvalidasi keberhasilan penyelesaian challenge.
