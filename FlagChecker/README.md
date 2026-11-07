# FlagChecker: Writeup

| Parameter | Keterangan |
| --- | --- |
| Soal | FlagChecker |
| Kategori | Reverse Engineering |
| File Soal | `flagchecker.zip` |
| Binary | `FlagChecker.elf` (ELF 64-bit, statically linked, UPX packed) |
| Password Arsip | `tryhards` |
| Format Flag | `TryHards{...}` |
| Flag | `TryHards{https://youtu.be/k4V3Mo61fJM?si=eNDAJecKDMhedHnU&t=25}` |
| Status | Solved (terverifikasi pada executable asli) |

## Deskripsi Soal

> An unusual flag checker. If your input is correct, it will print :). Otherwise, it will print :(. Can you find the correct input?
>
> Archive password: tryhards

Sasaran challenge adalah merekayasa balik file binary Linux untuk menemukan string flag yang menghasilkan output `:)`.

## 1. Identifikasi File

Ekstrak arsip soal:

```bash
unzip -P tryhards flagchecker.zip
chmod +x FlagChecker.elf
file FlagChecker.elf
```

Output:

```text
FlagChecker.elf: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, stripped
```

Pemeriksaan awal teks menggunakan `strings` memperlihatkan penanda `UPX!`. Binary diproteksi dengan kompresor UPX.

## 2. Unpacking dan Analisis Binary

Langkah pertama adalah dekompresi layer UPX:

```bash
upx -d FlagChecker.elf -o FlagChecker_unpacked.elf
```

Jika unpacking otomatis terhambat oleh modifikasi header, unpacking dinamis dapat dilakukan dengan menjalankan binary di debugger (GDB), menangkap transisi eksekusi dari stub unpacker ke Original Entry Point (OEP), lalu melakukan dump memori.

Setelah binary didekompresi, ditemukan artefak runtime:

```text
FlagChecker.dll
System.Private.CoreLib
__managedcode
```

Tanda ini mengonfirmasi bahwa aplikasi dibangun dengan .NET Native AOT (Ahead-of-Time compilation). Kompilasi jenis ini mengubah kode perantara CIL (.NET) langsung menjadi instruksi mesin native, memadukan CoreLib secara statis.

## 3. Penelusuran Validasi Input

Saat program dijalankan, prompt meminta input:

```text
Flag: 
```

Jika string salah, program merespons dengan `:(`.
Cabang penentu validasi memeriksa struktur string input secara berurutan. Analisis aliran kontrol (control flow analysis) pada fungsi validasi mengungkap bahwa string yang diterima merujuk ke URL video YouTube tertentu yang dibungkus format flag TryHards.

## 4. Flag

String yang memenuhi syarat validasi:

```text
TryHards{https://youtu.be/k4V3Mo61fJM?si=eNDAJecKDMhedHnU&t=25}
```

Catatan: tanda `?`, `&`, dan `=` merupakan bagian sah dari flag. Saat pengujian via terminal Linux, gunakan tanda petik tunggal agar karakter khusus tidak diproses oleh shell.

## 5. Validasi Flag

Menguji input langsung ke program:

```bash
printf '%s\n' 'TryHards{https://youtu.be/k4V3Mo61fJM?si=eNDAJecKDMhedHnU&t=25}' | ./FlagChecker.elf
```

Hasil eksekusi:

```text
Flag: :)
```

Sebagai perbandingan, input uji acak:

```bash
printf '%s\n' 'TryHards{dummy_test}' | ./FlagChecker.elf
```

Hasil:

```text
Flag: :(
```

Status validasi terkonfirmasi valid pada binary target.
