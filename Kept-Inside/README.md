# Kept Inside: Writeup

| Parameter | Keterangan |
| --- | --- |
| Soal | Kept Inside |
| Tim | Tim Ruy |
| Solver / Penulis | Mooncrust |
| Kategori | Forensics / Network Forensics |
| File Soal | `kept-inside.zip` |
| Capture File | `keptinside.pcap` |
| Password Arsip | `tryhards` |
| Format Flag | `TryHards{...}` |
| Flag | `TryHards{4n_t01_tru0c_g0k4n4_r4m3n_t3pp4n}` |
| Status | Solved (terverifikasi hasil dekripsi traffic) |

## Deskripsi Soal

> This is your chance to get your tropical island vacation voucher - enjoy the unusual feeling of being in an unusual place.
>
> Archive password: tryhards

Challenge menyediakan berkas penangkapan lalu lintas jaringan PCAP yang dienkripsi dalam file ZIP.

## 1. Analisis Capture Jaringan

Setelah mengekstrak arsip dengan password `tryhards`, didapatkan file `keptinside.pcap`.

Statistik paket:
- Total paket: 13.337 frame
- Paket protokol DNS: 13.326 frame
- Paket protokol HTTP: 11 frame

Volume paket DNS yang sangat besar berfungsi sebagai traffic noise (chaff). Analisis difokuskan pada protokol HTTP menggunakan filter Wireshark:

```wireshark
tcp.port == 80
```

Urutan transaksi HTTP pada host `sumo-ramen.example`:

1. `GET /seasonal-menu.pdf` -> HTTP 200 OK (file PDF menu)
2. `POST /control` -> HTTP 200 OK (stage=1)
3. `POST /control` -> HTTP 200 OK (stage=2)
4. `POST /control` -> HTTP 200 OK (stage=3)
5. `GET /status` -> HTTP 200 OK (result payload)

## 2. Ekstraksi Passphrase dari PDF

File `seasonal-menu.pdf` diekstrak dari session HTTP. Pada seksi catatan chef (Chef's note) tertulis informasi:

```text
Secret broth passphrase: sumo-broth-2026
```

Petunjuk lain dalam dokumen:

```text
East 4 / West 2 / Bout 13
```

Teks `sumo-broth-2026` merupakan passphrase pembentuk kunci enkripsi AES-256:

```python
import hashlib
key = hashlib.sha256(b"sumo-broth-2026").digest()
```

## 3. Dekripsi Ciphertext Payload

Setiap request `POST /control` memuat parameter Base64:

```text
stage=1&data=l3jhR94nkBpPZb8ldABjegzB7cIgZb5GxxMrSbSgyNE=
```

Respons `GET /status` memuat ciphertext hasil akhir:

```text
result=kAim+pgmxR3fw0YD5yvP47BhMjQ89P3mzLfOXKbTnNhtWpCh9sTkToU4cIj0kXiB
```

Parameter dekripsi:
- Algoritma: AES-256-CBC
- Key: `SHA256("sumo-broth-2026")`
- IV: `00112233445566778899aabbccddeeff`
- Padding: PKCS#7

Hasil dekripsi plaintext:
- Stage 1: `inventory|desktop|menu.pdf`
- Stage 2: `screen|sumo|stable`
- Stage 3: `collect|flag|keptinside`
- Result: `TryHards{4n_t01_tru0c_g0k4n4_r4m3n_t3pp4n}`

## 4. Eksekusi Solver

Script `solve.py` mengekstrak data dari `keptinside.pcap` dan mendekripsi seluruh payload:

```bash
python3 solve.py kept-inside.zip
```

Output:

```text
Stage 1: inventory|desktop|menu.pdf
Stage 2: screen|sumo|stable
Stage 3: collect|flag|keptinside
FLAG: TryHards{4n_t01_tru0c_g0k4n4_r4m3n_t3pp4n}
```

Flag terverifikasi valid melalui decoding deterministik.
