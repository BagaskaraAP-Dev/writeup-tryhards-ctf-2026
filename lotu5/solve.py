#!/usr/bin/env python3
"""Solver for lotu5 (CTF Cryptography / Video Steganography).

Scans changing QR codes in bottom-right corner of lotu5.mp4.
Dependencies: pip install opencv-python
"""
import sys
import cv2


def solve_video(video_path: str):
    cap = cv2.VideoCapture(video_path)
    if not cap.isOpened():
        raise RuntimeError(f"Gagal membuka file video: {video_path}")

    qr = cv2.QRCodeDetector()
    characters = []
    last_char = None
    frame_index = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        # Ambil sampel setiap 4 frame untuk efisiensi
        if frame_index % 4 == 0:
            # Region QR code di kuadran kanan bawah
            region = frame[215:360, 440:630]
            data, _, _ = qr.detectAndDecode(region)

            if data and data != last_char:
                characters.append(data)
                last_char = data

        frame_index += 1

    cap.release()
    flag = "".join(characters)
    print(f"Total frame diproses: {frame_index}")
    print(f"Karakter ditemukan: {len(characters)}")
    print(f"Flag: {flag}")
    return flag


if __name__ == "__main__":
    v_path = sys.argv[1] if len(sys.argv) > 1 else "lotu5.mp4"
    solve_video(v_path)
