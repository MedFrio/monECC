"""
Chiffrement hybride "façon ECIES" pour coller au CLI du TP :

- Chiffrement : on tire un scalaire éphémère r, on calcule R = rP,
  puis secret partagé S = rQb. On dérive clé+IV via SHA256(Sx||Sy).
- Déchiffrement : on relit R du cryptogramme, on calcule S = kR.

Sortie (ASCII) :
  b64("Rx;Ry") + ":" + b64(ciphertext)

ciphertext = AES-CBC( key=last16, iv=first16, PKCS7(plaintext) )
"""

from __future__ import annotations

import base64
import hashlib
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

from ecc import Curve, Point, scalar_mult, is_on_curve


def random_scalar(max_scalar: int) -> int:
    if max_scalar < 2:
        raise ValueError("max_scalar doit être >= 2.")
    # inclusif [1, max_scalar]
    return secrets.randbelow(max_scalar) + 1


def _derive_key_iv(S: Point) -> tuple[bytes, bytes]:
    if S.x is None or S.y is None:
        raise ValueError("Secret partagé invalide (point à l'infini).")

    # Petite courbe => coords petites. On sérialise proprement en bytes.
    msg = f"{S.x};{S.y}".encode("utf-8")
    digest = hashlib.sha256(msg).digest()  # 32 bytes
    iv = digest[:16]
    key = digest[16:]
    return key, iv


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def encrypt_message(curve: Curve, P: Point, Qb: Point, plaintext: str, max_scalar: int = 1000) -> str:
    if not is_on_curve(curve, P) or not is_on_curve(curve, Qb):
        raise ValueError("Point hors courbe.")

    # Scalaire éphémère
    while True:
        r = random_scalar(max_scalar)
        R = scalar_mult(curve, r, P)
        if R.is_infinity():
            continue

        S = scalar_mult(curve, r, Qb)
        if S.is_infinity():
            continue

        break

    key, iv = _derive_key_iv(S)

    # AES-CBC + PKCS7
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()

    r_part = _b64e(f"{R.x};{R.y}".encode("utf-8"))
    ct_part = _b64e(ct)
    return f"{r_part}:{ct_part}"


def decrypt_message(curve: Curve, P: Point, k: int, cryptogram: str) -> str:
    if not is_on_curve(curve, P):
        raise ValueError("Point générateur hors courbe.")

    try:
        r_part, ct_part = cryptogram.strip().split(":", 1)
    except ValueError as exc:
        raise ValueError("Cryptogramme invalide (format attendu: b64(Rx;Ry):b64(ct)).") from exc

    coords = _b64d(r_part).decode("utf-8").split(";")
    if len(coords) != 2:
        raise ValueError("Cryptogramme invalide (coordonnées R).")
    R = Point(int(coords[0]), int(coords[1]))

    ct = _b64d(ct_part)

    if not is_on_curve(curve, R):
        raise ValueError("Cryptogramme invalide (R hors courbe).")

    S = scalar_mult(curve, int(k), R)
    key, iv = _derive_key_iv(S)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(padded) + unpadder.finalize()
    return pt.decode("utf-8")
