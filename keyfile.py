"""
Lecture/écriture des clés au format du TP.
"""

from __future__ import annotations

import base64
from pathlib import Path

from ecc import Point


_PRIV_BEGIN = "---begin monECC private key---"
_PUB_BEGIN = "---begin monECC public key---"
_END = "---end monECC key---"


def _b64e(s: str) -> str:
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def _b64d(s: str) -> str:
    return base64.b64decode(s.encode("ascii")).decode("utf-8")


def write_private_key(path: Path, k: int) -> None:
    data = "\n".join([_PRIV_BEGIN, _b64e(str(int(k))), _END, ""])
    path.write_text(data, encoding="utf-8")


def write_public_key(path: Path, Q: Point) -> None:
    if Q.x is None or Q.y is None:
        raise ValueError("Impossible d'écrire un point à l'infini comme clé publique.")
    payload = f"{Q.x};{Q.y}"
    data = "\n".join([_PUB_BEGIN, _b64e(payload), _END, ""])
    path.write_text(data, encoding="utf-8")


def read_private_key(path: Path) -> int:
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() != ""]
    if len(lines) < 3 or lines[0] != _PRIV_BEGIN or lines[-1] != _END:
        raise ValueError("Format de clé privée invalide.")
    k_str = _b64d(lines[1])
    return int(k_str)


def read_public_key(path: Path) -> Point:
    lines = [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip() != ""]
    if len(lines) < 3 or lines[0] != _PUB_BEGIN or lines[-1] != _END:
        raise ValueError("Format de clé publique invalide.")
    payload = _b64d(lines[1])
    parts = payload.split(";")
    if len(parts) != 2:
        raise ValueError("Clé publique invalide (coordonnées).")
    return Point(int(parts[0]), int(parts[1]))
