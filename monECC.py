#!/usr/bin/env python3
"""
monECC - TP ECC (CLI)

Courbe: y^2 = x^3 + 35x + 3 (mod 101)
Point générateur: P = (2, 9)

ECC est codé à la main (voir ecc.py). SHA256 + AES-CBC via la lib "cryptography".
"""

from __future__ import annotations
from ecc import Curve, Point, scalar_mult, is_on_curve, point_order


import argparse
import sys
from pathlib import Path

from ecc import Curve, Point, scalar_mult, is_on_curve
from keyfile import (
    read_private_key,
    read_public_key,
    write_private_key,
    write_public_key,
)
from ecies import encrypt_message, decrypt_message


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="monECC",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
        description="Script monECC\nSyntaxe :\n  monECC <commande> [<clé>] [<texte>] [switchs]\n",
    )

    sub = parser.add_subparsers(dest="command")

    # help
    sub.add_parser("help", help="Affiche l'aide")

    # keygen
    p_keygen = sub.add_parser("keygen", help="Génère une paire de clés")
    p_keygen.add_argument("-f", "--filename", default="monECC",
                          help="Nom de base des fichiers (défaut: monECC -> monECC.pub & monECC.priv)")
    p_keygen.add_argument("-s", "--size", type=int, default=1000,
                          help="Plage d'aléa de la clé privée (défaut: 1000)")

    # crypt
    p_crypt = sub.add_parser("crypt", help="Chiffre un texte pour une clé publique")
    p_crypt.add_argument("keyfile", help="Fichier .pub (clé publique monECC)")
    p_crypt.add_argument("text", nargs="?", help="Texte en clair (mettez des guillemets si espaces)")
    p_crypt.add_argument("-s", "--size", type=int, default=1000,
                         help="Plage d'aléa (clé éphémère) (défaut: 1000)")
    p_crypt.add_argument("-i", "--input", dest="input_file",
                         help="Lire le texte en clair depuis un fichier")
    p_crypt.add_argument("-o", "--output", dest="output_file",
                         help="Écrire le cryptogramme dans un fichier (sinon stdout)")

    # decrypt
    p_decrypt = sub.add_parser("decrypt", help="Déchiffre un texte avec une clé privée")
    p_decrypt.add_argument("keyfile", help="Fichier .priv (clé privée monECC)")
    p_decrypt.add_argument("text", nargs="?", help="Cryptogramme (mettez des guillemets si espaces)")
    p_decrypt.add_argument("-i", "--input", dest="input_file",
                           help="Lire le cryptogramme depuis un fichier")
    p_decrypt.add_argument("-o", "--output", dest="output_file",
                           help="Écrire le texte en clair dans un fichier (sinon stdout)")

    return parser


def _print_manual() -> None:
    print(
        "Script monECC\n"
        "Syntaxe :\n"
        "  monECC <commande> [<clé>] [<texte>] [switchs]\n"
        "Commande :\n"
        "  keygen  : Génère une paire de clé\n"
        "  crypt   : Chiffre <texte> pour la clé publique <clé>\n"
        "  decrypt : Déchiffre <texte> avec la clé privée <clé>\n"
        "  help    : Affiche ce manuel\n"
        "Switchs :\n"
        "  keygen : -f <filename>, -s <size>\n"
        "  crypt/decrypt : -i <file> (input), -o <file> (output)\n"
    )


def _read_text_arg(text_arg: str | None, input_file: str | None) -> str:
    if input_file:
        return Path(input_file).read_text(encoding="utf-8")
    if text_arg is None:
        raise ValueError("Texte manquant : fournissez <texte> ou utilisez -i <file>.")
    return text_arg


def _write_output(data: str, output_file: str | None) -> None:
    if output_file:
        Path(output_file).write_text(data, encoding="utf-8")
    else:
        print(data)


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv

    parser = _build_parser()
    if not argv or argv[0] in {"help", "-h", "--help"}:
        _print_manual()
        return 0

    args = parser.parse_args(argv)

    curve = Curve(p=101, a=35, b=3)
    P = Point(2, 9)
    n = point_order(curve, P)


    if args.command in (None, "help"):
        _print_manual()
        return 0

    if args.command == "keygen":
        if args.size < 2:
            raise ValueError("La taille (-s) doit être >= 2.")
        priv_path = Path(f"{args.filename}.priv")
        pub_path = Path(f"{args.filename}.pub")

        # Tire k jusqu'à obtenir un point public valide (évite le point à l'infini).
        from ecies import random_scalar

        import secrets

        while True:
            k = secrets.randbelow(n - 1) + 1  # 1..n-1
            Q = scalar_mult(curve, k, P)
            if Q.is_infinity():
                continue
            if not is_on_curve(curve, Q):
                continue
            # optionnel mais recommandé : évite y=0 (points "spéciaux")
            if Q.y == 0:
                continue
            break


        write_private_key(priv_path, k)
        write_public_key(pub_path, Q)

        print(f"Clé privée : {priv_path}")
        print(f"Clé publique: {pub_path}")
        return 0

    if args.command == "crypt":
        plaintext = _read_text_arg(args.text, args.input_file)
        Qb = read_public_key(Path(args.keyfile))
        cryptogram = encrypt_message(curve, P, Qb, plaintext, max_scalar=n - 1)
        _write_output(cryptogram, args.output_file)
        return 0

    if args.command == "decrypt":
        cryptogram = _read_text_arg(args.text, args.input_file)
        k = read_private_key(Path(args.keyfile))
        plaintext = decrypt_message(curve, P, k, cryptogram)
        _write_output(plaintext, args.output_file)
        return 0

    _print_manual()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
