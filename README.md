# monECC (TP)

Application en ligne de commande qui génère des clés, chiffre et déchiffre des messages avec ECC (courbe imposée) + SHA256 + AES-CBC.

Courbe : `y^2 = x^3 + 35x + 3 (mod 101)`  
Point de départ : `P = (2, 9)`

## Prérequis

- Python 3.10+
- Paquet `cryptography`

## Installation

```bash
python -m venv .venv
# Linux/Mac
source .venv/bin/activate
# Windows
# .venv\Scripts\activate

pip install -r requirements.txt
```

## Utilisation

Afficher l'aide :

```bash
python monECC.py help
```

### 1) Générer une paire de clés

```bash
python monECC.py keygen
# ou
python monECC.py keygen -f alice -s 1000
```

Cela crée :
- `monECC.priv` et `monECC.pub` (ou `alice.priv` / `alice.pub`)

### 2) Chiffrer

```bash
python monECC.py crypt bob.pub "Bonjour Bob"
```

Sortie : `b64("Rx;Ry"):b64(ciphertext)` (ASCII)

> Astuce : si ton message contient des espaces, mets des guillemets.

### 3) Déchiffrer

```bash
python monECC.py decrypt bob.priv "<cryptogramme>"
```

### Options I/O (facultatif)

Lire depuis un fichier / écrire dans un fichier :

```bash
python monECC.py crypt bob.pub -i message.txt -o message.enc
python monECC.py decrypt bob.priv -i message.enc -o message.txt
```

## Notes

- La partie ECC (addition, double-and-add, inverse modulaire) est codée à la main dans `ecc.py`.
- Pour coller au CLI du TP, le chiffrement utilise un scalaire **éphémère** `r` et inclut `R = rP` dans le cryptogramme.
  Le destinataire calcule ensuite le secret partagé avec sa clé privée (`S = kR`).
