"""
ECC minimaliste pour le TP.

- Courbe courte de Weierstrass: y^2 = x^3 + ax + b (mod p)
- Point à l'infini représenté par Point(None, None)
"""

from __future__ import annotations

from dataclasses import dataclass

from math import isqrt



@dataclass(frozen=True)
class Curve:
    p: int
    a: int
    b: int


@dataclass(frozen=True)
class Point:
    x: int | None
    y: int | None

    def is_infinity(self) -> bool:
        return self.x is None and self.y is None


INF = Point(None, None)


def inv_mod(p: int, x: int) -> int:
    """
    Inverse modulaire (x^-1 mod p).
    p est premier dans ce TP.
    """
    x %= p
    if x == 0:
        raise ZeroDivisionError("Inverse de 0 impossible.")
    # Fermat (p premier) : x^(p-2) mod p
    return pow(x, p - 2, p)


def is_on_curve(curve: Curve, P: Point) -> bool:
    if P.is_infinity():
        return True
    x, y = P.x, P.y
    assert x is not None and y is not None
    p = curve.p
    return (y * y - (x * x * x + curve.a * x + curve.b)) % p == 0


def point_neg(curve: Curve, P: Point) -> Point:
    if P.is_infinity():
        return P
    assert P.x is not None and P.y is not None
    return Point(P.x, (-P.y) % curve.p)


def point_add(curve: Curve, P: Point, Q: Point) -> Point:
    """
    Addition de points sur la courbe.
    """
    p = curve.p

    if P.is_infinity():
        return Q
    if Q.is_infinity():
        return P

    assert P.x is not None and P.y is not None
    assert Q.x is not None and Q.y is not None

    # P + (-P) = O
    if P.x == Q.x and (P.y + Q.y) % p == 0:
        return INF

    if P == Q:
        # Doublage
        num = (3 * P.x * P.x + curve.a) % p
        den = (2 * P.y) % p
    else:
        # Addition
        num = (Q.y - P.y) % p
        den = (Q.x - P.x) % p

    lam = (num * inv_mod(p, den)) % p

    rx = (lam * lam - P.x - Q.x) % p
    ry = (lam * (P.x - rx) - P.y) % p
    return Point(rx, ry)


def scalar_mult(curve: Curve, k: int, P: Point) -> Point:
    """
    Multiplication scalaire (double-and-add).
    """
    if k == 0 or P.is_infinity():
        return INF


    k = int(k)
    if k < 0:
        return scalar_mult(curve, -k, point_neg(curve, P))

    result = INF
    addend = P

    while k:
        if k & 1:
            result = point_add(curve, result, addend)
        addend = point_add(curve, addend, addend)
        k >>= 1

    return result


def point_order(curve: Curve, P: Point) -> int:
    """
    Retourne n tel que nP = O (ordre du point).
    Sur p=101, c'est très petit, on peut le brute-force.
    """
    if P.is_infinity():
        return 1

    # borne large (Hasse + marge)
    max_steps = curve.p + 1 + 2 * isqrt(curve.p) + 20

    Q = INF
    for n in range(1, max_steps + 1):
        Q = point_add(curve, Q, P)
        if Q.is_infinity():
            return n

    raise ValueError("Ordre du point non trouvé (borne trop faible).")
