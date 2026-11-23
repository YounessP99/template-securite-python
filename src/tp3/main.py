"""TP3 - Breach the target (squelette).

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré). Voir tp3-breach-the-target.md.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse
from pathlib import Path

import requests

from tp3.utils.config import logger

def find_endpoint(session, target):
    # on récupère le fichier wordlist.txt qui est à côté de ce fichier
    chemin_wordlist = Path(__file__).parent / "wordlist.txt"

    # on lit le fichier et on met chaque ligne dans une liste
    mots = chemin_wordlist.read_text().splitlines()

    # on teste chaque mot un par un
    for mot in mots:
        mot = mot.strip()        # on enlève les espaces autour
        if mot == "":            # si la ligne est vide on passe
            continue

        url = target + "/" + mot     # on construit l'adresse à tester
        reponse = session.get(url)   # on demande la page

        # si ce n'est pas une erreur 404, la page existe
        if reponse.status_code != 404:
            logger.info(f"Endpoint trouve : {url}")
            return url

    # on n'a rien trouvé
    return None

def breach_web(target: str) -> tuple[str, int, bytes]:
    """Fuzz les endpoints, casse le CAPTCHA, retourne (host, port, key).

    Affiche aussi Flag 1. Indices : requests, PIL, pytesseract.
    """
    raise NotImplementedError


def breach_network(host: str, port: int, key: bytes) -> str:
    """pwntools/socket : décode le flux base64+XOR en boucle sous 30 s.

    Retourne le flag final. Indices : pwn.remote, base64.
    """
    raise NotImplementedError


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:8080")
    args = ap.parse_args()

    logger.info("Starting TP3 - breach the target")
    host, port, key = breach_web(args.target)
    flag = breach_network(host, port, key)
    logger.info(f"FLAG_FINAL: {flag}")


if __name__ == "__main__":
    main()
