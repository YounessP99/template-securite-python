"""TP3 - Breach the target (squelette).

Enchaîne une phase web (fuzzing + CAPTCHA) et une phase réseau (décodage
chronométré). Voir tp3-breach-the-target.md.

    poetry run tp3 --target http://127.0.0.1:8080
"""

import argparse
import base64
import socket
from pathlib import Path

import requests

from tp3.utils.config import logger
from tp3.utils.session import Session

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
    # on crée le navigateur partagé et on cherche la page cachée
    http = requests.Session()
    endpoint = find_endpoint(http, target)
    if endpoint is None:
        raise RuntimeError("Endpoint cache introuvable")

    # on prépare la session web avec le même navigateur
    session = Session(target, http)

    # on essaie plusieurs fois (l'OCR peut se tromper sur un captcha)
    for essai in range(10):
        session.prepare_request()      # va chercher + lit le captcha
        session.submit_request()       # envoie le code
        if session.process_response():  # True = captcha bon
            logger.info(f"FLAG_1: {session.get_flag()}")
            return session.host, session.port, session.key
        logger.info(f"Captcha rate (essai {essai + 1}), nouvel essai")

    # si après 10 essais rien n'a marché
    raise RuntimeError("Captcha non resolu apres plusieurs essais")

def xor_bytes(data, key):
    # on applique le XOR octet par octet, en répétant la clé si besoin
    resultat = bytearray()
    for i in range(len(data)):
        resultat.append(data[i] ^ key[i % len(key)])
    return bytes(resultat)


def breach_network(host: str, port: int, key: bytes) -> str:
    """pwntools/socket : décode le flux base64+XOR en boucle sous 30 s.

    Retourne le flag final. Indices : pwn.remote, base64.
    """
    # on se connecte au service TCP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    fichier = sock.makefile("rb")   # pour lire la connexion ligne par ligne

    # la 1re ligne est juste un message d'explication -> on la lit et on l'ignore
    fichier.readline()

    # il y a 3 rounds à résoudre
    for _ in range(3):
        ligne = fichier.readline().strip()   # la ligne du round
        brouille = base64.b64decode(ligne)   # on défait le base64
        token = xor_bytes(brouille, key)     # on défait le XOR -> le token en clair
        sock.sendall(token + b"\n")          # on renvoie le token

    # après les 3 rounds, le serveur envoie "OK <flag>"
    reponse = fichier.readline().strip()
    texte = reponse.decode()                 # on passe des octets au texte
    flag = texte.removeprefix("OK ")         # on enlève le "OK " pour garder le flag
    sock.close()
    return flag


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
