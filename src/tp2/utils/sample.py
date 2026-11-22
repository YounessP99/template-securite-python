import re
import hashlib
import math
from collections import Counter

from tp2.utils.config import logger

try:
    import magic
except ImportError:
    magic = None

class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        with open(path, "rb") as file:
            self.data = file.read()

    def get_file_metadata(self) -> dict:
        """
        Calcule les empreintes, la taille, le type et l'entropie du fichier

        :return: un dictionnaire sha256, md5, size, file_type, entropy
        """
        return {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data, usedforsecurity=False).hexdigest(),
            "size": len(self.data),
            "file_type": self.get_file_type(),
            "entropy": round(self.shannon_entropy(), 4),
        }

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def get_file_type(self) -> str:
        """
        Identifie le type de fichier en utilisant python-magic ou en se basant sur sa signature.

        :return: une description du type de fichier
        """
        if magic is not None:
            return magic.from_buffer(self.data)

        logger.warning("python-magic indisponible, detection par signature")

        if self.data[:4] == b"\x7fELF":
            return "ELF executable"

        if self.data[:2] == b"MZ":
            return "PE executable"

        return "data"

    def get_strings(self) -> str:
        """
        Extrait les chaines de caracteres lisibles du fichier

        :return: toutes les chaines mises bout a bout
        """
        morceaux = re.findall(rb"[\x20-\x7e]{4,}", self.data)
        texte = ""

        for morceau in morceaux:
            texte = texte + morceau.decode("ascii", errors="ignore") + " "

        return texte

    def dedoublonner(self, valeurs: list) -> list:
        """
        Supprime les doublons d'une liste et la trie

        :param valeurs: la liste a nettoyer
        :return: la liste triee sans doublons
        """
        resultat = []

        for valeur in valeurs:
            if valeur not in resultat:
                resultat.append(valeur)

        return sorted(resultat)

    def est_suspect(self, valeur: str) -> bool:
        """
        Dit si un domaine ou une URL merite d'etre signale

        :param valeur: le domaine ou l'URL a examiner
        :return: True si la valeur est retenue comme indicateur
        """
        legitimes = ["gnu.org", "translationproject.org"]
        tlds = ["com", "net", "org", "test", "info", "biz", "io", "ru", "cn", "xyz"]

        for legitime in legitimes:
            if legitime in valeur:
                return False

        for tld in tlds:
            if valeur.endswith("." + tld) or ("." + tld + "/") in valeur:
                return True

        return False

    def extract_iocs(self) -> dict:
        """
        Cherche les indicateurs de compromission dans les chaines du fichier

        :return: un dictionnaire domains, ips, urls, mutex, registry
        """
        texte = self.get_strings()

        domaines = re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", texte, re.IGNORECASE)
        ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", texte)
        urls = re.findall(r"https?://[^\s\"']+", texte)

        mutex = re.findall(r"Global\\[A-Za-z0-9]+", texte)
        registre = re.findall(r"HK(?:CU|LM)\\[^\s\"']+", texte)

        domaines_gardes = []
        for domaine in domaines:
            if self.est_suspect(domaine):
                domaines_gardes.append(domaine)

        urls_gardees = []
        for url in urls:
            if self.est_suspect(url):
                urls_gardees.append(url)                        

        return {
            "domains": self.dedoublonner(domaines_gardes),
            "ips": self.dedoublonner(ips),
            "urls": self.dedoublonner(urls_gardees),
            "mutex": self.dedoublonner(mutex),
            "registry": self.dedoublonner(registre),
        }

    def find_flag(self) -> str | None:
        """
        Cherche le drapeau marque FLAG= dans les chaines du fichier

        :return: le drapeau trouve, ou None
        """
        texte = self.get_strings()
        pieges = ["AI_INSTRUCTIONS", "NOTE_TO_AI", "ANALYST_NOTE"]

        for piege in pieges:
            if piege in texte:
                logger.warning(f"Tentative de manipulation detectee : {piege}")

        trouves = re.findall(r"FLAG=(ESGI\{[^}]+\})", texte)
        
        if trouves:
            logger.info(f"Drapeau trouve : {trouves[0]}")
            return trouves[0]

        return None

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        raise NotImplementedError
