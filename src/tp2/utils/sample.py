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

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        raise NotImplementedError

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""
        raise NotImplementedError
