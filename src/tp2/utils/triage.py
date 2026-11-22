from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner


class Triage:
    def __init__(self, path: str, backend: str, rules_path: str = "rules") -> None:
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner(rules_path)
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        """
        Analyse un echantillon et construit son rapport

        :return: le rapport au format attendu par la correction
        """
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()

        return {
            "sha256": meta["sha256"],
            "md5": meta["md5"],
            "size": meta["size"],
            "entropy": meta["entropy"],
            "file_type": meta["file_type"],
            "iocs": sample.extract_iocs(),
            "imports": [],
            "yara_matches": [],
            "family_guess": "unknown",
            "mitre_attack": [],
            "llm_summary": "",
            "score": 0,
            "flag": sample.find_flag(),
        }

        return {}
