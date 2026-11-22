import os

import yara

from tp2.utils.config import logger

REGLES_DE_SECOURS = """
rule Suspicious_Downloader
{
    strings:
        $dll = "urlmon.dll" nocase
        $api = "URLDownloadToFile" nocase
        $run = "WinExec" nocase
    condition:
        2 of them
}

rule Reverse_Shell
{
    strings:
        $ws = "WSASocket" nocase
        $sh = "cmd.exe" nocase
    condition:
        $ws and $sh
}

rule Keylogger
{
    strings:
        $hook = "SetWindowsHookEx" nocase
        $key = "GetAsyncKeyState" nocase
    condition:
        any of them
}

rule Has_Mutex
{
    strings:
        $run = "CurrentVersion\\\\Run" nocase
        $mutex = "Global\\\\" nocase
    condition:
        all of them
}

rule C2_Gate
{
    strings:
        $gate = "/gate.php" nocase
        $host = "c2-" nocase
    condition:
        all of them
}
"""


class YaraScanner:
    def __init__(self, rules_path: str = "rules") -> None:
        """
        Prepare le scanner en compilant les regles une seule fois

        :param rules_path: dossier contenant les fichiers .yar
        """
        self.rules_path = rules_path
        self.regles = self.compiler_regles()

    def compiler_regles(self) -> yara.Rules | None:
        """
        Compile les regles du dossier, ou celles de secours s'il est vide

        :return: les regles compilees, ou None si elles sont invalides
        """
        fichiers = {}

        if os.path.isdir(self.rules_path):
            for nom in sorted(os.listdir(self.rules_path)):
                if nom.endswith(".yar"):
                    fichiers[nom] = os.path.join(self.rules_path, nom)

        try:
            if fichiers:
                logger.info(f"{len(fichiers)} fichier(s) de regles charge(s)")
                return yara.compile(filepaths=fichiers)

            logger.warning("Aucun fichier .yar trouve, regles de secours utilisees")
            return yara.compile(source=REGLES_DE_SECOURS)
        except yara.Error as error:
            logger.error(f"Regles YARA invalides : {error}")
            return None

    def scan(self, data: bytes) -> list[str]:
        """
        Cherche les regles YARA declenchees par un echantillon

        :param data: le contenu du fichier a analyser
        :return: les noms des regles declenchees
        """
        if self.regles is None:
            return []

        noms = []

        for resultat in self.regles.match(data=data):
            noms.append(resultat.rule)

        return sorted(noms)
