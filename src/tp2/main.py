import argparse
import json
import os
import sys

from tp2.utils.config import logger
from tp2.utils.triage import Triage


def parse_args() -> argparse.Namespace:
    """
    Lit les arguments de la ligne de commande

    :return: les arguments analyses
    """
    parser = argparse.ArgumentParser(description="Triage automatise de malware")
    parser.add_argument("--samples", required=True, help="dossier des echantillons")
    parser.add_argument("--rules", default="rules", help="dossier des regles YARA")
    parser.add_argument("--out", required=True, help="dossier des rapports JSON")
    parser.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    return parser.parse_args()


def main() -> None:
    """
    Analyse tous les echantillons d'un dossier et ecrit un rapport par fichier

    Un echantillon illisible n'interrompt pas le lot : l'erreur est tracee
    et l'analyse continue avec le suivant.
    """
    logger.info("Starting TP2")
    args = parse_args()

    if not os.path.isdir(args.samples):
        logger.error(f"Dossier d'echantillons introuvable : {args.samples}")
        sys.exit(1)

    os.makedirs(args.out, exist_ok=True)

    analyses = 0
    echecs = 0

    for name in sorted(os.listdir(args.samples)):
        path = os.path.join(args.samples, name)

        if not os.path.isfile(path):
            continue

        try:
            triage = Triage(path, args.llm, args.rules)
            result = triage.run()
        except Exception as error:  # noqa: BLE001
            logger.error(f"Echec de l'analyse de {name} : {error}")
            echecs += 1
            continue

        out_path = os.path.join(args.out, f"{name}.triage.json")

        with open(out_path, "w", encoding="utf-8") as report_file:
            json.dump(result, report_file, indent=2)

        analyses += 1
        logger.info(f"{name} -> {out_path}")

    logger.info(f"{analyses} echantillon(s) analyse(s), {echecs} en echec")


if __name__ == "__main__":
    main()