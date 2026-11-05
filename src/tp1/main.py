import json
import argparse

from tp1.utils.capture import Capture
from tp1.utils.config import logger
from tp1.utils.report import Report


def parse_args() -> argparse.Namespace:
    """
    Lit les arguments de la ligne de commande

    :return: les argumentsanalyses
    """
    parser = argparse.ArgumentParser(description="IDS/IPS maison - analyse de capture reseau")
    parser.add_argument("--pcap", help="chemin du fichier pcap a analyser")
    parser.add_argument("--out", default="report.json", help="chemin du rapport JSON")
    parser.add_argument("--iface", help="interface reseau pour une capture live")
    return parser.parse_args()


def main():
    logger.info("Starting TP1")
    args = parse_args()

    capture = Capture()
    capture.capture_traffic(args.pcap)
    logger.info(capture.detect_port_scan())
    capture.analyse("tcp")
    with open(args.out, "w", encoding="utf-8") as report_file:
        json.dump(capture.build_report(), report_file, indent=2)
    logger.info(f"Rapport JSON ecrit dans {args.out}")
    summary = capture.get_summary()

    filename = "report.pdf"
    report = Report(capture, filename, summary)
    report.generate("graph")
    report.generate("array")
    report.save(filename)


if __name__ == "__main__":
    main()
