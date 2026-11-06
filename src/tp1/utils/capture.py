import re
from collections import Counter

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, Raw, rdpcap, sniff

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []

    def capture_traffic(self, pcap_file: str | None = None) -> None:
        """
        Lit une capture depuis un fichier pcap, ou capture sur l'interface

        :param pcap_file: chemin du fichier pcap, ou None pour une capture live
        """

        try:
            if pcap_file:
                logger.info(f"Lecture de la capture {pcap_file}")
                self.packets = rdpcap(pcap_file)
            else:
                logger.info(f"Capture sur l'interface {self.interface}")
                self.packets = sniff(iface=self.interface, count=100)
        except FileNotFoundError:
            logger.error(f"Le fichier {pcap_file} est introuvable")
            self.packets = []
        except Exception as error:  # noqa: BLE001
            logger.error(f"Erreur pendant la capture : {error}")
            self.packets = []

        logger.info(f"{len(self.packets)} paquets récupérés")

    def sort_network_protocols(self) -> list:
        """
        Trie les protocoles du plus au moins frequent

        :return: une liste de tuples
        """
        return self.get_all_protocols().most_common()

    def get_all_protocols(self) -> Counter:
        """
        Compte le nb de paquets par protocole

        :return: un compteur {nom du protocole: nb de paquets}
        """
        protocols: Counter = Counter()

        for packet in self.packets:
            if packet.haslayer(Ether):
                protocols["Ethernet"] += 1

            if packet.haslayer(ARP):
                protocols["ARP"] += 1

            if packet.haslayer(IP):
                protocols["IP"] += 1

            if packet.haslayer(TCP):
                protocols["TCP"] += 1

            if packet.haslayer(UDP):
                protocols["UDP"] += 1

            if packet.haslayer(ICMP):
                protocols["ICMP"] += 1

            if packet.haslayer(DNS):
                protocols["DNS"] += 1

            if packet.haslayer(TCP) and packet.haslayer(Raw):
                protocols["HTTP"] += 1

        return protocols

    def detect_arp_spoofing(self) -> list[dict]:
        """
        Detecte une usurpation ARP : plusieurs MAC pour une meme IP

        :return: la liste des attaques detectees
        """
        attacks: list[dict] = []
        announcements: dict = {}
        poisoned: dict = {}

        for packet in self.packets:
            if not packet.haslayer(ARP):
                continue

            if packet[ARP].op == 2:
                ip = packet[ARP].psrc
                mac = packet[ARP].hwsrc

                if ip not in announcements:
                    announcements[ip] = []

                if mac not in announcements[ip]:
                    announcements[ip].append(mac)

            if packet[ARP].op == 1 and packet.dst != "ff:ff:ff:ff:ff:ff":
                poisoned[packet[ARP].pdst] = packet.dst

        for ip, macs in announcements.items():
            if len(macs) > 1:
                attacker = poisoned.get(ip, macs[-1])

                logger.warning(f"ARP spoofing detecte sur {ip} par {attacker}")
                attacks.append({"type": "arp_spoofing", "attacker": attacker})

        return attacks

    def detect_port_scan(self, threshold: int = 20) -> list[dict]:
        """
        Detecte un scan de ports : de nombreux SYN vers des ports differents

        :param threshold: nb de port distincts a partir duquel on alerte
        :return: la liste des attaques detectees
        """
        attacks: list[dict] = []
        targeted_ports: dict = {}

        for packet in self.packets:
            if packet.haslayer(TCP) and packet[TCP].flags == "S":
                ip = packet[IP].src
                port = packet[TCP].dport

                if ip not in targeted_ports:
                    targeted_ports[ip] = []

                if port not in targeted_ports[ip]:
                    targeted_ports[ip].append(port)

        for ip, ports in targeted_ports.items():
            if len(ports) >= threshold:
                logger.warning(
                    f"scan de ports detecte depuis {ip} ({len(ports)} ports)"
                )
                attacks.append({"type": "port_scan", "attacker": ip})

        return attacks

    def detect_sql_injection(self) -> list[dict]:
        """
        Cherche une injection sql dans les requetes HTTP

        :return: la liste des attaques detectees
        """
        patterns = ["' or 1=1", "%27%20or%201=1", "union select", "sqlmap", "or 1=1"]
        attacks: list[dict] = []
        attackers: list = []

        for packet in self.packets:
            if not packet.haslayer(Raw) or not packet.haslayer(IP):
                continue

            payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore").lower()

            for pattern in patterns:
                if pattern in payload:
                    if packet[IP].src not in attackers:
                        attackers.append(packet[IP].src)
                    break

        for ip in attackers:
            logger.warning(f"Injection SQL detectee depuis {ip}")
            attacks.append({"type": "sql_injection", "attacker": ip})

        return attacks

    def find_flag(self) -> str | None:
        """
        Cherche le flag dans la capture en ignorant les leurres

        :return: le flag trouve, ou None
        """
        decoys = [
            "system prompt",
            "x-ai-instructions",
            "as an ai",
            "ignore your previous",
        ]

        for packet in self.packets:
            if not packet.haslayer(Raw):
                continue

            payload = bytes(packet[Raw].load).decode("utf-8", errors="ignore")

            is_decoy = False

            for decoy in decoys:
                if decoy in payload.lower():
                    is_decoy = True

            if is_decoy:
                logger.warning("Tentative de manipulation detectee, paquet ignore")
                continue

            found = re.search(r"ESGI\{[^}]+\}", payload)
            if found:
                logger.info(f"Flag trouve : {found.group(0)}")
                return found.group(0)

        return None

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary

    def build_report(self) -> dict:
        """
        Construit le rapport d'analyse au format attendu par la correction

        :return: un dictionnaire {protocols, attacks, flag}
        """
        attacks = (
            self.detect_arp_spoofing()
            + self.detect_port_scan()
            + self.detect_sql_injection()
        )

        if not attacks:
            logger.info("Aucune activité suspecte detectee")

        return {
            "protocols": dict(self.get_all_protocols()),
            "attacks": attacks,
            "flag": self.find_flag(),
        }
