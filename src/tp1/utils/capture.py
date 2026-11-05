from collections import Counter, defaultdict

from scapy.all import ARP, DNS, ICMP, IP, TCP, UDP, Ether, Raw, rdpcap, sniff

from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.summary = ""
        self.packets = []

    def capture_traffic(self, pcap_file=None) -> None:
        interface = self.interface
        logger.info(f"Capture traffic from interface {interface}")

        if pcap_file:
            self.packets = rdpcap(pcap_file)
        else:
            self.packets = sniff(iface=self.interface, count=100)

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
                protocols["ETHERNET"] += 1

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
        announcements: defaultdict = defaultdict(Counter)

        for packet in self.packets:
            if packet.haslayer(ARP):
                announcements[packet[ARP].psrc][packet[ARP].hwsrc] += 1

        for ip, macs in announcements.items():
            if len(macs) > 1:
                attacker = macs.most_common()[-1][0]
                logger.warning(f"ARP spoofing detect sur {ip} par {attacker}")
                attacks.append({"type": "arp_spoofing", "attacker": attacker})

        return attacks

    def detect_port_scan(self, threshold: int = 20) -> list[dict]:
        """
        Detecte un scan de ports : de nombreux SYN vers des ports differents

        :param threshold: nb de port distincts a partir duquel on alerte
        :return: la liste des attaques detectees
        """
        attacks: list[dict] = []
        targeted_ports: defaultdict = defaultdict(set)

        for packet in self.packets:
            if packet.haslayer(TCP) and packet[TCP].flags == "S":
                targeted_ports[packet[IP].src].add(packet[TCP].dport)

        for ip, ports in targeted_ports.items():
            if len(ports) >= threshold:
                logger.warning(f"scan de ports detecte depuis {ip} ({len(ports)} ports")
                attacks.append({"type": "port_scan", "attacker": ip})

        return attacks

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
        return {
            "protocols": dict(self.get_all_protocols()),
            "attacks": [],
            "flag": None,
        }
