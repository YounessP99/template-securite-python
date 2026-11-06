# TP1 - Analyse réseau

## Description

Le projet est un TP de M1 écrit en python avec Scapy, le programme analyse une capture réseau pour trouver des attaques

## Installation

Faire un fork puis un clone du projet :

```bash
git clone https://github.com/YounessP99/template-securite-python.git
cd template-securite-python
poetry install
```

## Utilisation

Lancer le projet :

```bash
poetry run tp1 --pcap capture.pcap --out report.json
```
- `--pcap` -> le chemin du fichier capture à analyser
- `--out` -> le chemin du fichier JSON à écrire pour le rapport
- `--iface` -> l'interface réseau pour une capture en direct

## Ce que le programme détecte

- ARP spoofing : plusieurs adresses MAC annoncent la meme IP
- Scan de ports : une machine teste plein de ports différents
- Injection SQL : motifs suspects dans les requetes HTTP

## Le flag

Le programme va chercher le flag caché dans la capture. Les faux flags, placés dans des paquets qui essaient de manipuler un analyste, sont ignorés

## Tests

```bash
poetry run pytest
```