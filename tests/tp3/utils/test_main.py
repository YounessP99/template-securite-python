import base64

import src.tp3.main as main_mod
from tp3.main import find_endpoint, xor_bytes


def test_xor_bytes():
    data = b"hello"
    key = b"\x01\x02"
    brouille = xor_bytes(data, key)
    # XOR deux fois avec la meme cle = retour au depart
    assert xor_bytes(brouille, key) == data


# un faux navigateur : 404 partout sauf sur internal-panel
class FausseReponse:
    def __init__(self, status_code):
        self.status_code = status_code


class FausseSession:
    def get(self, url):
        if url.endswith("/internal-panel"):
            return FausseReponse(200)
        return FausseReponse(404)


def test_find_endpoint():
    session = FausseSession()
    resultat = find_endpoint(session, "http://cible")
    assert resultat == "http://cible/internal-panel"


def test_breach_web(monkeypatch):
    # on evite le vrai reseau : on remplace find_endpoint et Session
    monkeypatch.setattr(
        main_mod, "find_endpoint", lambda http, target: target + "/internal-panel"
    )

    class FausseSessionWeb:
        def __init__(self, url, http=None):
            self.host = "1.2.3.4"
            self.port = 9090
            self.key = b"\x01\x02"

        def prepare_request(self):
            pass

        def submit_request(self):
            pass

        def process_response(self):
            return True

        def get_flag(self):
            return "ESGI{flag1}"

    monkeypatch.setattr(main_mod, "Session", FausseSessionWeb)

    host, port, key = main_mod.breach_web("http://cible")
    assert host == "1.2.3.4"
    assert port == 9090
    assert key == b"\x01\x02"


# un faux fichier qui renvoie des lignes preparees a l'avance
class FauxFichier:
    def __init__(self, lignes):
        self.lignes = lignes
        self.i = 0

    def readline(self):
        ligne = self.lignes[self.i]
        self.i += 1
        return ligne


# un faux socket qui sert ces lignes
class FauxSocket:
    def __init__(self, lignes):
        self._fichier = FauxFichier(lignes)

    def connect(self, addr):
        pass

    def makefile(self, mode):
        return self._fichier

    def sendall(self, data):
        pass

    def close(self):
        pass


def test_breach_network(monkeypatch):
    # les lignes que le "serveur" enverra : intro, 3 rounds, puis le flag
    lignes = [
        b"intro\n",
        base64.b64encode(b"token-round-0001") + b"\n",
        base64.b64encode(b"token-round-0002") + b"\n",
        base64.b64encode(b"token-round-0003") + b"\n",
        b"OK ESGI{final}\n",
    ]
    monkeypatch.setattr(main_mod.socket, "socket", lambda *a, **k: FauxSocket(lignes))

    flag = main_mod.breach_network("1.2.3.4", 9090, b"\x01\x02")
    assert flag == "ESGI{final}"
