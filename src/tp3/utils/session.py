import requests

from src.tp3.utils.captcha import Captcha


class Session:
    def __init__(self, url, http=None):
        self.url = url                           # adresse de base de la cible
        self.http = http or requests.Session()   # le navigateur partagé (garde les cookies)
        self.captcha_value = ""
        self.flag_value = ""
        self.valid_flag = ""
        self.response = None
        # infos qu'on récupérera pour la phase réseau
        self.host = ""
        self.port = 0
        self.key = b""

    def prepare_request(self):
        # on visite la page interne : ça crée le code du captcha et pose le cookie
        self.http.get(self.url + "/internal-panel")
        # on télécharge et on lit le captcha, avec le MÊME navigateur (donc même cookie)
        captcha = Captcha(self.url + "/captcha.png", self.http)
        captcha.capture()
        captcha.solve()
        self.captcha_value = captcha.get_value()

    def submit_request(self):
        # on renvoie le code lu au serveur, dans le champ "captcha"
        self.response = self.http.post(
            self.url + "/internal-panel",
            data={"captcha": self.captcha_value},
        )

    def process_response(self):
        # si le captcha est faux, le serveur répond 403 -> on signale l'échec
        if self.response.status_code != 200:
            return False
        # sinon il renvoie un JSON avec les infos qu'on cherche
        donnees = self.response.json()
        self.valid_flag = donnees["flag1"]
        self.host = donnees["host"]
        self.port = donnees["port"]
        self.key = bytes.fromhex(donnees["key"])   # la clé arrive en hexa -> on la convertit en octets
        return True

    def get_flag(self):
        return self.valid_flag