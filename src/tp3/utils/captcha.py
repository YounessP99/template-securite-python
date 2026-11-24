import io
import os

import pytesseract
import requests
from PIL import Image

# Si Tesseract est installé à l'endroit habituel sous Windows, on indique son chemin.
# Sur une autre machine (le correcteur, sous Linux), Tesseract est déjà accessible
# tout seul -> dans ce cas on ne touche à rien.
_chemin_windows = r"C:\Program Files\Tesseract-OCR\tesseract.exe"
if os.path.exists(_chemin_windows):
    pytesseract.pytesseract.tesseract_cmd = _chemin_windows


class Captcha:
    def __init__(self, url, session=None):
        self.url = url
        # on garde la session (le "navigateur" avec les cookies) si on nous en donne une,
        # sinon on en crée une nouvelle
        self.session = session or requests.Session()
        self.image = ""
        self.value = ""

    def capture(self):
        # on télécharge l'image du captcha (ses octets)
        reponse = self.session.get(self.url)
        self.image = reponse.content

    def solve(self):
        # on ouvre l'image à partir des octets téléchargés
        img = Image.open(io.BytesIO(self.image))

        # on demande à Tesseract de lire l'image
        # --psm 7 = "c'est une seule ligne de texte"
        # la whitelist = on n'autorise que majuscules + chiffres (le code n'a que ça)
        config = "--psm 7 -c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        texte = pytesseract.image_to_string(img, config=config)

        # on nettoie : on enlève espaces/retours à la ligne et on passe en majuscules
        self.value = texte.strip().upper()

    def get_value(self):
        return self.value