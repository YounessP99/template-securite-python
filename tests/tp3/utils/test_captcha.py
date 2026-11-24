import io

from PIL import Image

import src.tp3.utils.captcha as captcha_mod
from src.tp3.utils.captcha import Captcha


# un faux navigateur qui renvoie une image bidon
class FausseReponse:
    def __init__(self, content):
        self.content = content


class FausseSession:
    def get(self, url):
        return FausseReponse(b"octets-image-bidon")


def test_captcha_init():
    captcha = Captcha("http://exemple.com/captcha.png")
    assert captcha.url == "http://exemple.com/captcha.png"
    assert captcha.image == ""
    assert captcha.value == ""


def test_capture():
    captcha = Captcha("http://exemple.com/captcha.png", FausseSession())
    captcha.capture()
    # capture() doit avoir telecharge les octets de l'image
    assert captcha.image == b"octets-image-bidon"


def test_solve(monkeypatch):
    # on fabrique une vraie petite image (son contenu importe peu : on remplace l'OCR)
    img = Image.new("RGB", (60, 20), "white")
    buffer = io.BytesIO()
    img.save(buffer, "PNG")

    captcha = Captcha("http://exemple.com/captcha.png")
    captcha.image = buffer.getvalue()

    # on remplace l'OCR par une fausse lecture qui renvoie un texte connu
    monkeypatch.setattr(
        captcha_mod.pytesseract,
        "image_to_string",
        lambda image, config="": "  ab12c \n",
    )

    captcha.solve()
    # solve() doit nettoyer : enlever espaces/retours et passer en majuscules
    assert captcha.value == "AB12C"


def test_get_value():
    captcha = Captcha("http://exemple.com/captcha.png")
    captcha.value = "TEST123"
    assert captcha.get_value() == "TEST123"
