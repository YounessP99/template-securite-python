import src.tp3.utils.session as session_mod
from src.tp3.utils.session import Session


# une fausse reponse HTTP (status + json au choix)
class FausseReponse:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self._data = data or {}

    def json(self):
        return self._data


# un faux navigateur qui note les URL visitees et renvoie ce qu'on veut
class FausseHttp:
    def __init__(self, post_reponse=None):
        self.post_reponse = post_reponse
        self.gets = []

    def get(self, url):
        self.gets.append(url)
        return FausseReponse(200)

    def post(self, url, data=None):
        return self.post_reponse


# un faux captcha pour tester prepare_request sans vrai OCR
class FauxCaptcha:
    def __init__(self, url, session=None):
        pass

    def capture(self):
        pass

    def solve(self):
        pass

    def get_value(self):
        return "ZZZZZ"


def test_session_init():
    s = Session("http://exemple.com")
    assert s.url == "http://exemple.com"
    assert s.captcha_value == ""
    assert s.flag_value == ""
    assert s.valid_flag == ""


def test_prepare_request(monkeypatch):
    # on remplace la vraie classe Captcha par notre fausse
    monkeypatch.setattr(session_mod, "Captcha", FauxCaptcha)
    http = FausseHttp()
    s = Session("http://exemple.com", http)
    s.prepare_request()
    # doit avoir visite la page interne et range le code du captcha
    assert "http://exemple.com/internal-panel" in http.gets
    assert s.captcha_value == "ZZZZZ"


def test_submit_request():
    http = FausseHttp(post_reponse=FausseReponse(200))
    s = Session("http://exemple.com", http)
    s.captcha_value = "ABCDE"
    s.submit_request()
    # la reponse du POST doit etre rangee dans self.response
    assert s.response.status_code == 200


def test_process_response_ok():
    s = Session("http://exemple.com")
    s.response = FausseReponse(
        200,
        {"flag1": "ESGI{test}", "host": "1.2.3.4", "port": 9090, "key": "ff19"},
    )
    resultat = s.process_response()
    assert resultat is True
    assert s.get_flag() == "ESGI{test}"
    assert s.host == "1.2.3.4"
    assert s.port == 9090
    assert s.key == bytes.fromhex("ff19")


def test_process_response_echec():
    s = Session("http://exemple.com")
    s.response = FausseReponse(403)
    assert s.process_response() is False


def test_get_flag():
    s = Session("http://exemple.com")
    s.valid_flag = "FLAG123"
    assert s.get_flag() == "FLAG123"
