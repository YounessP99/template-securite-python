import pytest

from src.tp2.utils.triage import Triage

CONTENU = (
    b"\x7fELF faux echantillon\n"
    b"urlmon.dll URLDownloadToFileA WinExec\n"
    b"c2-deadbeef.example.test\n"
    b"http://c2-deadbeef.example.test/gate.php\n"
    b"Global\\mabc123\n"
    b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svcabc\n"
    b"FLAG=ESGI{test_1234}\n"
)


@pytest.fixture
def rapport(tmp_path):
    chemin = tmp_path / "faux.bin"
    chemin.write_bytes(CONTENU)
    triage = Triage(str(chemin), "openrouter", "dossier_qui_nexiste_pas")
    return triage.run()


def test_run(rapport):
    # Then
    assert len(rapport["sha256"]) == 64
    assert rapport["flag"] == "ESGI{test_1234}"
    assert rapport["iocs"]["domains"] == ["c2-deadbeef.example.test"]
    assert "Suspicious_Downloader" in rapport["yara_matches"]
