import pytest

from src.tp2.utils.scanner import YaraScanner

CONTENU = (
    b"urlmon.dll URLDownloadToFileA WinExec\n"
    b"c2-deadbeef.example.test /gate.php\n"
    b"Global\\mabc123\n"
    b"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\svcabc\n"
)


@pytest.fixture
def scanner():
    return YaraScanner("dossier_qui_nexiste_pas")


def test_compiler_regles(scanner):
    # When
    regles = scanner.compiler_regles()

    # Then
    assert regles is not None


def test_scan(scanner):
    # When
    declenchees = scanner.scan(CONTENU)

    # Then
    assert "Suspicious_Downloader" in declenchees
    assert "C2_Gate" in declenchees
    assert "Has_Mutex" in declenchees


def test_scan_sans_regles(scanner):
    # Given
    scanner.regles = None

    # Then
    assert scanner.scan(CONTENU) == []
