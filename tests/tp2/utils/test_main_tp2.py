from unittest.mock import patch

from src.tp2.main import main, parse_args


def test_parse_args():
    # Given
    arguments = ["tp2", "--samples", "ech", "--rules", "regles", "--out", "sortie"]

    # When
    with patch("sys.argv", arguments):
        args = parse_args()

    # Then
    assert args.samples == "ech"
    assert args.rules == "regles"
    assert args.out == "sortie"


def test_main(tmp_path):
    # Given
    dossier_samples = tmp_path / "samples"
    dossier_samples.mkdir()
    fichier = dossier_samples / "faux.bin"
    fichier.write_bytes(b"FLAG=ESGI{test_1234} c2-x.example.test /gate.php")

    dossier_out = tmp_path / "out"
    arguments = [
        "tp2",
        "--samples",
        str(dossier_samples),
        "--rules",
        "dossier_qui_nexiste_pas",
        "--out",
        str(dossier_out),
    ]

    # When
    with patch("sys.argv", arguments):
        main()

    # Then
    assert (dossier_out / "faux.bin.triage.json").exists()
