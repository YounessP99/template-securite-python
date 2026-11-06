from unittest.mock import patch

from src.tp1.main import main, parse_args


def test_parse_args():
    # Given
    arguments = ["tp1", "--pcap", "capture.pcap", "--out", "rapport.json"]

    # When
    with patch("sys.argv", arguments):
        result = parse_args()

    # Then
    assert result.pcap == "capture.pcap"
    assert result.out == "rapport.json"


def test_main(tmp_path):
    # Given
    sortie = tmp_path / "rapport.json"
    arguments = ["tp1", "--pcap", "inexistant.pcap", "--out", str(sortie)]

    # When
    with patch("sys.argv", arguments):
        main()

    # Then
    assert sortie.exists()