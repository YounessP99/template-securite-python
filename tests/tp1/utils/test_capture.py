from unittest.mock import patch

from scapy.all import ARP, IP, TCP, Ether

from src.tp1.utils.capture import Capture


def test_capture_init():
    # When
    capture = Capture()

    # Then
    assert capture.interface == ""
    assert capture.summary == ""


def test_given_capture_when_capture_traffic_then_interface_is_set():
    # Given
    capture = Capture()

    # When
    capture.capture_traffic()

    # Then
    # This is a minimal test since the method doesn't do much yet
    assert capture.interface == ""


def test_sort_network_protocols():
    # Given
    capture = Capture()
    capture.packets = [Ether() / IP() / TCP(), Ether() / ARP()]

    # When
    result = capture.sort_network_protocols()

    # Then
    assert result[0] == ("Ethernet", 2)


def test_get_all_protocols():
    # Given
    capture = Capture()
    capture.packets = [Ether() / IP() / TCP(), Ether() / ARP()]

    # When
    result = capture.get_all_protocols()

    # Then
    assert result["Ethernet"] == 2
    assert result["ARP"] == 1
    assert result["TCP"] == 1


def test_analyse():
    # Given
    capture = Capture()

    # When
    with (
        patch.object(capture, "get_all_protocols") as mock_get_protocols,
        patch.object(capture, "sort_network_protocols") as mock_sort,
        patch.object(capture, "_gen_summary") as mock_gen_summary,
    ):
        mock_gen_summary.return_value = "Test summary"
        capture.analyse("tcp")

    # Then
    mock_get_protocols.assert_called_once()
    mock_sort.assert_called_once()
    mock_gen_summary.assert_called_once()
    assert capture.summary == "Test summary"


def test_get_summary():
    # Given
    capture = Capture()
    capture.summary = "Test summary"

    # When
    result = capture.get_summary()

    # Then
    assert result == "Test summary"


def test_gen_summary():
    # Given
    capture = Capture()

    # When
    result = capture._gen_summary()

    # Then
    assert result == ""  # Method currently returns empty string


def test_detect_arp_spoofing():
    # Given
    capture = Capture()
    capture.packets = [
        Ether() / ARP(op=2, psrc="192.168.245.1", hwsrc="02:89:e6:3a:b6:81"),
        Ether() / ARP(op=2, psrc="192.168.245.1", hwsrc="02:98:2a:08:d0:a2"),
    ]

    # When
    result = capture.detect_arp_spoofing()

    # Then
    assert len(result) == 1
    assert result[0]["attacker"] == "02:98:2a:08:d0:a2"


def test_detect_port_scan():
    # Given
    capture = Capture()
    capture.packets = []

    for port in range(1, 31):
        capture.packets.append(
            Ether() / IP(src="10.0.0.5") / TCP(dport=port, flags="S")
        )

    # When
    result = capture.detect_port_scan()

    # Then
    assert len(result) == 1
    assert result[0]["type"] == "port_scan"
    assert result[0]["attacker"] == "10.0.0.5"
