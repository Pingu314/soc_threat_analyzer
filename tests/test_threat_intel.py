from src.threat_intel import is_private_ip


class TestIsPrivateIp:
    def test_private_ranges(self):
        assert is_private_ip("192.168.1.10") is True
        assert is_private_ip("10.0.0.1") is True
        assert is_private_ip("172.16.0.1") is True

    def test_public_ips(self):
        assert is_private_ip("8.8.8.8") is False
        assert is_private_ip("185.220.101.1") is False

    def test_invalid_ip(self):
        assert is_private_ip("not_an_ip") is False
