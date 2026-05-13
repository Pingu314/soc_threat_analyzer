from src.risk_scoring import calculate_risk, get_severity, map_mitre


class TestGetSeverity:
    def test_low(self):
        assert get_severity(0) == "LOW"
        assert get_severity(5) == "LOW"

    def test_medium(self):
        assert get_severity(6) == "MEDIUM"
        assert get_severity(11) == "MEDIUM"

    def test_high(self):
        assert get_severity(12) == "HIGH"
        assert get_severity(99) == "HIGH"


class TestCalculateRisk:
    def test_base_score(self):
        assert calculate_risk({"ip": "1.2.3.4", "count": 3}, None) == 9

    def test_suspicious_country(self):
        alert = {"ip": "1.2.3.4", "count": 3}
        intel = {"ip": "1.2.3.4", "country": "RU", "org": "SomeISP"}
        assert calculate_risk(alert, intel) == 14

    def test_tor_node(self):
        alert = {"ip": "1.2.3.4", "count": 3}
        intel = {"ip": "1.2.3.4", "country": "DE", "org": "Tor Network"}
        assert calculate_risk(alert, intel) == 14

    def test_no_intel(self):
        assert calculate_risk({"ip": "1.2.3.4", "count": 2}, None) == 6

    def test_spray_bonus(self):
        alert = {"ip": "1.2.3.4", "count": 3, "distinct_users": ["admin", "root", "guest"]}
        score = calculate_risk(alert, None)
        assert score == 9 + 6  # base + 3 users * 2

    def test_travel_bonus(self):
        alert = {"user": "admin", "count": 2, "distinct_ips": ["1.1.1.1", "2.2.2.2"]}
        score = calculate_risk(alert, None)
        assert score == 6 + 4  # base + 2 IPs * 2

    def test_private_ip_no_extra_score(self):
        """PRIVATE country branch logs but adds no score — internal movement scored normally."""
        alert = {"ip": "192.168.1.1", "count": 3}
        intel = {"ip": "192.168.1.1", "country": "PRIVATE", "org": "Internal Network"}
        score = calculate_risk(alert, intel)
        assert score == 9  # base only, PRIVATE adds nothing

    def test_cn_suspicious_country(self):
        alert = {"ip": "1.2.3.4", "count": 3}
        intel = {"ip": "1.2.3.4", "country": "CN", "org": "SomeISP"}
        assert calculate_risk(alert, intel) == 14

    def test_kp_suspicious_country(self):
        alert = {"ip": "1.2.3.4", "count": 3}
        intel = {"ip": "1.2.3.4", "country": "KP", "org": "SomeISP"}
        assert calculate_risk(alert, intel) == 14


class TestMapMitre:
    def test_brute_force_subtechnique(self):
        assert map_mitre("T1110.001") == "Brute Force: Password Guessing"

    def test_spraying_subtechnique(self):
        assert map_mitre("T1110.003") == "Brute Force: Password Spraying"

    def test_impossible_travel(self):
        assert map_mitre("T1078") == "Valid Accounts: Impossible Travel"

    def test_unknown(self):
        assert map_mitre("T9999") == "T9999"

    def test_none(self):
        assert map_mitre(None) == "UNKNOWN"
