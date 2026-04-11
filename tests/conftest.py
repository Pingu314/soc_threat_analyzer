import pytest
from datetime import datetime, timedelta

from config.settings import SPRAY_THRESHOLD, TRAVEL_THRESHOLD


@pytest.fixture
def base_time():
    return datetime(2026, 1, 1, 10, 0, 0)

@pytest.fixture
def brute_force_logs(base_time):
    return [{"ip": "185.220.101.1",
             "user": "admin",
             "status": "FAILED",
             "timestamp": base_time + timedelta(seconds=i * 10)}
            for i in range(3)]

@pytest.fixture
def spray_logs(base_time):
    users = [f"user_{i}" for i in range(SPRAY_THRESHOLD)]
    return [{"ip": "45.83.64.1",
             "user": user,
             "status": "FAILED",
             "timestamp": base_time + timedelta(minutes=i)}
            for i, user in enumerate(users)]

@pytest.fixture
def travel_logs(base_time):
    ips = [f"10.0.0.{i+1}" for i in range(TRAVEL_THRESHOLD)]
    return [{"ip": ip,
             "user": "admin",
             "status": "FAILED",
             "timestamp": base_time + timedelta(minutes=i)}
            for i, ip in enumerate(ips)]

@pytest.fixture
def mixed_logs(brute_force_logs, spray_logs, travel_logs):
    return brute_force_logs + spray_logs + travel_logs