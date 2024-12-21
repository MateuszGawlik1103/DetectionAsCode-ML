import sys
from io import StringIO
import pytest
from attacks import *
from main import detect

TARGET_IP = "127.0.0.1"


@pytest.fixture
def output():
    output = StringIO()
    sys.stdout = output
    yield output
    sys.stdout = sys.__stdout__


def test_http_get(output):
    packet = http_get(TARGET_IP)
    detect(packet, csv_file=None)
    assert "HTTP GET" in output.getvalue()


def test_ssh_connection(output):
    packet = ssh_connection(TARGET_IP)
    detect(packet, csv_file=None)
    assert "SSH" in output.getvalue()


def test_icmp_ping(output):
    packet = icmp_ping(TARGET_IP)
    detect(packet, csv_file=None)
    assert "ICMP" in output.getvalue()


def test_syn_flood(output):
    packet = syn_flood(TARGET_IP, 55555, 1)
    for i in range(150):
        detect(packet, csv_file=None)
    assert "SYN" in output.getvalue()
