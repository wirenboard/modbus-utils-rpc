from argparse import Namespace

import pytest

from modbus_scanner_rpc import main

working_args_parsing_cases = [
    (
        ["--debug", "--broker", "127.0.0.1", "-o", "100", "/dev/ttyRS485-1"],
        Namespace(
            debug=True,
            mqtt_broker="127.0.0.1",
            timeout=100,
            response_timeout=None,
            serial_port="/dev/ttyRS485-1",
        ),
    ),
    (
        ["--broker", "127.0.0.1", "-o", "100", "/dev/ttyRS485-1"],
        Namespace(
            debug=False,
            mqtt_broker="127.0.0.1",
            timeout=100,
            response_timeout=None,
            serial_port="/dev/ttyRS485-1",
        ),
    ),
    (
        ["-o", "100", "/dev/ttyRS485-1"],
        Namespace(
            debug=False,
            mqtt_broker="unix:///var/run/mosquitto/mosquitto.sock",
            timeout=100,
            response_timeout=None,
            serial_port="/dev/ttyRS485-1",
        ),
    ),
    (
        [
            "/dev/ttyRS485-1",
        ],
        Namespace(
            debug=False,
            mqtt_broker="unix:///var/run/mosquitto/mosquitto.sock",
            timeout=10000,
            response_timeout=None,
            serial_port="/dev/ttyRS485-1",
        ),
    ),
    (
        ["--response-timeout", "250", "/dev/ttyRS485-1"],
        Namespace(
            debug=False,
            mqtt_broker="unix:///var/run/mosquitto/mosquitto.sock",
            timeout=10000,
            response_timeout=250,
            serial_port="/dev/ttyRS485-1",
        ),
    ),
]


erroneous_args_parsing_cases = [
    (
        [
            "-h",
        ],
        [],
    ),
    (
        ["--debug", "-o", "100"],
        [],
    ),
    (
        ["--debug", "--broker", "127.0.0.1", "-o", "100", "/dev/ttyRS485-1", "--BANG"],
        [],
    ),
]


@pytest.mark.parametrize("argv, expected_options", working_args_parsing_cases)
def test_parse_options_positive(argv, expected_options):
    parser = main.get_parser()
    options = parser.parse_args(argv)
    assert options == expected_options


@pytest.mark.parametrize("argv, expected_options", erroneous_args_parsing_cases)
def test_parse_options_erroneous(argv, expected_options):
    with pytest.raises(SystemExit):
        parser = main.get_parser()
        options = parser.parse_args(argv)
        assert options == expected_options


@pytest.mark.parametrize("scan_function", [main.start_scan, main.continue_scan])
def test_scan_timeout_units(scan_function):
    """mqttrpc waits in seconds, wb-mqtt-serial's total_timeout is in ms"""
    calls = []

    def rpc_call(_driver, _service, _method, params, timeout=None):
        calls.append((params, timeout))
        return {"response": "fd6004c9f3"}

    scan_function("/dev/ttyRS485-1", 9600, "N", Namespace(call=rpc_call), 10000)

    params, timeout = calls[0]
    assert timeout == 10
    assert params["total_timeout"] == 10000
