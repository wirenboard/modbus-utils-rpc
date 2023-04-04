from argparse import Namespace

import pytest

from modbus_scanner_rpc import main


working_args_parsing_cases = [
    (
        ["--debug", "--broker", "127.0.0.1", "-o", "100", "/dev/ttyRS485-1"],
        Namespace(debug=True, mqtt_broker="127.0.0.1", timeout=100, serial_port="/dev/ttyRS485-1"),
    ),
    (
        ["--broker", "127.0.0.1", "-o", "100", "/dev/ttyRS485-1"],
        Namespace(debug=False, mqtt_broker="127.0.0.1", timeout=100, serial_port="/dev/ttyRS485-1"),
    ),
    (
        ["-o", "100", "/dev/ttyRS485-1"],
        Namespace(
            debug=False,
            mqtt_broker="unix:///var/run/mosquitto/mosquitto.sock",
            timeout=100,
            serial_port="/dev/ttyRS485-1",
        ),
    ),
    (
        ["/dev/ttyRS485-1",],
        Namespace(
            debug=False,
            mqtt_broker="unix:///var/run/mosquitto/mosquitto.sock",
            timeout=10000,
            serial_port="/dev/ttyRS485-1",
        ),
    ),
]


erroneous_args_parsing_cases = [
    (["-h",], [], ),
    (["--debug", "-o", "100"], [],),
    (["--debug", "--broker", "127.0.0.1", "-o", "100", "/dev/ttyRS485-1", "--BANG"], [],),
]


@pytest.mark.parametrize("argv, expected_options", working_args_parsing_cases)
def test_parse_options_positive(argv, expected_options):
    options = main.parse_args(argv)
    assert options == expected_options


@pytest.mark.parametrize("argv, expected_options", erroneous_args_parsing_cases)
def test_parse_options_erroneous(argv, expected_options):
    with pytest.raises(SystemExit):
        options = main.parse_args(argv)
        assert options == expected_options
