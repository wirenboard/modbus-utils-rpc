# pylint: disable=redefined-outer-name, unused-import, unused-argument, line-too-long
from argparse import Namespace

import pytest
from mqttrpc import client as rpcclient
from pytest_mock import mocker

from modbus_client_rpc import main

test_modbus_parameters = [
    (
        main.rtu,
        0x01,
        0,
        False,
        0,
        1,
        [],
        "000100000001fc1b",
        6,
        False,
    ),
    (
        main.rtu,
        0x02,
        247,
        False,
        65535,
        1,
        [],
        "f702ffff0001ad78",
        6,
        False,
    ),
    (
        main.rtu,
        0x03,
        0,
        False,
        0,
        125,
        [],
        "00030000007d843a",
        255,
        False,
    ),
    (
        main.rtu,
        0x04,
        247,
        True,
        65535,
        2,
        [],
        "f704fffe000234b9",
        9,
        False,
    ),
    (
        main.rtu,
        0x05,
        0,
        False,
        65535,
        0,
        [255],
        "0005ffffff008dcf",
        8,
        False,
    ),
    (
        main.rtu,
        0x06,
        247,
        True,
        65535,
        0,
        [22950],
        "f706fffe59a67692",
        8,
        False,
    ),
    (
        main.rtu,
        0x0F,
        0,
        False,
        0,
        0,
        [0, 255, 0, 100, 0, 50],
        "000f00000006012adf45",
        8,
        False,
    ),
    (
        main.rtu,
        0x10,
        247,
        False,
        65533,
        0,
        [22950, 15406, 4658],
        "f710fffd00030659a63c2e1232ed65",
        8,
        False,
    ),
    (
        main.tcp,
        0x01,
        0,
        False,
        0,
        1,
        [],
        "000000000006000100000001",
        10,
        False,
    ),
    (
        main.tcp,
        0x02,
        247,
        False,
        65535,
        1,
        [],
        "000000000006f702ffff0001",
        10,
        False,
    ),
    (
        main.tcp,
        0x03,
        0,
        False,
        0,
        125,
        [],
        "00000000000600030000007d",
        259,
        False,
    ),
    (
        main.tcp,
        0x04,
        247,
        True,
        65535,
        2,
        [],
        "000000000006f704fffe0002",
        13,
        False,
    ),
    (
        main.tcp,
        0x05,
        0,
        False,
        65535,
        0,
        [255],
        "0000000000060005ffffff00",
        12,
        False,
    ),
    (
        main.tcp,
        0x06,
        247,
        True,
        65535,
        0,
        [22950],
        "000000000006f706fffe59a6",
        12,
        False,
    ),
    (
        main.tcp,
        0x0F,
        0,
        False,
        0,
        0,
        [0, 255, 0, 100, 0, 50],
        "000000000008000f00000006012a",
        12,
        False,
    ),
    (
        main.tcp,
        0x10,
        247,
        False,
        65533,
        0,
        [22950, 15406, 4658],
        "00000000000df710fffd00030659a63c2e1232",
        12,
        False,
    ),
    (main.rtu, 0x07, 0, False, 0, 0, [], "", 0, True),
    (main.rtu, 0x01, 250, False, 0, 0, [], "", 0, True),
    (main.rtu, 0x01, 0, False, 65536, 0, [], "", 0, True),
    (main.rtu, 0x01, 0, True, 0, 0, [], "", 0, True),
    (main.rtu, 0x01, 0, True, 0, 126, [], "", 0, True),
    (main.rtu, 0x01, 0, True, 0, 0, [], "", 0, True),
]


@pytest.mark.parametrize(
    "lib, function, slave_address, address_decrement, start_address, read_count, write_data, expected_message, expected_length,must_fail",
    test_modbus_parameters,
)
def test_create_modbus_message(  # pylint:disable=too-many-arguments
    lib,
    function,
    slave_address,
    address_decrement,
    start_address,
    read_count,
    write_data,
    expected_message,
    expected_length,
    must_fail,
):

    if must_fail:
        with pytest.raises(Exception):
            message, length = main.create_modbus_message(
                lib, function, slave_address, address_decrement, start_address, read_count, write_data
            )
    else:
        message, length = main.create_modbus_message(
            lib, function, slave_address, address_decrement, start_address, read_count, write_data
        )

        if lib == main.rtu:
            assert (expected_message, expected_length) == (message, length)


test_rpc_param = [
    (
        main.get_rtu_params,
        {
            "serialport_host": "rtu_path",
            "baudrate": 9600,
            "parity_port": "N",
            "data_bits": 8,
            "stop_bits": 1,
        },
        {
            "path": "rtu_path",
            "baud_rate": 9600,
            "parity": "N",
            "data_bits": 8,
            "stop_bits": 1,
        },
    ),
    (
        main.get_tcp_params,
        {"serialport_host": "tcp_path", "parity_port": 1000},
        {"ip": "tcp_path", "port": 1000},
    ),
]


@pytest.mark.parametrize("get_path_function, options, expected_path", test_rpc_param)
def test_create_rpc_request(get_path_function, options, expected_path):
    test_message = "message"
    test_response_size = 10
    test_timeout = 10000

    def test_get_path_function(options):
        path = get_path_function(options)
        assert path == expected_path
        return path

    request = main.create_rpc_request(
        Namespace(**options), test_get_path_function, test_message, test_response_size, test_timeout
    )

    assert (request["format"], request["msg"], request["response_size"]) == ("HEX", "message", 10)


test_send_message_params = [
    ("request", "response", "none"),
    ("request", "response", "MQTTRPCError"),
    ("request", "response", "TimeoutError"),
]


@pytest.fixture(params=test_send_message_params)
def send_message_context(request):
    return request.param


def test_send_message(mocker, send_message_context):

    request = send_message_context[0]
    expected_response = send_message_context[1]
    must_fail = send_message_context[2]
    request_timeout = 1000
    args = {"mqtt_broker": "tcp://127.0.0.1:1883", "timeout": request_timeout}

    def test_rpc_call(  # pylint:disable=too-many-arguments
        self, driver, service, method, params, timeout=None
    ):
        assert (
            driver == "wb-mqtt-serial"
            and service == "port"
            and method == "Load"
            and params == request
            and timeout == request_timeout / 1000
        )
        if must_fail == "MQTTRPCError":
            raise rpcclient.MQTTRPCError("message", 0, "data")
        if must_fail == "TimeoutError":
            raise rpcclient.TimeoutError

        return expected_response

    def test_connect(self, ip, port):
        assert ip == "127.0.0.1" and port == 1883

    mocker.patch("modbus_client_rpc.main.rpcclient.TMQTTRPCClient.call", test_rpc_call)

    mocker.patch("modbus_client_rpc.main.MQTTClient.connect", test_connect)
    mocker.patch("modbus_client_rpc.main.MQTTClient.loop_start")
    mocker.patch("modbus_client_rpc.main.MQTTClient.loop_stop")
    mocker.patch("modbus_client_rpc.main.MQTTClient.disconnect")

    if must_fail != "none":
        with pytest.raises(Exception):
            assert (
                main.send_message(Namespace(**args), args["mqtt_broker"], request, args["timeout"])
                == expected_response
            )
    else:
        assert (
            main.send_message(Namespace(**args), args["mqtt_broker"], request, args["timeout"])
            == expected_response
        )


test_parse_rpc_params = [
    ({"response": "modbus_response"}, False),
    ({"Response": "modbus_response"}, True),
    ({"": ""}, True),
]


@pytest.mark.parametrize("rpc_response, must_fail", test_parse_rpc_params)
def test_parse_rpc_response(rpc_response, must_fail):

    if must_fail:
        with pytest.raises(Exception):
            modbus_response = main.parse_rpc_response(
                rpc_response,
            )
    else:
        modbus_response = main.parse_rpc_response(
            rpc_response,
        )

        assert rpc_response["response"] == modbus_response


test_modbus_response_params = [
    (main.rtu, 0x01, "1604010e000152d2", "160402fe348c84", False),
    (main.rtu, 0x01, "1604010e000152d2", "160402fe348c80", True),
]


@pytest.mark.parametrize("lib, function, modrequest, response, must_fail", test_modbus_response_params)
def test_parse_modbus_response(lib, function, modrequest, response, must_fail):
    if must_fail:
        with pytest.raises(Exception):
            main.parse_modbus_response(lib, function, modrequest, response)
    else:
        main.parse_modbus_response(lib, function, modrequest, response)


test_argv_params_positive = [
    (
        [
            "test",
            "--debug",
            "-mrtu",
            "-pnone",
            "-b9600",
            "-s2",
            "-a22",
            "/dev/ttyRS485-1",
            "-t0x06",
            "-r0x78",
            "10",
        ],
        Namespace(
            debug=True,
            mode="rtu",
            slave_addr=22,
            read_count=1,
            start_addr=120,
            func_type=6,
            timeout=1000,
            address_decrement=False,
            baudrate=9600,
            data_bits=8,
            stop_bits=2,
            parity_port="N",
            mqtt_broker="unix:///var/run/mosquitto/mosquitto.sock",
            serialport_host="/dev/ttyRS485-1",
            write_data=[10],
        ),
        [],
    ),
    (
        ["test", "-mtcp", "-t1", "192.168.10.4", "-p1000", "-r5", "-0", "-o100"],
        Namespace(
            debug=False,
            mode="tcp",
            slave_addr=1,
            read_count=1,
            start_addr=5,
            func_type=1,
            timeout=100,
            address_decrement=True,
            baudrate=9600,
            data_bits=8,
            stop_bits=1,
            parity_port=1000,
            mqtt_broker="unix:///var/run/mosquitto/mosquitto.sock",
            serialport_host="192.168.10.4",
            write_data=[],
        ),
        [],
    ),
    (
        ["test", "-mrtu", "-r10", "/dev/ttyRS485-1", "-a22", "-t0x05", "--broker", "tcp://192.168.10.6:1883"],
        Namespace(
            debug=False,
            mode="rtu",
            slave_addr=22,
            read_count=1,
            start_addr=10,
            func_type=5,
            timeout=1000,
            address_decrement=False,
            baudrate=9600,
            data_bits=8,
            stop_bits=1,
            parity_port=None,
            mqtt_broker="tcp://192.168.10.6:1883",
            serialport_host="/dev/ttyRS485-1",
            write_data=[],
        ),
        [],
    ),
]


test_argv_params_negative = [
    (["test", "-r5", "-pnone"], [], []),
    (["test", "-mtcp", "-t1", "192.168.10.4", "abc", "def"], [], []),
    (["test", "-mascii"], [], []),
]


@pytest.mark.parametrize("argv, expected_options, expected_error_options", test_argv_params_positive)
def test_parse_options_positive(argv, expected_options, expected_error_options):
    options, error_options = main.parse_options(argv[1:])
    assert (options, error_options) == (expected_options, expected_error_options)


@pytest.mark.xfail
@pytest.mark.parametrize("argv, expected_options, expected_error_options", test_argv_params_negative)
def test_parse_options_negative(argv, expected_options, expected_error_options):
    options, error_options = main.parse_options(argv[1:])
    assert (options, error_options) == (expected_options, expected_error_options)


@pytest.fixture(params=test_argv_params_positive)
def main_context(request):
    return request.param


def test_main(mocker, main_context):
    test_argv = main_context[0]
    test_options = main_context[1]

    test_modbus_message = [0x01, 0x02, 0x03]
    test_response_size = 5
    test_rpc_request = {"message": "request"}
    test_rpc_response = {"message": "response"}
    test_modbus_response = [0x04, 0x05, 0x06]

    def parse_options(argv):
        assert argv == test_argv[1:]
        return test_options, []

    def create_modbus_message(  # pylint:disable=too-many-arguments
        lib, function, slave_address, address_decrement, start_address, read_count, write_data
    ):
        if test_options.mode == "rtu":
            assert lib == main.rtu
        else:
            assert lib == main.tcp
        assert function == test_options.func_type
        assert slave_address == test_options.slave_addr
        assert address_decrement == test_options.address_decrement
        assert start_address == test_options.start_addr
        assert read_count == test_options.read_count
        assert write_data == test_options.write_data
        return test_modbus_message, test_response_size

    def create_rpc_request(args, get_port_params, modbus_message, response_size, timeout):
        assert args == test_options
        if test_options.mode == "rtu":
            assert get_port_params == main.get_rtu_params  # pylint:disable=comparison-with-callable
        else:
            assert get_port_params == main.get_tcp_params  # pylint:disable=comparison-with-callable
        assert modbus_message == test_modbus_message
        assert response_size == test_response_size
        assert timeout == test_options.timeout
        return test_rpc_request

    def send_message(args, broker, message, timeout):
        assert args == test_options
        assert message == test_rpc_request
        assert broker == test_options.mqtt_broker
        assert timeout == test_options.timeout
        return test_rpc_response

    def parse_rpc_response(response):
        assert response == test_rpc_response
        return test_modbus_response

    def parse_modbus_response(lib, function, request, response):
        if test_options.mode == "rtu":
            assert lib == main.rtu
        else:
            assert lib == main.tcp
        assert function == test_options.func_type
        assert request == test_modbus_message
        assert response == test_modbus_response

    mocker.patch("modbus_client_rpc.main.parse_options", parse_options)
    mocker.patch("modbus_client_rpc.main.create_modbus_message", create_modbus_message)
    mocker.patch("modbus_client_rpc.main.create_rpc_request", create_rpc_request)
    mocker.patch("modbus_client_rpc.main.send_message", send_message)
    mocker.patch("modbus_client_rpc.main.parse_rpc_response", parse_rpc_response)
    mocker.patch("modbus_client_rpc.main.parse_modbus_response", parse_modbus_response)

    main.main(test_argv)


def test_dummy():
    assert True
