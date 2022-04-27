from argparse import Namespace

import pytest
from modbus_utils_rpc import main

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
    ),
    pytest.param(main.rtu, 0x07, 0, False, 0, 0, [], "", 0, marks=pytest.mark.xfail),
    pytest.param(main.rtu, 0x01, 250, False, 0, 0, [], "", 0, marks=pytest.mark.xfail),
    pytest.param(main.rtu, 0x01, 0, False, 65536, 0, [], "", 0, marks=pytest.mark.xfail),
    pytest.param(main.rtu, 0x01, 0, True, 0, 0, [], "", 0, marks=pytest.mark.xfail),
    pytest.param(main.rtu, 0x01, 0, True, 0, 126, [], "", 0, marks=pytest.mark.xfail),
    pytest.param(main.rtu, 0x01, 0, True, 0, 0, [], "", 0, marks=pytest.mark.xfail),
]


@pytest.mark.parametrize(
    "lib, function, slave_address, address_decrement, start_address, read_count, write_data, expected_message, expected_length",
    test_modbus_parameters,
)
def test_create_modbus_message(
    lib,
    function,
    slave_address,
    address_decrement,
    start_address,
    read_count,
    write_data,
    expected_message,
    expected_length,
):

    message, length = main.create_modbus_message(
        lib, function, slave_address, address_decrement, start_address, read_count, write_data
    )

    if lib == main.rtu:
        assert (expected_message, expected_length) == (message, length)
    elif lib == main.tcp:
        assert (expected_message[4:], expected_length) == (message[4:], length)


test_rpc_param = [
    (
        main.get_rtu_params,
        {"serialport_host": "rtu_path"},
        {"path": "rtu_path"},
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

    def test_get_path_function(options):
        path = get_path_function(options)
        assert path == expected_path
        return path

    request = main.create_rpc_request(
        Namespace(**options), test_get_path_function, test_message, test_response_size
    )

    assert (request["format"], request["msg"], request["response_size"]) == ("HEX", "message", 10)


test_send_message_params = [("request", "response")]


@pytest.fixture(params=test_send_message_params)
def send_message_context(request):
    return request.param


def test_send_message(mocker, send_message_context):

    request = send_message_context[0]
    expected_response = send_message_context[1]
    broker = main.DEFAULT_BROKER
    request_timeout = 1000

    def test_rpc_call(self, driver, service, method, params, timeout=None):
        assert (
            driver == "wb-mqtt-serial"
            and service == "port"
            and method == "Load"
            and params == request
            and timeout == request_timeout / 1000
        )
        return expected_response

    def test_connect(self, ip, port):
        assert {"ip": ip, "port": port} == main.DEFAULT_BROKER

    mocker.patch("modbus_utils_rpc.main.rpcclient.TMQTTRPCClient.call", test_rpc_call)

    mocker.patch("modbus_utils_rpc.main.mosquitto.Mosquitto.connect", test_connect)
    mocker.patch("modbus_utils_rpc.main.mosquitto.Mosquitto.loop_start")
    mocker.patch("modbus_utils_rpc.main.mosquitto.Mosquitto.loop_stop")
    mocker.patch("modbus_utils_rpc.main.mosquitto.Mosquitto.disconnect")

    assert main.send_message(broker, request, request_timeout) == expected_response


test_parse_rpc_params = [
    ({"result_code": 0, "response": "response", "error_msg": "Error"}),
    pytest.param({"result_code": -1, "response": "response", "error_msg": "Error"}, marks=pytest.mark.xfail),
    pytest.param(
        {"result_code": -100, "response": "response", "error_msg": "Error"}, marks=pytest.mark.xfail
    ),
]


@pytest.mark.parametrize("response", test_parse_rpc_params)
def test_parse_rpc_response(response):
    assert response["response"] == main.parse_rpc_response(
        Namespace(**{"serialport_host": "rtu_path"}), main.get_rtu_params, "request", response
    )


test_modbus_response_params = [
    (main.rtu, 0x01, "1604010e000152d2", "160402fe348c84"),
    pytest.param(main.rtu, 0x01, "1604010e000152d2", "160402fe348c80", marks=pytest.mark.xfail),
]


@pytest.mark.parametrize("lib, function, modrequest, response", test_modbus_response_params)
def test_parse_modbus_response(lib, function, modrequest, response):
    assert main.parse_modbus_response(lib, function, modrequest, response) is None


test_argv_params = [
    (
        ["--debug", "-mrtu", "-pnone", "-b9600", "-s2", "-a22", "/dev/ttyRS485-1", "-t0x06", "-r0x78", "10"],
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
            parity_port="none",
            mqtt_broker={"ip": "127.0.0.1", "port": 1883},
            serialport_host="/dev/ttyRS485-1",
            write_data=[10],
        ),
        [],
    ),
    (
        ["-mtcp", "-t1", "192.168.10.4", "-p1000", "-r5", "-0", "-o100"],
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
            mqtt_broker={"ip": "127.0.0.1", "port": 1883},
            serialport_host="192.168.10.4",
            write_data=[],
        ),
        [],
    ),
    (
        ["-mrtu", "-r10", "/dev/ttyRS485-1", "-a22", "-t0x05", "--broker", "192.168.10.6:1883"],
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
            mqtt_broker={"ip": "192.168.10.6", "port": 1883},
            serialport_host="/dev/ttyRS485-1",
            write_data=[],
        ),
        [],
    ),
    pytest.param(["-r5", "-pnone"], [], [], marks=pytest.mark.xfail),
    pytest.param(["-mtcp", "-t1", "192.168.10.4", "abc", "def"], [], [], marks=pytest.mark.xfail),
    pytest.param(["-mascii"], [], [], marks=pytest.mark.xfail),
]


@pytest.mark.parametrize("argv, expected_options, expected_error_options", test_argv_params)
def test_parse_options(argv, expected_options, expected_error_options):
    options, error_options = main.parse_options(argv)
    assert (options, error_options) == (expected_options, expected_error_options)
