# pylint: disable=redefined-outer-name, unused-import, unused-argument, line-too-long
from argparse import Namespace

import pytest
from mqttrpc import client as rpcclient
from pytest_mock import mocker

from modbus_client_rpc import main

test_modbus_parameters = [
    (
        0x01,
        False,
        0,
        1,
        [],
        "",
        1,
        False,
    ),
    (
        0x02,
        False,
        65535,
        1,
        [],
        "",
        1,
        False,
    ),
    (
        0x03,
        False,
        0,
        125,
        [],
        "",
        125,
        False,
    ),
    (
        0x04,
        True,
        65535,
        2,
        [],
        "",
        2,
        False,
    ),
    (
        0x05,
        False,
        65535,
        0,
        [255],
        "ff00",
        1,
        False,
    ),
    (
        0x06,
        True,
        65535,
        0,
        [22950],
        "59a6",
        1,
        False,
    ),
    (
        0x0F,
        False,
        0,
        0,
        [0, 255, 0, 100, 0, 50],
        "2a",
        6,
        False,
    ),
    (
        0x10,
        False,
        65533,
        0,
        [22950, 15406, 4658],
        "59a63c2e1232",
        3,
        False,
    ),
    (0x07, False, 0, 0, [], "", 0, True),
    (0x01, False, 0, 0, [], "", 0, True),
    (0x01, False, 65536, 0, [], "", 0, True),
    (0x01, True, 0, 0, [], "", 0, True),
    (0x01, True, 0, 126, [], "", 126, False),  # it's fun, but reading 125 *coils* is actually allowed
    (0x01, True, 0, 0, [], "", 0, True),
]


@pytest.mark.parametrize(
    "function, address_decrement, start_address, read_count, write_data, expected_rpc_payload, expected_rpc_count,must_fail",
    test_modbus_parameters,
)
def test_get_modbus_rpc_payload(  # pylint:disable=too-many-arguments
    function,
    address_decrement,
    start_address,
    read_count,
    write_data,
    expected_rpc_payload,
    expected_rpc_count,
    must_fail,
):

    if must_fail:
        with pytest.raises(Exception):
            message, length = main.get_modbus_rpc_payload_and_count(
                function, address_decrement, start_address, read_count, write_data
            )
    else:
        message, length = main.get_modbus_rpc_payload_and_count(
            function, address_decrement, start_address, read_count, write_data
        )
        assert (expected_rpc_payload, expected_rpc_count) == (message, length)


test_rpc_param = [
    (
        main.get_rtu_params,
        "rtu",
        "modbus",
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
        "tcp",
        "modbus-tcp",
        {"serialport_host": "tcp_path", "parity_port": 1000},
        {"ip": "tcp_path", "port": 1000},
    ),
    (
        main.get_tcp_params,
        "rtuovertcp",
        "modbus",
        {"serialport_host": "tcp_path", "parity_port": 1000},
        {"ip": "tcp_path", "port": 1000},
    ),
]


@pytest.mark.parametrize(
    "get_path_function, modbus_mode, rpc_protocol, options, expected_path", test_rpc_param
)
def test_create_rpc_request(get_path_function, modbus_mode, rpc_protocol, options, expected_path):
    test_message = "01020304"
    test_slave_addr = 123
    test_func_type = 0x10
    test_start_addr = 200
    test_register_count = 2
    test_timeout = 5000

    def test_get_path_function(options):
        path = get_path_function(options)
        assert path == expected_path
        return path

    request = main.create_rpc_request(
        Namespace(**options),
        modbus_mode,
        test_get_path_function,
        test_slave_addr,
        test_func_type,
        test_start_addr,
        test_register_count,
        test_message,
        test_timeout,
    )

    assert request["format"] == "HEX"
    assert request["msg"] == test_message
    assert request["slave_id"] == test_slave_addr
    assert request["function"] == test_func_type
    assert request["address"] == test_start_addr
    assert request["count"] == test_register_count
    assert request["protocol"] == rpc_protocol
    assert request["total_timeout"] == test_timeout


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
    (0x01, 8, "fe34", False),
    (0x03, 2, "000a0000", False),
]


@pytest.mark.parametrize("function, register_count, response, must_fail", test_modbus_response_params)
def test_parse_modbus_response(function, register_count, response, must_fail):
    if must_fail:
        with pytest.raises(Exception):
            main.parse_modbus_response(function, register_count, response)
    else:
        main.parse_modbus_response(function, register_count, response)


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

    test_payload_str = "01020304"
    test_register_count = 5
    test_rpc_request = {"message": "request"}
    test_rpc_response = {"response": "040506"}

    def parse_options(argv):
        assert argv == test_argv[1:]
        return test_options, []

    def get_modbus_rpc_payload_and_count(function, address_decrement, start_address, read_count, write_data):
        assert function == test_options.func_type
        assert address_decrement == test_options.address_decrement
        assert start_address == test_options.start_addr
        assert read_count == test_options.read_count
        assert write_data == test_options.write_data
        return test_payload_str, test_register_count

    def create_rpc_request(
        args,
        modbus_mode,
        get_port_params,
        slave_addr,
        function,
        start_addr,
        register_count,
        payload_str,
        timeout,
    ):
        assert args == test_options
        if test_options.mode == "rtu":
            assert get_port_params == main.get_rtu_params  # pylint:disable=comparison-with-callable
        else:
            assert get_port_params == main.get_tcp_params  # pylint:disable=comparison-with-callable
        assert slave_addr == test_options.slave_addr
        assert function == test_options.func_type
        assert start_addr == test_options.start_addr
        assert register_count == test_register_count
        assert payload_str == test_payload_str
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
        return "040506"

    def parse_modbus_response(function, register_count, response):
        assert function == test_options.func_type
        assert register_count == test_register_count
        assert response == "040506"

    mocker.patch("modbus_client_rpc.main.parse_options", parse_options)
    mocker.patch("modbus_client_rpc.main.get_modbus_rpc_payload_and_count", get_modbus_rpc_payload_and_count)
    mocker.patch("modbus_client_rpc.main.create_rpc_request", create_rpc_request)
    mocker.patch("modbus_client_rpc.main.send_message", send_message)
    mocker.patch("modbus_client_rpc.main.parse_rpc_response", parse_rpc_response)
    mocker.patch("modbus_client_rpc.main.parse_modbus_response", parse_modbus_response)

    main.main(test_argv)
