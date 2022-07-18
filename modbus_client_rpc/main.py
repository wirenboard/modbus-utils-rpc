import argparse
import logging
import os
import struct
import sys
from contextlib import contextmanager
from enum import IntEnum

import paho.mqtt.client as mosquitto
import umodbus.exceptions
from modbus_client_rpc import exceptions
from mqttrpc import client as rpcclient
from umodbus import functions
from umodbus.client import tcp
from umodbus.client.serial import rtu

DEFAULT_BROKER = {"ip": "127.0.0.1", "port": 1883}

logger = logging.getLogger(__name__)


class RPCResultCode(IntEnum):
    RPC_OK = 0
    RPC_WRONG_PARAM_SET = -1
    RPC_WRONG_PARAM_VALUE = -2
    RPC_WRONG_PORT = -3
    RPC_WRONG_IO = -4
    RPC_WRONG_RESPONSE_LEN = -5


class ResultCode(IntEnum):
    OK = 0
    OPERATION_ERROR = 1
    USER_INPUT_ERROR = 2


def parse_hex_or_dec(data):
    return int(data, 0)


def parse_parity_or_tcpport(data):
    if data in ("none", "even", "odd"):
        return data
    else:
        try:
            return parse_hex_or_dec(data)
        except ValueError as error:
            logger.error("Invalid value %s for -p option. Set {none|even|odd} or port number", data)
            raise error


def parse_broker_host(data):
    host = data.split(":")
    return {"ip": host[0], "port": int(host[1])}


def get_tcp_params(args):
    return {"ip": args.serialport_host, "port": args.parity_port}


def get_rtu_params(args):
    return {"path": args.serialport_host}


def create_modbus_message(
    lib, function, slave_address, address_decrement, start_address, read_count, write_data
):
    """Function accept modbus params and return tuple:
    string type message with expected response size

    Returns:
        string: message
        int: expected response size
    """

    try:
        if address_decrement:
            start_address -= 1

        if function in (
            functions.WRITE_SINGLE_COIL,
            functions.WRITE_SINGLE_REGISTER,
            functions.WRITE_MULTIPLE_COILS,
            functions.WRITE_MULTIPLE_REGISTERS,
        ):
            logger.debug("Data to write: %s", "".join("0x{:02x} ".format(x) for x in write_data))

        if function in (functions.WRITE_SINGLE_COIL, functions.WRITE_MULTIPLE_COILS):
            write_data = [0 if x == 0 else 1 for x in write_data]

        if function == functions.READ_COILS:
            message_byte = lib.read_coils(slave_address, start_address, read_count)
        elif function == functions.READ_DISCRETE_INPUTS:
            message_byte = lib.read_discrete_inputs(slave_address, start_address, read_count)
        elif function == functions.READ_HOLDING_REGISTERS:
            message_byte = lib.read_holding_registers(slave_address, start_address, read_count)
        elif function == functions.READ_INPUT_REGISTERS:
            message_byte = lib.read_input_registers(slave_address, start_address, read_count)
        elif function == functions.WRITE_SINGLE_COIL:
            message_byte = lib.write_single_coil(slave_address, start_address, write_data[0])
        elif function == functions.WRITE_SINGLE_REGISTER:
            message_byte = lib.write_single_register(slave_address, start_address, write_data[0])
        elif function == functions.WRITE_MULTIPLE_COILS:
            message_byte = lib.write_multiple_coils(slave_address, start_address, write_data)
        elif function == functions.WRITE_MULTIPLE_REGISTERS:
            message_byte = lib.write_multiple_registers(slave_address, start_address, write_data)

        logger.debug("%s", "".join("[{:02x}]".format(x) for x in message_byte))

        message_str = "".join("{:02x}".format(x) for x in message_byte)
        response_size = lib.expected_response_size(message_byte)

    except (struct.error, umodbus.exceptions.ModbusError, IndexError) as error:
        raise exceptions.ModbusParametersError from error

    return message_str, response_size


def create_rpc_request(args, get_port_params, modbus_message, response_size):
    rpc_request = get_port_params(args)
    rpc_request.update({"response_size": response_size, "format": "HEX", "msg": modbus_message})
    return rpc_request


@contextmanager
def mqtt_client(name, broker=DEFAULT_BROKER):
    try:
        client = mosquitto.Mosquitto(name)
        logger.debug("Connecting to broker %s:%s", broker["ip"], broker["port"])
        client.connect(broker["ip"], broker["port"])
        client.loop_start()
        yield client
    except (TimeoutError, ConnectionRefusedError) as error:
        raise exceptions.BrokerConnectionError from error
    finally:
        client.loop_stop()
        client.disconnect()


def send_message(broker, message, timeout):
    with mqtt_client("modbus-utils-rpc-%d" % os.getpid(), broker) as client:
        try:
            rpc_client = rpcclient.TMQTTRPCClient(client)
            client.on_message = rpc_client.on_mqtt_message

            logger.debug("RPC Client -> %s (%d timeout ms)", message, timeout)
            # RPC Client accepts timeout in seconds
            response = rpc_client.call("wb-mqtt-serial", "port", "Load", message, timeout / 1000)
            logger.debug("RPC Client <- %s", response)

        except (rpcclient.TimeoutError) as error:
            raise exceptions.RPCClientTimeoutError from error

        return response


def parse_rpc_response(args, get_port_params, request, response):
    result_code = int(response["result_code"])
    response_message = response["response"]
    error_message = response["error_msg"]

    logger.debug("Error message: %s", error_message)
    logger.debug("Result code: %d", result_code)

    if result_code != RPCResultCode.RPC_OK:
        print("ERROR occurred")
        raise exceptions.RPCError(result_code, get_port_params(args), request, response)

    return response_message


def parse_modbus_response(lib, function, request, response):

    try:
        response_byte = bytearray.fromhex(response)

        logger.debug("%s", "".join("<{:02x}>".format(x) for x in response_byte))

        data = lib.parse_response_adu(response_byte, bytearray.fromhex(request))

        if function in (functions.READ_COILS, functions.READ_DISCRETE_INPUTS):

            print("SUCCESS: read", len(data), "elements:")
            print("\tData:", "".join("0x{:02x} ".format(x) for x in data))

        elif function in (functions.READ_HOLDING_REGISTERS, functions.READ_INPUT_REGISTERS):

            print("SUCCESS: read", len(data), "elements:")
            print("\tData:", "".join("0x{:04x} ".format(x) for x in data))

        elif function in (functions.WRITE_SINGLE_COIL, functions.WRITE_SINGLE_REGISTER):
            print("SUCCESS: written 1 element")
        else:
            print("SUCCESS: Coils/Registers written:", data)

    except (struct.error, umodbus.exceptions.ModbusError) as error:
        raise exceptions.ModbusParseError from error


def handle_rpcumodbusparameterserror(args):
    logger.error("Wrong modbus parameters:")
    logger.error("\tFunction type %d", args.func_type)
    logger.error("\tSlave address % d", args.slave_addr)
    logger.error("\tStart address % d", args.start_addr)
    logger.error("\tStart address decrement: %r", args.address_decrement)
    logger.error("\tRead count % d", args.read_count)
    logger.error("\tWrite data % s", tuple(args.write_data), exc_info=(logger.level <= logging.DEBUG))
    return ResultCode.USER_INPUT_ERROR


def handle_brokerconnectionerror():
    logger.error("There is no connection with the broker", exc_info=(logger.level <= logging.DEBUG))
    return ResultCode.OPERATION_ERROR


def handle_rpcclienttimeouterror(timeout):
    logger.error("Mqtt-rpc client timeout error, timeout %d ms", timeout)
    return ResultCode.OPERATION_ERROR


def handle_rpcumodbusparseerror(response):
    logger.error("Error occurred while parsing modbus response:")
    logger.error("%s", "".join("[{:02x}]".format(x) for x in bytearray.fromhex(response)))
    return ResultCode.OPERATION_ERROR


def handle_rpcerror(error):

    if error.result_code == RPCResultCode.RPC_WRONG_PARAM_SET:
        logger.error("Wrong RPC request parameters set: %s", error.rpc_parameters)
        result_code = ResultCode.OPERATION_ERROR

    elif error.result_code == RPCResultCode.RPC_WRONG_PARAM_VALUE:
        logger.error("Wrong RPC parameter values: %s", error.rpc_parameters)
        result_code = ResultCode.USER_INPUT_ERROR

    elif error.result_code == RPCResultCode.RPC_WRONG_PORT:
        logger.error("Requested port doesn't exist: %s", error.port_path)
        result_code = ResultCode.USER_INPUT_ERROR

    elif error.result_code == RPCResultCode.RPC_WRONG_IO:
        logger.error("Device IO error: %s", error.port_path)
        result_code = ResultCode.OPERATION_ERROR

    elif error.result_code == RPCResultCode.RPC_WRONG_RESPONSE_LEN:
        logger.error("Wrong expected response length:")
        logger.error("\tExpected %d", error.rpc_parameters["response_size"])
        logger.error("\tActual % d", len(error.rpc_response["response"]))
        result_code = ResultCode.OPERATION_ERROR

    return result_code


def process_request(args, lib, get_port_params):

    try:
        modbus_msg_str, modbus_resp_size = create_modbus_message(
            lib,
            args.func_type,
            args.slave_addr,
            args.address_decrement,
            args.start_addr,
            args.read_count,
            args.write_data,
        )

        rpc_request = create_rpc_request(args, get_port_params, modbus_msg_str, modbus_resp_size)

        rpc_response = send_message(args.mqtt_broker, rpc_request, args.timeout)

        modbus_resp_str = parse_rpc_response(args, get_port_params, rpc_request, rpc_response)

        parse_modbus_response(lib, args.func_type, modbus_msg_str, modbus_resp_str)

        result_code = ResultCode.OK

    except exceptions.ModbusParametersError:
        result_code = handle_rpcumodbusparameterserror(args)
    except exceptions.BrokerConnectionError:
        result_code = handle_brokerconnectionerror()
    except exceptions.RPCClientTimeoutError:
        result_code = handle_rpcclienttimeouterror(args.timeout)
    except exceptions.ModbusParseError:
        result_code = handle_rpcumodbusparseerror(modbus_resp_str)
    except exceptions.RPCError as error:
        result_code = handle_rpcerror(error)

    return result_code


def parse_options(argv=sys.argv):

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--debug",
        help="Enable debug output",
        default=False,
        dest="debug",
        required=False,
        action="store_true",
    )
    parser.add_argument(
        "-m",
        help="Mode",
        type=str,
        choices=["tcp", "rtu"],
        dest="mode",
        required=True,
    )
    parser.add_argument(
        "-a",
        help="Slave address",
        type=parse_hex_or_dec,
        default=1,
        dest="slave_addr",
        required=False,
    )
    parser.add_argument(
        "-c",
        help="Read Count",
        type=parse_hex_or_dec,
        default=1,
        dest="read_count",
        required=False,
    )
    parser.add_argument(
        "-r",
        help="First reg's addr",
        type=parse_hex_or_dec,
        default=100,
        dest="start_addr",
        required=False,
    )
    parser.add_argument(
        "-t",
        help="Function type",
        type=parse_hex_or_dec,
        choices=[
            functions.READ_COILS,
            functions.READ_DISCRETE_INPUTS,
            functions.READ_HOLDING_REGISTERS,
            functions.READ_INPUT_REGISTERS,
            functions.WRITE_SINGLE_COIL,
            functions.WRITE_SINGLE_REGISTER,
            functions.WRITE_MULTIPLE_COILS,
            functions.WRITE_MULTIPLE_REGISTERS,
        ],
        dest="func_type",
        required=True,
    )
    parser.add_argument(
        "-o",
        help="Timeout, ms",
        type=parse_hex_or_dec,
        default=1000,
        dest="timeout",
        required=False,
    )
    parser.add_argument(
        "-0",
        help="First reg's address decrement",
        default=False,
        dest="address_decrement",
        required=False,
        action="store_true",
    )

    parser.add_argument(
        "-b",
        help="Baudrate",
        type=parse_hex_or_dec,
        default=9600,
        dest="baudrate",
        choices=[50, 75, 110, 150, 300, 600, 1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200],
        required=False,
    )
    parser.add_argument(
        "-d",
        help="Data bits",
        type=parse_hex_or_dec,
        default=8,
        dest="data_bits",
        choices=[7, 8],
        required=False,
    )
    parser.add_argument(
        "-s",
        help="Stop bits",
        type=parse_hex_or_dec,
        default=1,
        dest="stop_bits",
        choices=[1, 2],
        required=False,
    )

    # There is no way to create two different '-p' options
    # for parity and port. Therefore, there is only one option without
    # choices and default value. We have to check its value in the type
    # function.
    parser.add_argument(
        "-p",
        help="Parity {none|even|odd} = none | Port = 502",
        type=parse_parity_or_tcpport,
        dest="parity_port",
        metavar="parity|port",
        required=False,
    )

    parser.add_argument(
        "--broker",
        help="Mqtt broker IP:PORT",
        dest="mqtt_broker",
        default=DEFAULT_BROKER,
        type=parse_broker_host,
        required=False,
    )

    parser.add_argument(
        "serialport_host",
        help="Serial port path or host IP",
        type=str,
        metavar="serialport|host",
    )
    parser.add_argument(
        "write_data",
        nargs="*",
        type=parse_hex_or_dec,
        help="Data to write",
    )

    options, unknown_options = parser.parse_known_args(argv)

    error_options = []
    for x in unknown_options:
        try:
            options.write_data.append(parse_hex_or_dec(x))
        except ValueError:
            error_options.append(x)

    return options, error_options


# TODO: Now modbus-utils-rpc can only send messages to ports added to mqtt-serial.
# In RTU mode options -b, -d, -s, -p are ignored at the moment.
# We should add to mqtt-serial ability to open a port that is not in the configuration.
# Also we should start use ignored options.


def main(argv=sys.argv):

    options, error_options = parse_options(argv[1:])

    if len(error_options) != 0:
        logger.error("Invalid values for write_data option. Set hex or dec numbers")
        logger.error("\rInvalid values: %s", error_options)
        return ResultCode.USER_INPUT_ERROR

    if options.debug:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setLevel(logging.DEBUG)
        logger.addHandler(stream_handler)
        logger.setLevel(logging.DEBUG)

    if options.mode == "tcp":
        if options.parity_port is None:
            options.parity_port = 502
        get_port_params = get_tcp_params
        lib = tcp
    else:
        if options.parity_port is None:
            options.parity_port = "none"
        get_port_params = get_rtu_params
        lib = rtu

    return process_request(options, lib, get_port_params)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
