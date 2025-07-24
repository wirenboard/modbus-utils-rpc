import argparse
import logging
import struct
import sys
from contextlib import contextmanager
from enum import IntEnum

import umodbus.exceptions
from mqttrpc import client as rpcclient
from umodbus import functions
from wb_common.mqtt_client import DEFAULT_BROKER_URL, MQTTClient

from modbus_client_rpc import exceptions

logger = logging.getLogger(__name__)


class RPCErrorCode(IntEnum):
    E_RPC_PARSE_ERROR = -32700
    E_RPC_SERVER_ERROR = -32000
    E_RPC_REQUEST_TIMEOUT = -32600


class ResultCode(IntEnum):
    OK = 0
    OPERATION_ERROR = 1
    USER_INPUT_ERROR = 2


def parse_hex_or_dec(data):
    return int(data, 0)


def parse_parity_or_tcpport(data):
    parities = {
        "none": "N",
        "even": "E",
        "odd": "O",
    }
    ret = parities.get(data)

    if ret:
        return ret

    try:
        return parse_hex_or_dec(data)
    except ValueError as error:
        logger.error("Invalid value %s for -p option. Set {none|even|odd} or port number", data)
        raise error


def get_tcp_params(args):
    return {"ip": args.serialport_host, "port": args.parity_port}


def get_rtu_params(args):
    return {
        "path": args.serialport_host,
        "baud_rate": args.baudrate,
        "parity": args.parity_port,
        "data_bits": args.data_bits,
        "stop_bits": args.stop_bits,
    }


def _check_function(function):
    """Check if the function is valid for Modbus RPC calls."""
    valid_functions = (
        functions.READ_COILS,
        functions.READ_DISCRETE_INPUTS,
        functions.READ_HOLDING_REGISTERS,
        functions.READ_INPUT_REGISTERS,
        functions.WRITE_SINGLE_COIL,
        functions.WRITE_SINGLE_REGISTER,
        functions.WRITE_MULTIPLE_COILS,
        functions.WRITE_MULTIPLE_REGISTERS,
    )
    if function not in valid_functions:
        raise exceptions.ModbusParametersError(f"Invalid function type: {function}")


def _check_address(address):
    """Check if the address is a valid Modbus address."""
    if not isinstance(address, int) or address < 0:
        raise exceptions.ModbusParametersError(
            f"Invalid start address: {address}. It must be a non-negative integer."
        )
    if address > 65535:
        raise exceptions.ModbusParametersError(
            f"Start address {address} exceeds maximum allowed value of 65535."
        )


def get_rpc_register_count(function, write_data, read_count):
    """Get the number of registers for the RPC call based on the function and data."""

    if function in (functions.WRITE_SINGLE_COIL, functions.WRITE_SINGLE_REGISTER):
        return 1

    if function in (functions.WRITE_MULTIPLE_COILS, functions.WRITE_MULTIPLE_REGISTERS):
        return len(write_data)

    if not isinstance(read_count, int) or read_count <= 0:
        raise exceptions.ModbusParametersError(
            f"Invalid read count: {read_count}. It must be a positive integer."
        )
    return read_count


def get_payload_for_write_coils(write_data):
    """Convert write data for WRITE_MULTIPLE_COILS function to a bitmask string."""

    write_data = [0 if x == 0 else 1 for x in write_data]
    # Pack bits into bytes as bitmask
    payload_bytes = []
    for i in range(0, len(write_data), 8):
        byte_val = 0
        for j in range(8):
            if i + j < len(write_data) and write_data[i + j]:
                byte_val |= 1 << j
        payload_bytes.append(byte_val)
    return "".join(f"{x:02x}" for x in payload_bytes)


def get_payload_for_single_coil(write_data):
    """Convert write data for WRITE_SINGLE_COIL function to RPC call payload."""
    if write_data[0] == 0:
        return "0000"
    else:
        return "ff00"


def get_modbus_rpc_payload_and_count(  # pylint:disable=too-many-arguments
    function, address_decrement, start_address, read_count, write_data
):
    """Function accept modbus params and return payload string and register count for wb-mqtt-serial RPC call

    Returns:
        string: message
    """

    _check_function(function)
    _check_address(start_address)

    msg_payload = ""

    if address_decrement:
        start_address -= 1

    if function in (
        functions.WRITE_SINGLE_COIL,
        functions.WRITE_SINGLE_REGISTER,
        functions.WRITE_MULTIPLE_COILS,
        functions.WRITE_MULTIPLE_REGISTERS,
    ):
        logger.debug("Data to write: %s", "".join(f"0x{x:02x} " for x in write_data))

    if function == functions.WRITE_SINGLE_COIL:
        msg_payload = get_payload_for_single_coil(write_data)
    elif function == functions.WRITE_MULTIPLE_COILS:
        msg_payload = get_payload_for_write_coils(write_data)
    else:
        msg_payload = "".join(f"{x:04x}" for x in write_data)

    register_count = get_rpc_register_count(function, write_data, read_count)
    return msg_payload, register_count


def create_rpc_request(  # pylint:disable=too-many-arguments
    args, modbus_mode, get_port_params, slave_addr, function, start_addr, register_count, payload_str, timeout
):
    rpc_request = get_port_params(args)
    rpc_request.update(
        {
            "slave_id": slave_addr,
            "function": function,
            "address": start_addr,
            "count": register_count,
            "format": "HEX",
            "msg": payload_str,
            "total_timeout": timeout,
        }
    )
    if modbus_mode == "tcp":
        rpc_request["protocol"] = "modbus-tcp"
    else:
        rpc_request["protocol"] = "modbus"

    return rpc_request


@contextmanager
def mqtt_client(name, broker):
    try:
        client = MQTTClient(name, broker)
        logger.debug("Connecting to broker %s", broker)
        client.start()
        yield client
    except (TimeoutError, ConnectionRefusedError) as error:
        raise exceptions.BrokerConnectionError from error
    finally:
        client.stop()


def send_message(args, broker, message, timeout):
    with mqtt_client("modbus-client-rpc", broker) as client:
        try:
            rpc_client = rpcclient.TMQTTRPCClient(client)
            client.on_message = rpc_client.on_mqtt_message

            logger.debug("RPC Client -> %s (%d timeout ms)", message, timeout)
            # RPC Client accepts timeout in seconds
            response = rpc_client.call("wb-mqtt-serial", "port", "Load", message, timeout / 1000)
            logger.debug("RPC Client <- %s", response)

        except rpcclient.TimeoutError as error:
            raise exceptions.RPCClientTimeoutError from error

        except rpcclient.MQTTRPCError as error:
            logger.debug("Options: %s", vars(args))
            raise exceptions.RPCError(error.rpc_message, error.code, error.data) from error

        return response


def parse_rpc_response(response):
    logger.debug("Response: %s", response)
    if "response" in response.keys():
        logger.debug("Response: %s", response["response"])
        return response["response"]
    if "exception" in response.keys():
        logger.debug("Modbus error code=%d (%s)", response["exception"]["code"], response["exception"]["msg"])
        raise umodbus.exceptions.error_code_to_exception_map[response["exception"]["code"]](
            response["exception"]["msg"]
        )

    raise exceptions.RPCError("Parse error", RPCErrorCode.E_RPC_PARSE_ERROR, '"response" field is missing')


def parse_modbus_response(function, register_count, response):
    try:
        response_byte = bytearray.fromhex(response)
        logger.debug("%s", "".join(f"<{x:02x}>" for x in response_byte))

        if function in (functions.READ_COILS, functions.READ_DISCRETE_INPUTS):
            # response_byte: bytearray(b'\x00\xFF')
            # data: [0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1]
            data = []
            for byte in response_byte:
                for bit in range(8):
                    data.append((byte >> bit) & 1)
                    if len(data) >= register_count:
                        break

            print("SUCCESS: read", len(data), "elements:")
            print("\tData:", "".join(f"0x{x:02x} " for x in data))

        elif function in (functions.READ_HOLDING_REGISTERS, functions.READ_INPUT_REGISTERS):
            # response_byte: bytearray(b'\x00\x0a\x00\x00')
            # data: [0x000A, 0x0000]
            data = [int.from_bytes(response_byte[i : i + 2], "big") for i in range(0, len(response_byte), 2)]

            print("SUCCESS: read", len(data), "elements:")
            print("\tData:", "".join(f"0x{x:04x} " for x in data))

        elif function in (functions.WRITE_SINGLE_COIL, functions.WRITE_SINGLE_REGISTER):
            print("SUCCESS: written 1 element")
        else:
            print("SUCCESS: Coils/Registers written:", "?")

    except (struct.error, umodbus.exceptions.ModbusError) as error:
        raise exceptions.ModbusParseError(response_byte) from error


def handle_rpcumodbusparameterserror(args):
    logger.error("Wrong modbus parameters:")
    logger.error("\tFunction type %d", args.func_type)
    logger.error("\tSlave address % d", args.slave_addr)
    logger.error("\tStart address % d", args.start_addr)
    logger.error("\tStart address decrement: %r", args.address_decrement)
    logger.error("\tRead count % d", args.read_count)
    logger.error("\tWrite data % s", tuple(args.write_data), exc_info=logger.level <= logging.DEBUG)
    return ResultCode.USER_INPUT_ERROR


def handle_brokerconnectionerror():
    logger.error("There is no connection with the broker", exc_info=logger.level <= logging.DEBUG)
    return ResultCode.OPERATION_ERROR


def handle_rpcclienttimeouterror(timeout):
    logger.error("Mqtt-rpc client timeout error, timeout %d ms", timeout)
    return ResultCode.OPERATION_ERROR


def handle_rpcumodbusparseerror(error):
    logger.error("Error occurred while parsing modbus response:")
    logger.error("%s", "".join(f"[{x:02x}]" for x in bytearray.fromhex(error.modbus_message)))
    return ResultCode.OPERATION_ERROR


def handle_rpcerror(error):
    print("ERROR occurred")
    logger.debug("Error message: %s", error.error_message)
    logger.debug("Error code: %d", error.error_code)
    logger.debug("Error data: %s", error.error_data)

    return ResultCode.OPERATION_ERROR


def process_request(args, modbus_mode, get_port_params):

    try:
        payload_str, register_count = get_modbus_rpc_payload_and_count(
            args.func_type,
            args.address_decrement,
            args.start_addr,
            args.read_count,
            args.write_data,
        )

        rpc_request = create_rpc_request(
            args,
            modbus_mode,
            get_port_params,
            args.slave_addr,
            args.func_type,
            args.start_addr,
            register_count,
            payload_str,
            args.timeout,
        )

        rpc_response = send_message(args, args.mqtt_broker, rpc_request, args.timeout)

        modbus_resp_str = parse_rpc_response(rpc_response)
        parse_modbus_response(args.func_type, register_count, modbus_resp_str)

        result_code = ResultCode.OK

    except exceptions.ModbusParametersError:
        result_code = handle_rpcumodbusparameterserror(args)
    except exceptions.BrokerConnectionError:
        result_code = handle_brokerconnectionerror()
    except exceptions.RPCClientTimeoutError:
        result_code = handle_rpcclienttimeouterror(args.timeout)
    except exceptions.ModbusParseError as error:
        result_code = handle_rpcumodbusparseerror(error)
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
        help="Mode: Modbus TCP, Modbus RTU or Modbus RTU over TCP (transparent serial port <-> TCP bridge)",
        type=str,
        choices=["tcp", "rtu", "rtuovertcp"],
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
        help=(
            "Function type: (0x01) Read Coils, (0x02) Read Discrete Inputs, (0x05) Write Single Coil, "
            "(0x03) Read Holding Registers, (0x04) Read Input Registers, (0x06) Write Single Register, "
            "(0x0F) Write Multiple Coils, (0x10) Write Multiple Registers"
        ),
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
        help="Mqtt broker url",
        dest="mqtt_broker",
        default=DEFAULT_BROKER_URL,
        type=str,
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


def main(argv=sys.argv):

    options, error_options = parse_options(argv[1:])

    if len(error_options) != 0:
        logger.error("Invalid values for write_data option. Set hex or dec numbers")
        logger.error("\rInvalid values: %s", error_options)
        return ResultCode.USER_INPUT_ERROR

    if options.debug:
        logger_level = logging.DEBUG
    else:
        logger_level = logging.INFO

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setLevel(logger_level)
    stream_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(stream_handler)
    logger.setLevel(logger_level)

    if options.mode in ("tcp", "rtuovertcp"):
        if options.parity_port is None:
            options.parity_port = 502
        get_port_params = get_tcp_params
    else:
        if options.parity_port is None:
            options.parity_port = "none"
        get_port_params = get_rtu_params

    return process_request(options, options.mode, get_port_params)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
