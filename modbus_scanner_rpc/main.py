import argparse
import logging
import sys
from contextlib import contextmanager

from mqttrpc import client as rpcclient
from umodbus.client.serial import redundancy_check
from wb_common.mqtt_client import DEFAULT_BROKER_URL, MQTTClient

from modbus_client_rpc import exceptions
from modbus_client_rpc import main as modbus_client

logger = logging.getLogger(__name__)


def remove_substring_prefix(prefix, string):
    while string.startswith(prefix):
        string = string[len(prefix) :]
    return string


def parse_hex_or_dec(data):
    return int(data, 0)


def create_rpc_request(serial_port, modbus_message, timeout):
    return {
        "path": serial_port,
        "baud_rate": 9600,
        "parity": "N",
        "data_bits": 8,
        "stop_bits": 1,
        "response_size": 1000,  # we need relatively huge one; wb-mqtt-serial returns only actual bytes
        "format": "HEX",
        "msg": modbus_message,
        "total_timeout": timeout,
    }


def start_scan(serial_port, rpc_client, timeout):
    """Send broadcast command FD600198, where 60 01 - command and start scan subcommand for WB Devices"""
    rpc_request = create_rpc_request(serial_port, "FD600109F0", timeout)
    logger.debug("Scan init")
    logger.debug("RPC Client -> %s, %d ms", rpc_request, timeout)
    rpc_response = rpc_client.call("wb-mqtt-serial", "port", "Load", rpc_request, timeout)
    modbus_response = modbus_client.parse_rpc_response(rpc_response)
    return bytearray.fromhex(remove_substring_prefix("ff", modbus_response))


def continue_scan(serial_port, rpc_client, timeout):
    """Send 60 command and 02 subcommand for scan continue. Devices respond sequentially with subcommand 03 on every 02 subcommand."""
    """If not a single unasked device left, first device respond with 04 subcommand"""
    rpc_request = create_rpc_request(serial_port, "FD600249F1", timeout)
    logger.debug("Scan next")
    logger.debug("RPC Client -> %s, %d ms", rpc_request, timeout)
    rpc_response = rpc_client.call("wb-mqtt-serial", "port", "Load", rpc_request, timeout)
    logger.debug("RPC Client <- %s", rpc_response)

    modbus_response = modbus_client.parse_rpc_response(rpc_response)
    return bytearray.fromhex(remove_substring_prefix("ff", modbus_response))


def should_continue(scan_message):
    try:
        redundancy_check.validate_crc(scan_message)
    except redundancy_check.CRCError as error:
        raise exceptions.ModbusParseError(scan_message) from error

    if not scan_message.startswith(bytearray.fromhex("FD60")):
        logger.error("Scan error while parsing answer", "".join("{:02x}".format(x) for x in scan_message))
        return False

    if scan_message[2] == 0x03:
        serial_number = scan_message[3:-3]
        modbus_address = scan_message[-3]
        print(
            "Found device with SN ",
            "".join("{:02x}".format(x) for x in serial_number),
            int.from_bytes(serial_number, byteorder="big", signed=False),
            "modbus address ",
            modbus_address,
        )
        return True

    if scan_message[2] == 0x04:
        logger.debug("Scan end")
        return False


@contextmanager
def mqtt_client(name, broker):
    try:
        client = MQTTClient(name, broker)
        logger.debug("Connecting to broker %s", broker)
        client.start()
        yield client
    except (TimeoutError, ConnectionRefusedError, OSError) as error:
        raise exceptions.BrokerConnectionError from error
    finally:
        client.stop()


def scan_bus(args):
    with mqtt_client("modbus-scanner-rpc", args.mqtt_broker) as client:
        try:
            rpc_client = rpcclient.TMQTTRPCClient(client)
            client.on_message = rpc_client.on_mqtt_message

            response_message = start_scan(args.serial_port, rpc_client, args.timeout)
            while should_continue(response_message):
                response_message = continue_scan(args.serial_port, rpc_client, args.timeout)

        except rpcclient.TimeoutError as error:
            raise exceptions.RPCClientTimeoutError from error

        except rpcclient.MQTTRPCError as error:
            logger.debug("Options: %s", vars(args))
            raise exceptions.RPCError(error.rpc_message, error.code, error.data) from error


def main(argv=sys.argv):

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
        "serial_port",
        help="Serial port path",
        type=str,
        metavar="serial_port",
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
        "-o",
        help="Timeout, ms",
        type=parse_hex_or_dec,
        default=10000,
        dest="timeout",
        required=False,
    )

    args = parser.parse_args()

    if args.debug:
        logger_level = logging.DEBUG
    else:
        logger_level = logging.INFO

    stream_handler = logging.StreamHandler(sys.stderr)
    stream_handler.setLevel(logger_level)
    stream_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

    logger.addHandler(stream_handler)
    logger.setLevel(logger_level)
    modbus_client.logger.addHandler(stream_handler)
    modbus_client.logger.setLevel(logger_level)

    try:
        scan_bus(args)
        result_code = modbus_client.ResultCode.OK
    except exceptions.BrokerConnectionError:
        result_code = modbus_client.handle_brokerconnectionerror()
    except exceptions.RPCClientTimeoutError:
        result_code = modbus_client.handle_rpcclienttimeouterror(args.timeout)
    except exceptions.ModbusParseError as error:
        result_code = modbus_client.handle_rpcumodbusparseerror(error)
    except exceptions.RPCError as error:
        result_code = modbus_client.handle_rpcerror(error)

    return result_code


if __name__ == "__main__":
    sys.exit(main(sys.argv))
