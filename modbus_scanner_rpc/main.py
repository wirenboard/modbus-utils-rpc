import argparse
import logging
import os
import sys
from contextlib import contextmanager

import paho.mqtt.client as mqtt
from modbus_client_rpc import exceptions
from modbus_client_rpc import main as modbus_client
from mqttrpc import client as rpcclient
from umodbus.client.serial import redundancy_check

logger = logging.getLogger(__name__)


def remove_substring_prefix(prefix, string):
    while string.startswith(prefix):
        string = string[len(prefix) :]
    return string


def parse_hex_or_dec(data):
    return int(data, 0)


def parse_broker_host(data):
    host = data.split(":")
    return {"ip": host[0], "port": int(host[1])}


def create_rpc_request(serial_port, modbus_message, response_size, timeout):
    return {
        "path": serial_port,
        "response_size": response_size,
        "format": "HEX",
        "msg": modbus_message,
        "total_timeout": timeout,
    }


def start_scan(serial_port, rpc_client, timeout):
    """Send broadcast command FD600198, where 60 01 - command and start scan subcommand for WB Devices"""
    rpc_request = create_rpc_request(serial_port, "FD600109F0", 0, timeout)
    print("SCAN INIT")
    print("RPC Client -> {}, {} ms".format(rpc_request, timeout))
    rpc_response = rpc_client.call("wb-mqtt-serial", "port", "Load", rpc_request, timeout)
    modbus_client.parse_rpc_response(rpc_response)


def continue_scan(serial_port, rpc_client, timeout):
    """Send 60 command and 02 subcommand for scan continue. Devices respond sequentially with subcommand 03 on every 02 subcommand."""
    """If not a single unasked device left, first device respond with 04 subcommand"""
    rpc_request = create_rpc_request(serial_port, "FD600249F1", 60, timeout)
    print("SCAN NEXT")
    print("RPC Client -> {}, {} ms".format(rpc_request, timeout))
    rpc_response = rpc_client.call("wb-mqtt-serial", "port", "Load", rpc_request, timeout)
    print("RPC Client <- {}".format(rpc_response))

    modbus_response = modbus_client.parse_rpc_response(rpc_response)
    scan_message = bytearray.fromhex(remove_substring_prefix("ff", modbus_response))

    try:
        redundancy_check.validate_crc(scan_message)

        if not scan_message.startswith(bytearray.fromhex("FD60")):
            print("Scan error while parsing answer", "".join("{:02x}".format(x) for x in scan_message))
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
            print("SCAN END")
            return False
    except redundancy_check.CRCError as error:
        raise exceptions.ModbusParseError(scan_message) from error


@contextmanager
def mqtt_client(name, broker=modbus_client.DEFAULT_BROKER):
    try:
        client = mqtt.Client(name)
        logger.debug("Connecting to broker %s:%s", broker["ip"], broker["port"])
        client.connect(broker["ip"], broker["port"])
        client.loop_start()
        yield client
    except (TimeoutError, ConnectionRefusedError, OSError) as error:
        raise exceptions.BrokerConnectionError from error
    finally:
        client.loop_stop()
        client.disconnect()


def scan_bus(args):
    with mqtt_client("modbus-scanner-rpc-%d" % os.getpid(), args.mqtt_broker) as client:
        try:
            rpc_client = rpcclient.TMQTTRPCClient(client)
            client.on_message = rpc_client.on_mqtt_message

            start_scan(args.serial_port, rpc_client, args.timeout)
            while continue_scan(args.serial_port, rpc_client, args.timeout):
                pass

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
        help="Mqtt broker IP:PORT",
        dest="mqtt_broker",
        default=modbus_client.DEFAULT_BROKER,
        type=parse_broker_host,
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
