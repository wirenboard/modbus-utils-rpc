import argparse
import sys

import paho.mqtt.client as mqtt
from mqttrpc import client as rpcclient
from umodbus.client.serial import redundancy_check

DEFAULT_BROKER = {"ip": "127.0.0.1", "port": 1883}


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
    rpc_client.call("wb-mqtt-serial", "port", "Load", rpc_request, timeout)


def continue_scan(serial_port, rpc_client, timeout):
    """Send 60 command and 02 subcommand for scan continue. Devices respond sequentially with subcommand 03 on every 02 subcommand."""
    """If not a single unasked device left, first device respond with 04 subcommand"""
    rpc_request = create_rpc_request(serial_port, "FD600249F1", 60, timeout)
    print("SCAN NEXT")
    print("RPC Client -> {}, {} ms".format(rpc_request, timeout))
    response = rpc_client.call("wb-mqtt-serial", "port", "Load", rpc_request, timeout)
    print("RPC Client <- {}".format(response))
    scan_message = bytearray.fromhex(remove_substring_prefix("ff", response["response"]))

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
        print(str(error))


def main(argv=sys.argv):

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "serialport",
        help="Serial port path",
        type=str,
        metavar="serial_port",
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
        "-o",
        help="Timeout, ms",
        type=parse_hex_or_dec,
        default=10000,
        dest="timeout",
        required=False,
    )

    args = parser.parse_args()

    client = mqtt.Client(client_id="New-Modbus-Scanner-RPC")
    client.connect(args.mqtt_broker["ip"], args.mqtt_broker["port"])
    client.loop_start()

    rpc_client = rpcclient.TMQTTRPCClient(client)
    client.on_message = rpc_client.on_mqtt_message

    start_scan(args.serial_port, rpc_client, args.timeout)
    while continue_scan(args.serial_port, rpc_client, args.timeout):
        pass


if __name__ == "__main__":
    sys.exit(main(sys.argv))
