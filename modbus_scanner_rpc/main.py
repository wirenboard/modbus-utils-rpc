import sys

import paho.mqtt.client as mqtt
from mqttrpc import client as rpcclient
from umodbus.client.serial import redundancy_check


def create_message(message, response_size):
    return {
        "path": "/dev/ttyRS485-2",
        "response_size": response_size,
        "format": "HEX",
        "msg": message,
    }


def start_scan(rpc_client):
    rpc_client.call("wb-mqtt-serial", "port", "Load", create_message("00600198", 0), 500.0)


def continue_scan(rpc_client):
    response = rpc_client.call("wb-mqtt-serial", "port", "Load", create_message("006002D801", 60), 500.0)
    scan_message = bytearray.fromhex(response["response"].lstrip("ff"))

    try:
        redundancy_check.validate_crc(scan_message)

        if not scan_message.startswith(bytearray.fromhex("0060")):
            print("Scan error when parsing answer", "".join("{:02x}".format(x) for x in scan_message))
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
            return False
    except redundancy_check.CRCError as error:
        print(str(error))


def main(argv=sys.argv):
    client = mqtt.Client(client_id="New-Modbus-RPC")
    client.connect(host="192.168.0.6", port=1883)
    client.loop_start()
    rpc_client = rpcclient.TMQTTRPCClient(client)
    client.on_message = rpc_client.on_mqtt_message

    print("Start scan")
    start_scan(rpc_client)
    while continue_scan(rpc_client):
        pass
    print("End scan")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
