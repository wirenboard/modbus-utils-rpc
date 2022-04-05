import argparse
import logging
import os
import sys
from contextlib import contextmanager
from enum import IntEnum
from struct import error

import paho.mqtt.client as mosquitto
from mqttrpc.client import MQTTRPCError, TMQTTRPCClient
from umodbus.client import tcp
from umodbus.client.serial import rtu
from umodbus.exceptions import ModbusError


class ResultCode(IntEnum):
    OK = 0
    OPERATION_ERROR = 1
    USER_INPUT_ERROR = 2


def hex_str(data):
    str_data_list = data.split()
    hex_data_list = [int(x, 16) for x in str_data_list]
    return hex_data_list


def create_tcp_path(args):
    data = {}
    data['ip'] = args.ip
    data['port'] = args.port
    return data


def create_rtu_path(args):
    data = {}
    data['path'] = args.serialport
    return data


@contextmanager
def mqtt_client(name):
    try:
        client = mosquitto.Mosquitto(name)
        client.connect("192.168.10.6", 1883)
        client.loop_start()
        yield client
    except ConnectionRefusedError:
        raise
    finally:
        client.loop_stop()
        client.disconnect()


def send_message(message, timeout):
    with mqtt_client("modbus-utils-rpc-%d" % os.getpid()) as client:
        rpc_client = TMQTTRPCClient(client)
        client.on_message = rpc_client.on_mqtt_message
        resp = rpc_client.call('wb-mqtt-serial', 'port',
                               'Load', message, timeout)
        return resp


def create_message(lib, function, slave_address, start_address, read_no, write_data):
    if function == 0x01:
        msg_byte = lib.read_coils(
            slave_address, start_address, read_no)
    elif function == 0x02:
        msg_byte = lib.read_discrete_inputs(
            slave_address, start_address, read_no)
    elif function == 0x03:
        msg_byte = lib.read_holding_registers(
            slave_address, start_address, read_no)
    elif function == 0x04:
        msg_byte = lib.read_input_registers(
            slave_address, start_address, read_no)
    elif function == 0x05:
        msg_byte = lib.write_single_coil(
            slave_address, start_address, write_data[0])
    elif function == 0x06:
        msg_byte = lib.write_single_register(
            slave_address, start_address, write_data[0])
    elif function == 0x0F:
        msg_byte = lib.write_multiple_coils(
            slave_address, start_address, write_data)
    elif function == 0x10:
        msg_byte = lib.write_multiple_registers(
            slave_address, start_address, write_data)

    msg_str = "".join("{:02x}".format(x) for x in msg_byte)
    resp_size = lib.expected_response_size(msg_byte)

    return msg_str, resp_size


def process_request(args):
    args.func_type = int(args.func_type, 16)

    try:
        modbus_msg_str, modbus_resp_size = create_message(
            args.lib, args.func_type, args.slave_addr, args.start_addr, args.read_no, args.write_data)

        rpc_parameters = args.path_create(args)
        rpc_parameters['response_size'] = modbus_resp_size
        rpc_parameters['format'] = 'HEX'
        rpc_parameters['msg'] = modbus_msg_str

        resp = send_message(rpc_parameters, args.timeout)

        result_code = ResultCode.OK

        logging.info(resp['error_msg'])
        logging.info("Result code %d" % int(resp['result_code']))

        if int(resp['result_code']) == 0:
            data = args.lib.parse_response_adu(
                bytearray.fromhex(resp['response']), bytearray.fromhex(modbus_msg_str))
            if 0x01 <= args.func_type <= 0x04:
                logging.debug('Read data:')
                logging.debug('[{}]'.format(', '.join(hex(x) for x in data)))
            elif 0x05 <= args.func_type <= 0x06:
                logging.debug('New value:')
                logging.debug("0x%0.2X" % data)
            else:
                logging.debug('Coils/Registers written:')
                logging.debug(data)

    except (error, ModbusError):
        logging.error('Wrong modbus parameters')
        result_code = ResultCode.USER_INPUT_ERROR
    except ConnectionRefusedError:
        logging.error('Server connection refused')
        result_code = ResultCode.OPERATION_ERROR
    except (TimeoutError, MQTTRPCError):
        logging.error('Mqtt-rpc server error')
        result_code = ResultCode.OPERATION_ERROR

    return result_code


def main(argv=sys.argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="Enable debug output",
                        default=False, dest="debug", required=False, action='store_true')
    parser.add_argument("-a", help="Slave address", type=int,
                        default=1, dest="slave_addr", required=False)
    parser.add_argument("-c", help="Read no", type=int,
                        default=1, dest="read_no", required=False)
    parser.add_argument("-r", help="Srart address", type=int,
                        default=100, dest="start_addr", required=False)
    parser.add_argument("-f", help="Function type", type=str, choices=[
                        "0x01", "0x02", "0x03", "0x04", "0x05", "0x06", "0x0F", "0x10"],
                        dest="func_type", required=False)
    parser.add_argument("-o", help="Timeout", type=int,
                        default=1000, dest="timeout", required=False)
    parser.add_argument("-w", help="Data to write", type=hex_str,
                        dest="write_data", default="", required=False)

    subparsers = parser.add_subparsers(dest="cmd")
    subparsers.required = True

    tcp_subparser = subparsers.add_parser("tcp", help="ModbusTCP")
    tcp_subparser.add_argument("port", type=int)
    tcp_subparser.add_argument("ip", type=str)
    tcp_subparser.set_defaults(
        func=process_request, lib=tcp, path_create=create_tcp_path)

    rtu_subparser = subparsers.add_parser("rtu", help="ModbusRTU")
    rtu_subparser.add_argument("serialport", type=str)
    rtu_subparser.set_defaults(
        func=process_request, lib=rtu, path_create=create_rtu_path)

    options = parser.parse_args()

    if options.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    return options.func(options)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
