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

from exceptions import *

MOSQUITTO_IP = "127.0.0.1"
MOSQUITTO_PORT = 1883
DEFAULT_DEVICE_PORT = 502

logger = logging.getLogger(__name__)


class RPCResultCode(IntEnum):
    RPC_OK = 0
    RPC_WRONG_PARAM_SET = -1
    RPC_WRONG_PARAM_VALUE = -2
    RPC_WRONG_PORT = -3
    RPC_WRONG_IO = -4
    RPC_WRONG_RESP_LNGTH = -5


class ResultCode(IntEnum):
    OK = 0
    OPERATION_ERROR = 1
    USER_INPUT_ERROR = 2


def parse_int(data):
    return int(data, 0)


def get_tcp_params(args):
    return {'ip': args.serialport_host, 'port': args.parity_port}


def get_rtu_params(args):
    return {'path': args.serialport_host}


@contextmanager
def mqtt_client(name):
    try:
        client = mosquitto.Mosquitto(name)
        client.connect(MOSQUITTO_IP, MOSQUITTO_PORT)
        client.loop_start()
        yield client
    except (TimeoutError, ConnectionRefusedError) as err:
        raise BrokerConnectionError from err
    finally:
        client.loop_stop()
        client.disconnect()


def send_message(message, timeout):
    with mqtt_client("modbus-utils-rpc-%d" % os.getpid()) as client:
        try:

            rpc_client = TMQTTRPCClient(client)
            client.on_message = rpc_client.on_mqtt_message
            logger.debug("RPC Client -> %s (%.2f timeout)", message, timeout)
            resp = rpc_client.call('wb-mqtt-serial', 'port',
                                   'Load', message, timeout)
            logger.debug("RPC Client <- %s", resp)

        except (TimeoutError, MQTTRPCError) as err:
            raise RPCClientCallError from err

        return resp


def create_message(lib, function, slave_address, start_address, read_count,
                   write_data):
    """Fuction accept modbus params and return tuple:
    string type message with expected response size

    Returns:
        string: mesage
        int: expected response size
    """

    try:
        if function == 0x05 or function == 0x0F:
            write_data = [0 if x == 0 else 1 for x in write_data]

        if function == 0x01:
            msg_byte = lib.read_coils(
                slave_address, start_address, read_count)
        elif function == 0x02:
            msg_byte = lib.read_discrete_inputs(
                slave_address, start_address, read_count)
        elif function == 0x03:
            msg_byte = lib.read_holding_registers(
                slave_address, start_address, read_count)
        elif function == 0x04:
            msg_byte = lib.read_input_registers(
                slave_address, start_address, read_count)
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

    except (error, ModbusError) as err:
        raise UModbusError from err

    return msg_str, resp_size


def process_request(args):

    try:
        modbus_msg_str, modbus_resp_size = create_message(
            args.lib, args.func_type, args.slave_addr, args.start_addr,
            args.read_count, args.write_data)

        rpc_parameters = args.get_rpc_params(args)
        rpc_parameters.update(
            {'response_size': modbus_resp_size, 'format': 'HEX', 'msg': modbus_msg_str})

        resp = send_message(rpc_parameters, args.timeout)

        rpc_result_code = int(resp['result_code'])

        logger.info("%s\nResult code %d",
                    resp['error_msg'], rpc_result_code)

        if rpc_result_code == RPCResultCode.RPC_WRONG_PARAM_SET:
            raise RPCWrongParamSetError
        elif rpc_result_code == RPCResultCode.RPC_WRONG_PARAM_VALUE:
            raise RPCWrongParamValueError
        elif rpc_result_code == RPCResultCode.RPC_WRONG_PORT:
            raise RPCWrongPortError
        elif rpc_result_code == RPCResultCode.RPC_WRONG_IO:
            raise RPCWrongIOError
        elif rpc_result_code == RPCResultCode.RPC_WRONG_RESP_LNGTH:
            raise RPCWrongRespLngthError

        data = args.lib.parse_response_adu(bytearray.fromhex(
            resp['response']), bytearray.fromhex(modbus_msg_str))
        if 0x01 <= args.func_type <= 0x04:
            logger.debug('Read data: [%s]',
                         ', '.join(hex(x) for x in data))
        elif 0x05 <= args.func_type <= 0x06:
            logger.debug('New value:0x%0.2X', data)
        else:
            logger.debug('Coils/Registers written: %d', data)

        result_code = ResultCode.OK

    except UModbusError:
        logger.error('Wrong modbus parameters:\nFunction type %d\nSlave address %d\nStart address %d\nRead count %d\nWrite data %s',
                     args.func_type, args.slave_addr,
                     args.start_addr, args.read_count, tuple(args.write_data),
                     exc_info=(logger.level <= logging.DEBUG))
        result_code = ResultCode.USER_INPUT_ERROR
    except BrokerConnectionError:
        logger.error('There is no connection with the broker',
                     exc_info=(logger.level <= logging.DEBUG))
        result_code = ResultCode.OPERATION_ERROR
    except RPCClientCallError:
        logger.error('Mqtt-rpc client error',
                     exc_info=(logger.level <= logging.DEBUG))
        result_code = ResultCode.OPERATION_ERROR
    except RPCWrongParamSetError:
        logger.error('Wrong RPC request parameters set\n%s',
                     rpc_parameters)
        result_code = ResultCode.OPERATION_ERROR
    except RPCWrongParamValueError:
        logger.error('Wrong RPC parameter values\n%s',
                     rpc_parameters)
        result_code = ResultCode.USER_INPUT_ERROR
    except RPCWrongPortError:
        logger.error("Requested port doesn't exist\n%s",
                     args.get_rpc_params(args))
        result_code = ResultCode.USER_INPUT_ERROR
    except RPCWrongIOError:
        logger.error('Device IO error\n%s',
                     tuple(args.get_rpc_params(args)))
        result_code = ResultCode.OPERATION_ERROR
    except RPCWrongRespLngthError:
        logger.error('Wrong expected response length\nExpected %d\nActualy %d',
                     modbus_resp_size, len(resp['response']))

        result_code = ResultCode.OPERATION_ERROR

    return result_code


def check_port_parity_option(options):
    try:
        if options.mode == 'tcp':
            if options.parity_port is None:
                options.parity_port = DEFAULT_DEVICE_PORT
            else:
                options.parity_port = parse_int(options.parity_port)
    except ValueError:
        logger.error("Port value is not integer: %s", options.parity_port)
        return ResultCode.USER_INPUT_ERROR


def set_default_parser_values(options, parser):
    if options.mode == 'rtu':
        parser.set_defaults(process_func=process_request,
                            get_rpc_params=get_rtu_params,
                            lib=rtu)
    else:
        parser.set_defaults(process_func=process_request,
                            get_rpc_params=get_tcp_params,
                            lib=tcp)


def set_write_data(parser, unknown_options, options):
    for x in unknown_options:
        if x.startswith('-'):
            parser.error('Unknnown argument' + x)
        getattr(options, 'write_data').append(x)


def main(argv=sys.argv):
    parser = argparse.ArgumentParser(conflict_handler='resolve')
    parser.add_argument("--debug", help="Enable debug output",
                        default=False, dest="debug", required=False, action='store_true')
    parser.add_argument("-m", help="Mode", type=str, choices=["tcp", "rtu"],
                        dest="mode", required=True)
    parser.add_argument("-a", help="Slave address", type=parse_int,
                        default=1, dest="slave_addr", required=False)
    parser.add_argument("-c", help="Read Count", type=parse_int,
                        default=1, dest="read_count", required=False)
    parser.add_argument("-r", help="Srart address", type=parse_int,
                        default=100, dest="start_addr", required=False)
    parser.add_argument("-t", help="Function type", type=parse_int,
                        choices=[1, 2, 3, 4, 5, 6, 15, 16],
                        dest="func_type", required=True)
    parser.add_argument("-o", help="Timeout", type=parse_int,
                        default=1000, dest="timeout", required=False)
    parser.add_argument("-0", help="Slave address decrement",
                        default=False, dest="address_decrement",
                        required=False, action='store_true')

    parser.add_argument('-b', help="Baudrate", type=parse_int,
                        default=9600, dest="baudrate", required=False)
    parser.add_argument('-d', help="Data bits", type=parse_int,
                        default=8, dest="data_bits", choices=[7, 8],
                        required=False)
    parser.add_argument('-s', help="Stop bits", type=parse_int,
                        default=1, dest="stop_bits", choices=[1, 2],
                        required=False)

    # There is no way to create two different '-p' options
    # for parity and port. Therefore, there is only one option without choices and default
    # value. We have to check its value in the code.
    parser.add_argument('-p', help="Parity {1,2} = 1 | Port = 502",
                        type=str, dest="parity_port",
                        metavar='parity|port', required=False)

    parser.add_argument('serialport_host', help="Serial port path or host IP",
                        type=str, metavar='serialport|host')
    parser.add_argument('write_data', nargs='*',
                        type=parse_int, help="Data to write")

    options, unknown_options = parser.parse_known_args()

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logger.addHandler(stream_handler)

    if check_port_parity_option(options) == ResultCode.USER_INPUT_ERROR:
        return ResultCode.USER_INPUT_ERROR

    set_default_parser_values(options, parser)
    options, unknown_options = parser.parse_known_args()
    set_write_data(parser, unknown_options, options)

    return options.process_func(options)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
