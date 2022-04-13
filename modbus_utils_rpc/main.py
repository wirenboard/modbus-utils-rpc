import argparse
import logging
import os
import struct
import sys
from contextlib import contextmanager
from enum import IntEnum

import paho.mqtt.client as mosquitto
from mqttrpc.client import MQTTRPCError, TMQTTRPCClient
from umodbus import functions
from umodbus.client import tcp
from umodbus.client.serial import rtu
from umodbus.exceptions import ModbusError

import exceptions

MOSQUITTO_IP = "127.0.0.1"
MOSQUITTO_PORT = 1883

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
    if data in ('none', 'even', 'odd'):
        return data
    else:
        try:
            return parse_hex_or_dec(data)
        except ValueError as error:
            logger.error(
                "Invalid value %s for -p option. Set {none|even|odd} or port number",  data)
            raise error


def get_tcp_params(args):
    return {'ip': args.serialport_host, 'port': args.parity_port}


def get_rtu_params(args):
    # TODO: add RTU mode support to be able to work with ports unknown to wb-serial
    return {'path': args.serialport_host}


@contextmanager
def mqtt_client(name):
    try:
        client = mosquitto.Mosquitto(name)
        client.connect(MOSQUITTO_IP, MOSQUITTO_PORT)
        client.loop_start()
        yield client
    except (TimeoutError, ConnectionRefusedError) as error:
        raise exceptions.BrokerConnectionError from error
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

        except (TimeoutError, MQTTRPCError) as error:
            raise exceptions.RPCClientCallError from error

        return resp


def create_message(lib, function, slave_address, address_decrement,
                   start_address, read_count, write_data):
    """Fuction accept modbus params and return tuple:
    string type message with expected response size

    Returns:
        string: mesage
        int: expected response size
    """

    try:
        if address_decrement:
            slave_address -= 1

        if function in (functions.WRITE_SINGLE_COIL,
                        functions.WRITE_MULTIPLE_COILS):
            write_data = [0 if x == 0 else 1 for x in write_data]

        if function == functions.READ_COILS:
            msg_byte = lib.read_coils(
                slave_address, start_address, read_count)
        elif function == functions.READ_DISCRETE_INPUTS:
            msg_byte = lib.read_discrete_inputs(
                slave_address, start_address, read_count)
        elif function == functions.READ_HOLDING_REGISTERS:
            msg_byte = lib.read_holding_registers(
                slave_address, start_address, read_count)
        elif function == functions.READ_INPUT_REGISTERS:
            msg_byte = lib.read_input_registers(
                slave_address, start_address, read_count)
        elif function == functions.WRITE_SINGLE_COIL:
            msg_byte = lib.write_single_coil(
                slave_address, start_address, write_data[0])
        elif function == functions.WRITE_SINGLE_REGISTER:
            msg_byte = lib.write_single_register(
                slave_address, start_address, write_data[0])
        elif function == functions.WRITE_MULTIPLE_COILS:
            msg_byte = lib.write_multiple_coils(
                slave_address, start_address, write_data)
        elif function == functions.WRITE_MULTIPLE_REGISTERS:
            msg_byte = lib.write_multiple_registers(
                slave_address, start_address, write_data)

        msg_str = "".join("{:02x}".format(x) for x in msg_byte)
        resp_size = lib.expected_response_size(msg_byte)

    except (struct.error, ModbusError) as error:
        raise exceptions.RPCUModbusParametersError from error

    return msg_str, resp_size


def process_request(args, lib, get_port_params):

    try:
        modbus_msg_str, modbus_resp_size = create_message(
            lib, args.func_type, args.slave_addr, args.address_decrement,
            args.start_addr, args.read_count, args.write_data)

        port_path = get_port_params(args)
        rpc_parameters = port_path
        rpc_parameters.update(
            {'response_size': modbus_resp_size, 'format': 'HEX', 'msg': modbus_msg_str})

        rpc_response = send_message(rpc_parameters, args.timeout)

        rpc_result_code = int(rpc_response['result_code'])

        logger.info('Error_message: %s', rpc_response['error_msg'])
        logger.info('Result code: %d', rpc_result_code)

        if rpc_result_code != RPCResultCode.RPC_OK:
            raise exceptions.RPCError(
                rpc_result_code, port_path,
                rpc_parameters, rpc_response)

        data = lib.parse_response_adu(bytearray.fromhex(
            rpc_response['response']), bytearray.fromhex(modbus_msg_str))

        if args.func_type in (functions.READ_COILS,
                              functions.READ_DISCRETE_INPUTS,
                              functions.READ_HOLDING_REGISTERS,
                              functions.READ_INPUT_REGISTERS):

            logger.debug('Read data: [%s]',
                         ', '.join(hex(x) for x in data))

        elif args.func_type in (functions.WRITE_SINGLE_COIL,
                                functions.WRITE_SINGLE_REGISTER):
            logger.debug('New value:0x%0.2X', data)
        else:
            logger.debug('Coils/Registers written: %d', data)

        result_code = ResultCode.OK

    except exceptions.RPCUModbusParametersError:
        logger.error('Wrong modbus parameters:')
        logger.error('\tFunction type %d', args.func_type)
        logger.error('\tSlave address % d', args.slave_addr)
        logger.error('\tStart address % d', args.start_addr)
        logger.error('\tRead count % d', args.read_count)
        logger.error('\tWrite data % s', tuple(args.write_data))
        logger.error(exc_info=(logger.level <= logging.DEBUG))
        result_code = ResultCode.USER_INPUT_ERROR
    except exceptions.BrokerConnectionError:
        logger.error('There is no connection with the broker',
                     exc_info=(logger.level <= logging.DEBUG))
        result_code = ResultCode.OPERATION_ERROR
    except exceptions.RPCClientCallError:
        logger.error('Mqtt-rpc client error',
                     exc_info=(logger.level <= logging.DEBUG))
        result_code = ResultCode.OPERATION_ERROR
    except exceptions.RPCError as error:

        if error.result_code == RPCResultCode.RPC_WRONG_PARAM_SET:
            logger.error('Wrong RPC request parameters set: %s',
                         error.rpc_parameters)
            result_code = ResultCode.OPERATION_ERROR

        elif error.result_code == RPCResultCode.RPC_WRONG_PARAM_VALUE:
            logger.error('Wrong RPC parameter values: %s',
                         error.rpc_parameters)
            result_code = ResultCode.USER_INPUT_ERROR

        elif error.result_code == RPCResultCode.RPC_WRONG_PORT:
            logger.error("Requested port doesn't exist: %s",
                         error.port_path)
            result_code = ResultCode.USER_INPUT_ERROR

        elif error.result_code == RPCResultCode.RPC_WRONG_IO:
            logger.error('Device IO error: %s',
                         error.port_path)
            result_code = ResultCode.OPERATION_ERROR

        elif error.result_code == RPCResultCode.RPC_WRONG_RESPONSE_LEN:
            logger.error('Wrong expected response length:')
            logger.error('\tExpected %d',
                         error.rpc_parameters['response_size'])
            logger.error('\tActual % d',
                         len(error.rpc_response['response']))
            result_code = ResultCode.OPERATION_ERROR

    return result_code


def set_write_data(parser, unknown_options, options):
    for x in unknown_options:
        if x.startswith('-'):
            parser.error('Unknnown argument' + x)
        getattr(options, 'write_data').append(x)


def main(argv=sys.argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", help="Enable debug output",
                        default=False, dest="debug", required=False, action='store_true')
    parser.add_argument("-m", help="Mode", type=str, choices=["tcp", "rtu"],
                        dest="mode", required=True)
    parser.add_argument("-a", help="Slave address", type=parse_hex_or_dec,
                        default=1, dest="slave_addr", required=False)
    parser.add_argument("-c", help="Read Count", type=parse_hex_or_dec,
                        default=1, dest="read_count", required=False)
    parser.add_argument("-r", help="First reg's addr", type=parse_hex_or_dec,
                        default=100, dest="start_addr", required=False)
    parser.add_argument("-t", help="Function type", type=parse_hex_or_dec,
                        choices=[functions.READ_COILS,
                                 functions.READ_DISCRETE_INPUTS,
                                 functions.READ_HOLDING_REGISTERS,
                                 functions.READ_INPUT_REGISTERS,
                                 functions.WRITE_SINGLE_COIL,
                                 functions.WRITE_SINGLE_REGISTER,
                                 functions.WRITE_MULTIPLE_COILS,
                                 functions.WRITE_MULTIPLE_REGISTERS],
                        dest="func_type", required=True)
    parser.add_argument("-o", help="Timeout", type=parse_hex_or_dec,
                        default=1000, dest="timeout", required=False)
    parser.add_argument("-0", help="Slave address decrement",
                        default=False, dest="address_decrement",
                        required=False, action='store_true')

    parser.add_argument('-b', help="Baudrate", type=parse_hex_or_dec,
                        default=9600, dest="baudrate",
                        choices=[50, 75, 110, 150, 300, 600, 1200,
                                 2400, 4800, 9600, 19200, 38400, 57600, 115200],
                        required=False)
    parser.add_argument('-d', help="Data bits", type=parse_hex_or_dec,
                        default=8, dest="data_bits", choices=[7, 8],
                        required=False)
    parser.add_argument('-s', help="Stop bits", type=parse_hex_or_dec,
                        default=1, dest="stop_bits", choices=[1, 2],
                        required=False)

    # There is no way to create two different '-p' options
    # for parity and port. Therefore, there is only one option without
    # choices and default value. We have to check its value in the type
    # function.
    parser.add_argument('-p', help="Parity {none|even|odd} = none | Port = 502",
                        type=parse_parity_or_tcpport, dest="parity_port",
                        metavar='parity|port', required=False)

    parser.add_argument('serialport_host', help="Serial port path or host IP",
                        type=str, metavar='serialport|host')
    parser.add_argument('write_data', nargs='*',
                        type=parse_hex_or_dec, help="Data to write")

    options, unknown_options = parser.parse_known_args()
    set_write_data(parser, unknown_options, options)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG)
    logger.addHandler(stream_handler)

    if options.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    if options.mode == 'tcp':
        if options.parity_port is None:
            options.parity_port = 502
        get_port_params = get_rtu_params
        lib = rtu
    else:
        if options.parity_port is None:
            options.parity_port = 'none'
        get_port_params = get_tcp_params
        lib = tcp

    return process_request(options, lib, get_port_params)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
