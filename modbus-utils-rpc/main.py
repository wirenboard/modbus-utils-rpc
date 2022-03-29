import argparse
from mqttrpc.client import TMQTTRPCClient, MQTTRPCError 
import paho.mqtt.client as mosquitto
import os
from umodbus.client import tcp
from umodbus.client.serial import rtu

def tcp_path_create(args):
        data={}
        data['ip']=args.ip
        data['port']=args.port
        return data

def rtu_path_create(args):
        data={}
        data['path']=args.serialport
        return data

def request_handling(args):
        lib=args.lib
        func_type=int(args.funcType, 16)

        if (0x05 <= func_type <= 0x10):
                str_data_list=args.writeData.split();
                hex_data_list=[int(x, 16) for x in str_data_list]

        if (func_type==0x01):
                msg_byte=lib.read_coils(args.slaveAddr, args.startAddr, args.readNo)
        elif (func_type==0x02):
                msg_byte=lib.read_discrete_inputs(args.slaveAddr, args.startAddr, args.readNo)
        elif (func_type==0x03):
                msg_byte=lib.read_holding_registers(args.slaveAddr, args.startAddr, args.readNo)
        elif (func_type==0x04):
                msg_byte=lib.read_input_registers(args.slaveAddr, args.startAddr, args.readNo)
        elif (func_type==0x05):
                msg_byte=lib.write_single_coil(args.slaveAddr, args.startAddr, hex_data_list[0])
        elif (func_type==0x06):
                msg_byte=lib.write_single_register(args.slaveAddr, args.startAddr, hex_data_list[0])
        elif (func_type==0x0F):
                msg_byte=lib.write_multiple_coils(args.slaveAddr, args.startAddr, hex_data_list)
        elif (func_type==0x10):
                msg_byte=lib.write_multiple_registers(args.slaveAddr, args.startAddr, hex_data_list)   

        msg_str="".join("{:02x}".format(x) for x in msg_byte)
        resp_size=lib.expected_response_size(msg_byte)

        rpc_parameters=args.path_create(args)
        rpc_parameters['response_size']=resp_size
        rpc_parameters['format']='HEX'
        rpc_parameters['msg']=msg_str

        mqttClient = mosquitto.Mosquitto("modbus-utils-rpc-%d" % os.getpid())
        mqttClient.connect( "127.0.0.1", 1883)
        mqttClient.loop_start()

        rpc_client = TMQTTRPCClient(mqttClient)
        mqttClient.on_message = rpc_client.on_mqtt_message

        resp = rpc_client.call('wb-mqtt-serial', 'port', 'Load', rpc_parameters, args.timeout)

        print(resp['error_msg'])
        if (int(resp['result_code'])!=0):                
                return;

        data=lib.parse_response_adu(bytearray.fromhex(resp['response']), msg_byte)
        if (0x01 <= func_type <= 0x04):
                print ('Read data:')
                print ('[{}]'.format(', '.join(hex(x) for x in data)))
        elif (0x05 <= func_type <= 0x06):
                print ('New value:')
                print("0x%0.2X" % data)
        else:
                print ('Coils/Registers written:')
                print(data)

        

parser = argparse.ArgumentParser()
parser.add_argument("--debug", help="Enable debug output", default=False, dest="debug", required=False, action='store_true')
parser.add_argument("-a", help="Slave address", type=int, default=1, dest="slaveAddr", required=False)
parser.add_argument("-c", help="Read no", type=int, default=1, dest="readNo", required=False)
parser.add_argument("-r", help="Srart address", type=int, default=100, dest="startAddr", required=False)
parser.add_argument("-f", help="Function type", type=str, choices=["0x01", "0x02", "0x03", "0x04", "0x05", "0x06", "0x0F", "0x10"], dest="funcType", required=False)
parser.add_argument("-o", help="Timeout", type=int, default=1000, dest="timeout", required=False)
parser.add_argument("-w", help="Data to write", type=str, dest="writeData", default="", required=False)
subparsers = parser.add_subparsers()
tcp_subparser = subparsers.add_parser("tcp", help="ModbusTCP")
tcp_subparser.add_argument("port", type=int)
tcp_subparser.add_argument("ip", type=str)
tcp_subparser.set_defaults(func=request_handling, lib=tcp, path_create=tcp_path_create)

rtu_subparser = subparsers.add_parser("rtu", help="ModbusRTU")
rtu_subparser.add_argument("serialport", type=str)
rtu_subparser.set_defaults(func=request_handling, lib=rtu, path_create=rtu_path_create)

options = parser.parse_args()
if (hasattr(options,'func')):
        options.func(options)
else:
        print ('No connection type specified!')
