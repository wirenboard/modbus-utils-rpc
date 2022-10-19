# Modbus-utils-RPC

A command-line tool used for modbus RPC requests to [wb-mqtt-serial](https://github.com/wirenboard/wb-mqtt-serial). It provides abilities for sending Modbus requests to port and scan exists Modbus devices using "new-Modbus" feature.

## Modbus client
Use `modbus_client_rpc` command to send a modbus request to the port. Arguments of command are fully compatible with [`modbus_client`]() arguments 
Usage example:

    # modbus_client_rpc --debug -mrtu -pnone  /dev/ttyRS485-2 -a68 -t3 -r128 107
    SUCCESS: read 1 elements:
	    Data: 0x0044 
## Modbus scanner
Use `modbus_scanner_rpc` for scan available devices with "new-Modbus" feature on the bus.
Usage example:

    # modbus_scanner_rpc /dev/ttyRS485-2
    Found device with SN  fe124201 4262609409 modbus address  68

Run `modbus_client_rpc` and `modbus_scanner_rpc` with `-h` option for detailed parameters description. 
