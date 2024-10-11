class ModbusParametersError(Exception):
    """Rises if umodbus rises an exception after create message attempt"""


class BrokerConnectionError(Exception):
    """Rises if there is no connection with broker"""


class RPCClientTimeoutError(Exception):
    """Rises if mqttrpc.library rises Timeout exception"""


class ModbusParseError(Exception):
    """Rises if umodbus rises an exception after parse response attempt"""

    def __init__(self, modbus_message):
        self.modbus_message = modbus_message


class RPCError(Exception):
    """Rises if RPC request response is not successful"""

    def __init__(self, error_message, error_code, error_data):
        self.error_message = error_message
        self.error_code = error_code
        self.error_data = error_data
