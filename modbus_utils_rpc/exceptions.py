class ModbusParametersError(Exception):
    """Rises if umodbus rises an exception after create message attempt"""

    pass


class BrokerConnectionError(Exception):
    """Rises if there is no connection with broker"""

    pass


class RPCClientTimeoutError(Exception):
    """Rises if mqttrpc.library rises Timeout exception"""

    pass


class ModbusParseError(Exception):
    """Rises if umodbus rises an exception after parse response attempt"""

    pass


class RPCError(Exception):
    """Rises if RPC request response is not successful"""

    def __init__(self, error_message, error_code, error_data, parameters):
        self.error_message = error_message
        self.error_code = error_code
        self.error_data = error_data
        self.parameters = parameters


class RPCParseError(Exception):
    """RPC response parsing error"""

    def __init__(self, error_message, error_code, error_data, response):
        self.error_message = error_message
        self.error_code = error_code
        self.error_data = error_data
        self.response = response
