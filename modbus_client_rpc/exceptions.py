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

    def __init__(self, result_code, port_path, rpc_parameters, rpc_response):
        self.result_code = result_code
        self.port_path = port_path
        self.rpc_parameters = rpc_parameters
        self.rpc_response = rpc_response
