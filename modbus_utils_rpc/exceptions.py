class BrokerConnectionError(Exception):
    """Rises if there is no connection with broker"""
    pass


class RPCClientCallError(Exception):
    """Rises if mqttrpc.library rises an exception"""
    pass


class UModbusError(Exception):
    """Rises if umodbus rises an exception after create message attempt"""
    pass


class RPCWrongParamSetError(Exception):
    """ Rises if RPC result code is RPC_WRONG_PARAM_SET"""
    pass


class RPCWrongParamValueError(Exception):
    """ Rises if RPC result code is RPC_WRONG_PARAM_VALUE"""
    pass


class RPCWrongPortError(Exception):
    """ Rises if RPC result code is RPC_WRONG_PORT"""
    pass


class RPCWrongIOError(Exception):
    """ Rises if RPC result code is RPC_WRONG_IO"""
    pass


class RPCWrongRespLngthError(Exception):
    """ Rises if RPC result code is RPC_WRONG_RESP_LNGTH"""
    pass
