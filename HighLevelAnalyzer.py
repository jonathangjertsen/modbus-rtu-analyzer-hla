"""
Modbus RTU master+slave analyzer

Even though Modbus RTU uses time for packet limiting, the parsers are implemented as state machines
that can take one byte at a time, so that they can be parsed without knowing the timing information.
This is required Logic does not tell the applications when the stream has ended
(which we would need in order to parse the frames based on timing information).

Currently supported Modbus function codes:

    - 03: Read holding registers
    - 16: Write multiple registers
"""
import dataclasses
import enum
from pathlib import Path
from typing import Optional
import typing

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, NumberSetting
from saleae.data import GraphTimeDelta

def swap_endian_uint16(x: int):
    """
    Swap the endianness of a uint16
    """
    return ((x & 0x00ff) << 8) | ((x & 0xff00) >> 8)


def swap_endian_uint16_array(uint16_array: tuple) -> tuple:
    """
    Swap the endianness of all entries in a tuple of 16-bit ints
    """
    return tuple(swap_endian_uint16(x) for x in uint16_array)


def swap_endian_bytes(uint8_array: typing.ByteString) -> bytes:
    """
    Swap the endianness of a byte array
    """
    uint16_array   = bytes_to_uint16_array(uint8_array)
    uint16_swapped = swap_endian_uint16_array(uint16_array)
    uint8_swapped  = uint16_array_to_bytes(uint16_swapped)
    return uint8_swapped


def bytes_to_uint16_array(bytes_in: typing.ByteString) -> tuple:
    """
    Converts a byte array to a list of holding register values
    """
    return tuple(
        int.from_bytes(bytes_in[i:i+2], byteorder="big")
        for i in range(0, len(bytes_in), 2)
    )


def bytes_to_uint16(bytes_in: typing.ByteString) -> int:
    """
    Convert a 2-byte byte array to a 16-bit uint
    """
    assert len(bytes_in) == 2
    return bytes_to_uint16_array(bytes_in)[0]


def uint16_to_bytes(integer):
    """
    Convert a 16-bit uint to a 2-byte array
    """
    return bytes((integer >> 8, integer & 0xff))


def uint16_array_to_bytes(uint16_array):
    out = bytearray()
    for uint16 in uint16_array:
        out += uint16_to_bytes(uint16)
    return bytes(out)

def extract_crc(data: typing.Union) -> int:
    """
    Extract the received CRC from an encoded modbus frame
    """
    assert len(data) >= 2
    return swap_endian_uint16(bytes_to_uint16_array(data[-2:])[0])


def modbus_crc(data: bytes) -> int:
    """
    Calculate the expected CRC of an encoded modbus frame (sans the CRC)
    """
    crc_high = 0xff
    crc_low = 0xff
    for byte in data:
        index = (crc_low ^ byte) & 0xff
        crc_low = (crc_high ^ CRC_HIGH[index]) & 0xff
        crc_high = CRC_LOW[index]
    return (crc_high << 8) | crc_low


def append_modbus_crc(data) -> bytes:
    """
    Append checksum to an encoded modbus frame (sans the CRC)
    """
    data = bytes(data)
    return data + modbus_crc(data).to_bytes(length=2, byteorder="little")

# Initial and final available address
# For now, just allow any 16-bit address
ADDRESS_START = 0
ADDRESS_END = 1 << 16


class ModbusParserState(enum.Enum):
    """
    Each of the states that the modbus parser can be in
    """
    GetAddress = enum.auto()
    GetFunctionCode = enum.auto()
    GetStartRegisterMsb = enum.auto()
    GetStartRegisterLsb = enum.auto()
    GetRegisterCountMsb = enum.auto()
    GetRegisterCountLsb = enum.auto()
    GetByteCount = enum.auto()
    GetNextByte = enum.auto()
    GetCrcMsb = enum.auto()
    GetCrcLsb = enum.auto()
    GetExceptionCode = enum.auto()
    Success = enum.auto()
    Error = enum.auto()

class ModbusParserStatusCode(enum.Enum):
    """
    All possible results of parsing a byte stream
    """
    Incomplete = enum.auto()
    Success = enum.auto()
    AddressOutOfBounds = enum.auto()
    UnknownFunctionCode = enum.auto()
    StartRegisterOutOfBounds = enum.auto()
    RegisterCountOutOfBounds = enum.auto()
    ByteCountInconsistent = enum.auto()
    ByteCountOdd = enum.auto()
    CrcIncorrect = enum.auto()

class ModbusParserException(Exception):
    """
    Raised on fatal errors during parsing
    """

class ModbusFrameType(enum.Enum):
    """
    Request and response
    """
    Request = enum.auto()
    Response = enum.auto()

class ModbusFunctionCode(enum.Enum):
    """
    All supported modbus function codes
    """
    ReadHolding   = 0x03
    WriteMultiple = 0x10

    ExceptionReadHolding   = 0x80 | 0x03
    ExceptionWriteMultiple = 0x80 | 0x03

    # Set unknown to something that's not encodable as a byte
    Unknown = 0x100

class ModbusExceptionCode(enum.Enum):
    """
    All standard Modbus exception codes
    """
    IllegalFunction                    = 0x01
    IllegalDataAddress                 = 0x02
    IllegalDataValue                   = 0x03
    SlaveDeviceFailure                 = 0x04
    Acknowledge                        = 0x05
    SlaveDeviceBusy                    = 0x06
    NegativeAcknowledge                = 0x07
    MemoryParityError                  = 0x08
    GatewayPathUnavailable             = 0x0a
    GatewayTargetDeviceFailedToRespond = 0x0b
    Unknown                            = 0x100

@dataclasses.dataclass
class ModbusFrame:
    """
    Intermediate representation of a Modbus frame
    """
    frame_type: ModbusFrameType
    function: ModbusFunctionCode
    address: int
    data: list
    register_count: int
    start_register: int
    raw_data: list = None
    exception_code: int = None


@dataclasses.dataclass
class ModbusParserBase:
    """
    Common code for the request and response parsers
    """
    frame_type = None
    state: ModbusParserState = ModbusParserState.GetAddress
    address: int = None
    start_register: int = None
    register_count: int = None
    crc_received: int = None
    crc_calculated: int = None
    function: ModbusFunctionCode = None
    status_code: ModbusParserStatusCode = ModbusParserStatusCode.Incomplete
    exception_code: int = None
    _data: list = dataclasses.field(default_factory=list)
    _msb: int = 0
    _count: int = 0
    _raw: list = dataclasses.field(default_factory=list)

    def is_finished(self) -> bool:
        return self.status_code != ModbusParserStatusCode.Incomplete

    def is_successful(self) -> bool:
        return self.status_code == ModbusParserStatusCode.Success

    def make_frame(self):
        try:
            func = ModbusFunctionCode(self.function)
        except ValueError:
            func = ModbusFunctionCode.Unknown

        return ModbusFrame(
            frame_type=self.frame_type,
            function=func,
            address=self.address,
            data=bytes_to_uint16_array(self._data),
            start_register=self.start_register,
            register_count=self.register_count,
            raw_data=self._raw,
            exception_code=self.exception_code
        )

    def update(self, byte):
        self._raw.append(byte)
        if   self.state == ModbusParserState.GetAddress:
            self.state = self.handler_get_address(byte)
        elif self.state == ModbusParserState.GetFunctionCode:
            self.state = self.handler_get_function_code(byte)
        elif self.state == ModbusParserState.GetStartRegisterMsb:
            self.state = self.handler_get_msb(byte, ModbusParserState.GetStartRegisterLsb)
        elif self.state == ModbusParserState.GetStartRegisterLsb:
            self.state = self.handler_get_start_register_lsb(byte)
        elif self.state == ModbusParserState.GetRegisterCountMsb:
            self.state = self.handler_get_msb(byte, ModbusParserState.GetRegisterCountLsb)
        elif self.state == ModbusParserState.GetRegisterCountLsb:
            self.state = self.handler_get_register_count_lsb(byte)
        elif self.state == ModbusParserState.GetByteCount:
            self.state = self.handler_get_byte_count(byte)
        elif self.state == ModbusParserState.GetNextByte:
            self.state = self.handler_get_next_byte(byte)
        elif self.state == ModbusParserState.GetCrcMsb:
            self.state = self.handler_get_msb(byte, ModbusParserState.GetCrcLsb)
        elif self.state == ModbusParserState.GetCrcLsb:
            self.state = self.handler_get_crc_lsb(byte)
        elif self.state == ModbusParserState.GetExceptionCode:
            self.state = self.handler_get_exception_code(byte)
        else:
            raise ModbusParserException(self.state, byte)
        if self.is_finished():
            return self.make_frame()
        else:
            return None

    def handler_get_address(self, byte):
        self.address = byte
        if 0 <= self.address <= 0xf7:
            return ModbusParserState.GetFunctionCode
        else:
            self.status_code = ModbusParserStatusCode.AddressOutOfBounds
            return ModbusParserState.Error

    def handler_get_msb(self, byte, next_state):
        self._msb = byte
        return next_state

    def handler_get_exception_code(self, byte):
        self.exception_code = ModbusExceptionCode(byte)
        return ModbusParserState.GetCrcMsb

    def handler_get_crc_lsb(self, byte):
        self.crc_received = (byte << 8) | self._msb
        self.crc_calculated = modbus_crc(self._raw[:-2])
        if self.crc_calculated == self.crc_received:
            self.status_code = ModbusParserStatusCode.Success
            return ModbusParserState.Success
        else:
            self.status_code = ModbusParserStatusCode.CrcIncorrect
            return ModbusParserState.Error

class ModbusParserRequest(ModbusParserBase):
    frame_type = ModbusFrameType.Request

    def handler_get_function_code(self, byte):
        self.function = byte
        if byte in { ModbusFunctionCode.ReadHolding.value, ModbusFunctionCode.WriteMultiple.value }:
            return ModbusParserState.GetStartRegisterMsb
        else:
            self.status_code = ModbusParserStatusCode.UnknownFunctionCode
            return ModbusParserState.Error

    def handler_get_start_register_lsb(self, byte):
        self.start_register = (self._msb << 8) | byte
        if ADDRESS_START <= self.start_register <= ADDRESS_END:
            return ModbusParserState.GetRegisterCountMsb
        else:
            self.status_code = ModbusParserStatusCode.StartRegisterOutOfBounds
            return ModbusParserState.Error

    def handler_get_register_count_lsb(self, byte):
        self.register_count = (self._msb << 8) | byte
        if ADDRESS_START <= self.start_register + self.register_count <= ADDRESS_END:
            if self.function == ModbusFunctionCode.WriteMultiple.value:
                return ModbusParserState.GetByteCount
            else:
                return ModbusParserState.GetCrcMsb
        else:
            self.status_code = ModbusParserStatusCode.RegisterCountOutOfBounds
            return ModbusParserState.Error

    def handler_get_byte_count(self, byte):
        if byte == 2 * self.register_count:
            return ModbusParserState.GetNextByte
        else:
            self.status_code = ModbusParserStatusCode.ByteCountInconsistent
            return ModbusParserState.Error

    def handler_get_next_byte(self, byte):
        self._data.append(byte)
        if len(self._data) >= 2 * self.register_count:
            return ModbusParserState.GetCrcMsb
        else:
            return ModbusParserState.GetNextByte

class ModbusParserResponse(ModbusParserBase):
    frame_type = ModbusFrameType.Response

    def handler_get_function_code(self, byte):
        self.function = byte
        if byte == ModbusFunctionCode.WriteMultiple.value:
            return ModbusParserState.GetStartRegisterMsb
        elif byte == ModbusFunctionCode.ReadHolding.value:
            return ModbusParserState.GetByteCount
        elif byte & 0x80:
            return ModbusParserState.GetExceptionCode
        else:
            self.status_code = ModbusParserStatusCode.UnknownFunctionCode
            return ModbusParserState.Error

    def handler_get_start_register_lsb(self, byte):
        self.start_register = (self._msb << 8) | byte
        if ADDRESS_START <= self.start_register <= ADDRESS_END:
            return ModbusParserState.GetRegisterCountMsb
        else:
            self.status_code = ModbusParserStatusCode.StartRegisterOutOfBounds
            return ModbusParserState.Error

    def handler_get_register_count_lsb(self, byte):
        self.register_count = (self._msb << 8) | byte
        if ADDRESS_START <=  self.start_register + self.register_count <= ADDRESS_END:
            return ModbusParserState.GetCrcMsb
        else:
            self.status_code = ModbusParserStatusCode.RegisterCountOutOfBounds
            return ModbusParserState.Error

    def handler_get_byte_count(self, byte):
        if byte % 2 == 0:
            self.register_count = byte // 2
            return ModbusParserState.GetNextByte
        else:
            self.status_code = ModbusParserStatusCode.ByteCountOdd
            return ModbusParserState.Error

    def handler_get_next_byte(self, byte):
        self._data.append(byte)
        if len(self._data) >= 2 * self.register_count:
            return ModbusParserState.GetCrcMsb
        else:
            return ModbusParserState.GetNextByte

class ModbusParserRequestOrResponse():
    """
    Without parsing the application level of the modbus transactions, we don't know whether the next
    frame on any given line is a request or a response.
    This composite parser will attempt to parse it both as a request and a response, and returning the
    results of both.
    """
    def __init__(self):
        self.request = ModbusParserRequest()
        self.response = ModbusParserResponse()

    def update(self, byte):
        req_finished = self.request.is_finished()
        res_finished = self.response.is_finished()
        result_res = None
        result_req = None
        if not req_finished:
            result_req = self.request.update(byte)
        if not res_finished:
            result_res = self.response.update(byte)
        if req_finished and res_finished:
            raise ModbusParserException(
                self.request.state.name,
                self.request.status_code.name,
                self.response.state.name,
                self.response.status_code.name,
                byte
            )
        return result_res, result_req


def hex_encoded_string(data: bytes) -> str:
    """
    Returns a hex encoded version of the data
    """
    return ''.join(f'{x:04X}' for x in data)


def explain(result: ModbusFrame) -> str:
    """
    Convert a ModbusFrame to a human readable representation
    """
    if result.frame_type == ModbusFrameType.Request:
        if result.function == ModbusFunctionCode.WriteMultiple:
            if result.address == 0:
                return f"Master broadcasted write: start_register={result.start_register}, n_registers={result.register_count}, data={hex_encoded_string(result.data)}"
            else:
                return f"Master requested device #{result.address} write: start_register={result.start_register+1}, n_registers={result.register_count}, data={hex_encoded_string(result.data)}"
        elif result.function == ModbusFunctionCode.ReadHolding:
            return f"Master requested device #{result.address} read: start_register={result.start_register+1}, n_registers={result.register_count}"
    else:
        if result.function == ModbusFunctionCode.WriteMultiple:
            return f"Device #{result.address} responded to write: start_register={result.start_register+1}, n_registers={result.register_count}"
        elif result.function == ModbusFunctionCode.ReadHolding:
            return f"Device #{result.address} responded to read: n_registers={result.register_count}, data={hex_encoded_string(result.data)}"
        elif result.function.value & 0x80:
            return f"Device #{result.address} responded with {result.function.name}: {result.exception_code.name}"


class Hla(HighLevelAnalyzer):
    result_types = {
        "Frame": {
            "format": "{{{data.explanation}}}",
        },
        "Error": {
            "format": "ERROR: {{{data.error}}}"
        },
    }

    inter_character_timeout = NumberSetting(label="Timeout between characters (if 0, will use 750µs)")

    def __init__(self):
        self.reset()
        if self.inter_character_timeout == 0:
            self.inter_character_timeout = 750
        self.inter_character_timeout_delta = GraphTimeDelta(microsecond=self.inter_character_timeout)

    def reset(self):
        """
        Reset internal state (it will be as if we have never seen a packet before)
        """
        self.parser = ModbusParserRequestOrResponse()
        self.start_time = None
        self.end_time = None
        self.data = []

    def decode(self, frame: AnalyzerFrame) -> Optional[AnalyzerFrame]:
        # Return value
        out = None

        # Extract the byte
        byte, = frame.data["data"]

        # Check if we timed out
        if self.start_time is not None:
            if frame.start_time > self.end_time + self.inter_character_timeout_delta:
                out = AnalyzerFrame(
                    type="Timeout",
                    start_time=self.start_time,
                    end_time=self.end_time,
                    data={
                        "explanation": f"Timeout / corrupted frame after {len(self.data)} bytes"
                    }
                )
                self.reset()

        # Update start/end time
        if self.start_time is None:
            self.start_time = frame.start_time
        self.end_time = frame.end_time

        try:
            # Try to update the parser
            result_res, result_req = self.parser.update(byte)
            print(result_res)
        except Exception as exception:
            # No luck
            out = AnalyzerFrame(
                type="Error",
                start_time=self.start_time,
                end_time=self.end_time,
                data={
                    "explanation": str(exception)
                }
            )
            self.reset()
        else:
            # See if we got something
            have_request  = result_req and self.parser.request.is_successful()
            have_response = result_res and self.parser.response.is_successful()
            if have_request and have_response:
                out = AnalyzerFrame(
                    type="Frame",
                    start_time=self.start_time,
                    end_time=self.end_time,
                    data={
                        "address": hex(result_res.address),
                        "explanation": f'Ambiguous; either "{explain(result_res)}" or "{explain(result_req)}"',
                    }
                )
                self.reset()
            elif have_request:
                out = AnalyzerFrame(
                    type="Frame",
                    start_time=self.start_time,
                    end_time=self.end_time,
                    data={
                        "address": hex(result_req.address),
                        "explanation": explain(result_req)
                    }
                )
                self.reset()
            elif have_response:
                out = AnalyzerFrame(
                    type="Frame",
                    start_time=self.start_time,
                    end_time=self.end_time,
                    data={
                        "address": hex(result_res.address),
                        "explanation": explain(result_res)
                    }
                )
                self.reset()
        return out

###############
# CRC tables
###############

CRC_HIGH = [
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x00, 0xC1, 0x81, 0x40,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40, 0x01, 0xC0, 0x80, 0x41, 0x01, 0xC0, 0x80, 0x41,
    0x00, 0xC1, 0x81, 0x40
]

CRC_LOW = [
    0x00, 0xC0, 0xC1, 0x01, 0xC3, 0x03, 0x02, 0xC2, 0xC6, 0x06, 0x07, 0xC7,
    0x05, 0xC5, 0xC4, 0x04, 0xCC, 0x0C, 0x0D, 0xCD, 0x0F, 0xCF, 0xCE, 0x0E,
    0x0A, 0xCA, 0xCB, 0x0B, 0xC9, 0x09, 0x08, 0xC8, 0xD8, 0x18, 0x19, 0xD9,
    0x1B, 0xDB, 0xDA, 0x1A, 0x1E, 0xDE, 0xDF, 0x1F, 0xDD, 0x1D, 0x1C, 0xDC,
    0x14, 0xD4, 0xD5, 0x15, 0xD7, 0x17, 0x16, 0xD6, 0xD2, 0x12, 0x13, 0xD3,
    0x11, 0xD1, 0xD0, 0x10, 0xF0, 0x30, 0x31, 0xF1, 0x33, 0xF3, 0xF2, 0x32,
    0x36, 0xF6, 0xF7, 0x37, 0xF5, 0x35, 0x34, 0xF4, 0x3C, 0xFC, 0xFD, 0x3D,
    0xFF, 0x3F, 0x3E, 0xFE, 0xFA, 0x3A, 0x3B, 0xFB, 0x39, 0xF9, 0xF8, 0x38,
    0x28, 0xE8, 0xE9, 0x29, 0xEB, 0x2B, 0x2A, 0xEA, 0xEE, 0x2E, 0x2F, 0xEF,
    0x2D, 0xED, 0xEC, 0x2C, 0xE4, 0x24, 0x25, 0xE5, 0x27, 0xE7, 0xE6, 0x26,
    0x22, 0xE2, 0xE3, 0x23, 0xE1, 0x21, 0x20, 0xE0, 0xA0, 0x60, 0x61, 0xA1,
    0x63, 0xA3, 0xA2, 0x62, 0x66, 0xA6, 0xA7, 0x67, 0xA5, 0x65, 0x64, 0xA4,
    0x6C, 0xAC, 0xAD, 0x6D, 0xAF, 0x6F, 0x6E, 0xAE, 0xAA, 0x6A, 0x6B, 0xAB,
    0x69, 0xA9, 0xA8, 0x68, 0x78, 0xB8, 0xB9, 0x79, 0xBB, 0x7B, 0x7A, 0xBA,
    0xBE, 0x7E, 0x7F, 0xBF, 0x7D, 0xBD, 0xBC, 0x7C, 0xB4, 0x74, 0x75, 0xB5,
    0x77, 0xB7, 0xB6, 0x76, 0x72, 0xB2, 0xB3, 0x73, 0xB1, 0x71, 0x70, 0xB0,
    0x50, 0x90, 0x91, 0x51, 0x93, 0x53, 0x52, 0x92, 0x96, 0x56, 0x57, 0x97,
    0x55, 0x95, 0x94, 0x54, 0x9C, 0x5C, 0x5D, 0x9D, 0x5F, 0x9F, 0x9E, 0x5E,
    0x5A, 0x9A, 0x9B, 0x5B, 0x99, 0x59, 0x58, 0x98, 0x88, 0x48, 0x49, 0x89,
    0x4B, 0x8B, 0x8A, 0x4A, 0x4E, 0x8E, 0x8F, 0x4F, 0x8D, 0x4D, 0x4C, 0x8C,
    0x44, 0x84, 0x85, 0x45, 0x87, 0x47, 0x46, 0x86, 0x82, 0x42, 0x43, 0x83,
    0x41, 0x81, 0x80, 0x40
]
