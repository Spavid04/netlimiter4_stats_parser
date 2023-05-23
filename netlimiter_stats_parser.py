#   Explanation and format of stats files:
#
# stored in %PROGRAMDATA%\Locktime\NetLimiter\4\Stats\*
# contains 4 files:
#   * nlstatsV6.db - transfer stats per app, for IPv6 addresses
#   * nlstatsV4.db - transfer stats per app, for IPv4 addresses
#   * nlstats-apps.lst - known app list
#   * nlstats-users.lst - known user list
# all files are byte streams of fixed-size structures (except the app list) dumped directly to a file
# one stat "row" contains information about a transfer, per app, per connection, grouped by the update time (set in NetLimiter GUI -> Tools -> Stats manager)
#
#
#   IP2LOC files:
#
# maps IP's (specifically, IP ranges) to their geographical locations
# stored in %PROGRAMDATA%\Locktime\NetLimiter\4\Ip2Loc\*
# for each *.dat file, there is a *.xml file that describes the format (and order of fields!) of structures
# 3 important files:
#   * IpRangesV4.dat - ipv4 range to location id
#   * IpRangesV6.dat - ipv6 range to location id
#   * Locations.dat - location id's to actual names
# IpRangesV4.dat is a simple byte stream of a fixed size structure dumped directly
# IpRangesV6.dat and Locations.dat are a bit more complicated, but are still mostly a byte stream of dumped structures
# IpRangesV6.dat and Locations.dat format:
#   * files are broken up into chunks of fixed size (1024 bytes in both cases)
#   * each chunk contains a UINT16 at offset 0 that specifies how many structures it contains
#   * starting at offset 2, variable-sized structures start:
#       * in structure order, dump all fields and:
#           * if the field is a fixed size type (eg. UINT32), dump it directly to the byte stream
#           * if the field is a variable sized type (eg. byte[]), first dump a UINT16 size of the data, then the data
#   * at the end of the file, if there is no space left for another structure, 0x00 padding until the end of the chunk
# IpRangesV6.dat specific: comparing "sparse" IP's:
#   *
# Locations.dat specific: strings are ASCII encoded

import collections
import ctypes
import datetime
import io
import ipaddress
import os
import struct
import typing
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor


# region Utils


EPOCH = datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc)
def epoch_time_to_datetime(epoch_time: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(seconds=epoch_time)


def ipraw_to_str(raw: typing.Union[int, bytes]) -> str:
    if isinstance(raw, int):
        return str(ipaddress.IPv4Address(raw))
    else:
        return str(ipaddress.IPv6Address(raw))


def str_to_ipraw(string: str) -> typing.Union[int, bytes]:
    if "." in string:
        return int(ipaddress.IPv4Address(string))
    else:
        return int(ipaddress.IPv6Address(string)).to_bytes(6, byteorder="little")


def _chunkify(f: typing.BinaryIO, chunk_size: int) -> typing.Generator[io.BytesIO, None, None]:
    buffer = io.BytesIO()

    while True:
        data = f.read(chunk_size)
        if not data or len(data) < chunk_size:
            break

        buffer.seek(0)
        buffer.write(data)
        buffer.seek(0)

        yield buffer


class BinaryFDAdapter():
    def __init__(self, pathOrFd: typing.Union[str, typing.BinaryIO], writable: bool = False):
        self.pathOrFd = pathOrFd
        self.writable = writable
        self._toClose = False
        self.fd: typing.BinaryIO = None

    def __enter__(self) -> typing.BinaryIO:
        if isinstance(self.pathOrFd, str):
            self._toClose = True
            self.fd = open(self.pathOrFd, "wb" if self.writable else "rb")
        elif isinstance(self.pathOrFd, io.IOBase):
            self.fd = self.pathOrFd
        else:
            raise ValueError()

        return self.fd

    def __exit__(self, _, __, ___):
        if self._toClose:
            self.fd.close()

# endregion


# region Structures


class RawStatsTransferData(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("data_out_payload", ctypes.c_uint32),
        ("zero1", ctypes.c_uint16), # seems to USUALLY be (WORD)0
        ("app_id", ctypes.c_uint16),
        ("data_in_payload", ctypes.c_uint32),
        ("zero2", ctypes.c_uint16), # seems to USUALLY be (WORD)0
        ("user_id", ctypes.c_uint16), # possibly user_id
        ("data_out_overhead", ctypes.c_uint32),
        ("zero3", ctypes.c_uint16), # seems to always be (WORD)0
        ("u3_flags", ctypes.c_uint16), # unknown WORD
        ("data_in_overhead", ctypes.c_uint32),
        ("zero4", ctypes.c_uint16), # seems to always be (WORD)0
        ("network_id", ctypes.c_uint16) # possibly network_id
    ]

    def __str__(self):
        return "\n".join(field + ": " + str(getattr(self, field)) for (field, _) in self._fields_)


assert (ctypes.sizeof(RawStatsTransferData) == 32)


class RawStatsRowV4(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("timestamp", ctypes.c_uint32),

        ("local_ip", ctypes.c_uint32),
        ("remote_ip", ctypes.c_uint32),

        ("local_port", ctypes.c_uint16),
        ("remote_port", ctypes.c_uint16),

        ("transfer_data", RawStatsTransferData)
    ]

    def __str__(self):
        return "\n".join(field + ": " + str(getattr(self, field)) for (field, _) in self._fields_)


class RawStatsRowV6(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("timestamp", ctypes.c_uint32),

        ("local_ip", ctypes.c_byte * 16),
        ("remote_ip", ctypes.c_byte * 16),

        ("local_port", ctypes.c_uint16),
        ("remote_port", ctypes.c_uint16),

        ("transfer_data", RawStatsTransferData)
    ]

    def __str__(self):
        return "\n".join(field + ": " + str(getattr(self, field)) for (field, _) in self._fields_)


class RawAppsRow(ctypes.Structure):
    # unused, only for reference
    _pack_ = 1
    _fields_ = [
        ("app_id", ctypes.c_uint16),

        ("path_length", ctypes.c_uint16),
        ("path", ctypes.c_wchar * 0)
    ]

    def __str__(self):
        return "\n".join(field + ": " + str(getattr(self, field)) for (field, _) in self._fields_)


class RawUsersRow(ctypes.Structure):
    # unused, only for reference
    _pack_ = 1
    _fields_ = [
        ("user_id", ctypes.c_uint16),

        ("user_sid_length", ctypes.c_uint16),
        ("sid", ctypes.c_byte * 0)
    ]

    def __str__(self):
        return "\n".join(field + ": " + str(getattr(self, field)) for (field, _) in self._fields_)


class RawIPv4LocationRangeRow(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("location_id", ctypes.c_uint32),
        ("start_ip", ctypes.c_uint32),
        ("end_ip", ctypes.c_uint32),
    ]

    def __str__(self):
        return "\n".join(field + ": " + str(getattr(self, field)) for (field, _) in self._fields_)


class RawIPv6LocationRangeRow(ctypes.Structure):
    # unused, only for reference
    _pack_ = 1
    _fields_ = [
        ("location_id", ctypes.c_uint32),
        ("start_ip_length", ctypes.c_uint16),
        ("start_ip", ctypes.c_byte * 0),
        ("end_ip_length", ctypes.c_uint16),
        ("end_ip", ctypes.c_byte * 0),
    ]

    def __str__(self):
        return "\n".join(field + ": " + str(getattr(self, field)) for (field, _) in self._fields_)
class RawIPv6LocationRangeChunk(ctypes.Structure):
    # unused, only for reference
    _pack_ = 1024
    _fields_ = [
        ("item_count", ctypes.c_uint16),
        ("items_bytes", ctypes.POINTER(RawIPv6LocationRangeRow)),
        ("padding", ctypes.c_byte * 0),
    ]


class RawLocationRow(ctypes.Structure):
    # unused, only for reference
    _pack_ = 1
    _fields_ = [
        ("location_id", ctypes.c_uint32),
        ("latitude", ctypes.c_double),
        ("longitude", ctypes.c_double),
        ("town_length", ctypes.c_uint16),
        ("town", ctypes.c_byte * 0),
        ("province_length", ctypes.c_uint16),
        ("province", ctypes.c_byte * 0),
        ("country_length", ctypes.c_uint16),
        ("country", ctypes.c_byte * 0),
        ("country_code_length", ctypes.c_uint16),
        ("country_code", ctypes.c_byte * 0),
    ]

    def __str__(self):
        return "\n".join(field + ": " + str(getattr(self, field)) for (field, _) in self._fields_)
class RawLocationChunk(ctypes.Structure):
    # unused, only for reference
    _pack_ = 1024
    _fields_ = [
        ("item_count", ctypes.c_uint16),
        ("items_bytes", ctypes.POINTER(RawLocationRow)),
        ("padding", ctypes.c_byte * 0),
    ]


# endregion


# region Stats


class StatsRow:
    def __init__(self, raw_row: typing.Union[RawStatsRowV4, RawStatsRowV6]):
        self.raw_row = raw_row
        self.ip_version = 4 if isinstance(raw_row, RawStatsRowV4) else 6

        self._timestamp = None
        self.raw_timestamp = raw_row.timestamp

        self._local_ip = None
        self._remote_ip = None

        self.local_port = raw_row.local_port
        self.remote_port = raw_row.remote_port

        self.data_out_payload = raw_row.transfer_data.data_out_payload
        self.data_in_payload = raw_row.transfer_data.data_in_payload
        self.data_out_overhead = raw_row.transfer_data.data_out_overhead
        self.data_in_overhead = raw_row.transfer_data.data_in_overhead
        self.data_out_total = self.data_out_payload + self.data_out_overhead
        self.data_in_total = self.data_in_payload + self.data_in_overhead

        self.app_id = raw_row.transfer_data.app_id
        self.network_id = raw_row.transfer_data.network_id

    @property
    def timestamp(self):
        if self._timestamp is None:
            self._timestamp = epoch_time_to_datetime(self.raw_row.timestamp).astimezone(tz=None).replace(tzinfo=None)
        return self._timestamp

    @property
    def local_ip(self):
        if self._local_ip is None:
            self._local_ip = ipraw_to_str(self.raw_row.local_ip)
        return self._local_ip

    @property
    def remote_ip(self):
        if self._remote_ip is None:
            self._remote_ip = ipraw_to_str(self.raw_row.remote_ip)
        return self._remote_ip

    def process(self):
        _ = self.timestamp
        _ = self.local_ip
        _ = self.remote_ip


class AppRow:
    def __init__(self, app_id: int, path: str):
        self.app_id = app_id
        self.path = path

    @staticmethod
    def from_stream(stream: typing.BinaryIO) -> typing.Optional["AppRow"]:
        header = stream.read(4)
        if not header:
            return None
        if len(header) != 4:
            return None

        app_id = int.from_bytes(header[0:2], byteorder="little", signed=False)
        path_length = int.from_bytes(header[2:4], byteorder="little", signed=False)

        raw = stream.read(path_length * 2)
        if not raw:
            return None
        if len(raw) != path_length * 2:
            return None

        return AppRow(app_id, raw.decode("utf-16le"))

    def to_bytes(self) -> bytes:
        b = self.app_id.to_bytes(2, byteorder="little", signed=False)
        b += (len(self.path) * 2).to_bytes(2, byteorder="little", signed=False)
        b += self.path.encode("utf-16le")
        return b


class UserRow:
    def __init__(self, user_id: int, sid: bytes):
        self.user_id = user_id
        self.sid = sid

    @staticmethod
    def from_stream(stream: typing.BinaryIO) -> typing.Optional["UserRow"]:
        header = stream.read(4)
        if not header:
            return None
        if len(header) != 4:
            return None

        user_id = int.from_bytes(header[0:2], byteorder="little", signed=False)
        user_sid_length = int.from_bytes(header[2:4], byteorder="little", signed=False)

        raw = stream.read(user_sid_length)
        if not raw:
            return None
        if len(raw) != user_sid_length:
            return None

        return UserRow(user_id, raw)

    def to_bytes(self) -> bytes:
        b = self.user_id.to_bytes(2, byteorder="little", signed=False)
        b += (len(self.sid)).to_bytes(2, byteorder="little", signed=False)
        b += self.sid
        return b


def get_apps(pathOrFd: typing.Union[str, typing.BinaryIO]) -> typing.Generator[AppRow, None, None]:
    with BinaryFDAdapter(pathOrFd) as f:
        while True:
            row = AppRow.from_stream(f)
            if not row:
                break
            yield row

def get_users(pathOrFd: typing.Union[str, typing.BinaryIO]) -> typing.Generator[UserRow, None, None]:
    with BinaryFDAdapter(pathOrFd) as f:
        while True:
            row = UserRow.from_stream(f)
            if not row:
                break
            yield row

def __get_rows_commons(pathOrFd: typing.Union[str, typing.BinaryIO], ipv6: bool = None):
    bfda = BinaryFDAdapter(pathOrFd)
    if isinstance(pathOrFd, str):
        if ipv6 is None:
            ipv6 = "6" in os.path.split(pathOrFd)[1]
    elif isinstance(pathOrFd, io.IOBase):
        if ipv6 is None:
            raise ValueError()
    else:
        raise ValueError()
    classType = RawStatsRowV6 if ipv6 else RawStatsRowV4
    sizeof = ctypes.sizeof(classType)

    return (bfda, classType, sizeof)

def get_rows(pathOrFd: typing.Union[str, typing.BinaryIO], ipv6: bool = None) -> typing.Generator[StatsRow, None, None]:
    (bfda, classType, sizeof) = __get_rows_commons(pathOrFd, ipv6)

    with bfda as f:
        while True:
            buffer = f.read(sizeof)
            if not buffer:
                break
            yield StatsRow(classType.from_buffer_copy(buffer))


def __process_batch(classType, sizeof, buffer):
    data_rows = []
    offset = 0

    while offset < len(buffer):
        data_rows.append(StatsRow(classType.from_buffer_copy(buffer, offset)))
        offset += sizeof

    return data_rows
def get_batched_rows(pathOrFd: typing.Union[str, typing.BinaryIO], ipv6: bool = None, batch_size: int = 1000) -> typing.Generator[typing.List[StatsRow], None, None]:
    (bfda, classType, sizeof) = __get_rows_commons(pathOrFd, ipv6)
    batch_byte_size = sizeof * batch_size

    futures = collections.deque()
    with ThreadPoolExecutor() as pool, bfda as f:
        while True:
            buffer = f.read(batch_byte_size)
            if not buffer:
                break

            if len(futures) > 0:
                if futures[0].done():
                    yield futures.popleft().result()
            futures.append(pool.submit(__process_batch, classType, sizeof, buffer))

    for future in futures:
        yield future.result()


# endregion


# region Locations


class IpRange:
    def __init__(self, raw_row: typing.Optional[RawIPv4LocationRangeRow]):
        self.raw_row = raw_row
        self.ip_version = 4

        self.location_id = raw_row.location_id if raw_row else None
        self.start_ip = raw_row.start_ip if raw_row else None
        self.end_ip = raw_row.end_ip if raw_row else None

    def contains_ip(self, ip: typing.Union[int, bytes]) -> bool:
        if (self.ip_version == 4 and isinstance(ip, int)) or \
                (self.ip_version == 6 and isinstance(ip, bytes)):
            return self.start_ip <= ip <= self.end_ip

        return False


def _get_ranges_v6(f: typing.BinaryIO) -> typing.Generator[IpRange, None, None]:
    for chunk_stream in _chunkify(f, 1024):
        [item_count] = struct.unpack("H", chunk_stream.read(2))
        if item_count == 0:
            break

        for i in range(item_count):
            [location_id] = struct.unpack("I", chunk_stream.read(4))
            [length] = struct.unpack("H", chunk_stream.read(2))
            start_ip = chunk_stream.read(length)
            [length] = struct.unpack("H", chunk_stream.read(2))
            end_ip = chunk_stream.read(length)

            iprange = IpRange(None)
            iprange.ip_version = 6
            iprange.location_id = location_id
            iprange.start_ip = start_ip
            iprange.end_ip = end_ip
            yield iprange


def get_ranges(path: str) -> typing.Generator[IpRange, None, None]:
    version = 4 if "4" in os.path.split(path)[1] else 6

    with open(path, "rb") as f:
        if version == 4:
            sizeof = ctypes.sizeof(RawIPv4LocationRangeRow)
            while True:
                buffer = f.read(sizeof)
                if not buffer:
                    break
                yield IpRange(RawIPv4LocationRangeRow.from_buffer_copy(buffer))
        else:
            yield from _get_ranges_v6(f)


class LocationRow:
    def __init__(self, id: int, latitude: float, longitude: float, town: str, province: str, country: str, country_code: str):
        self.id = id
        self.latitude = latitude
        self.longitude = longitude
        self.town = town
        self.province = province
        self.country = country
        self.country_code = country_code

    @staticmethod
    def from_stream(stream: typing.BinaryIO) -> typing.Optional["LocationRow"]:
        [id] = struct.unpack("I", stream.read(4))
        (latitude, longitude) = struct.unpack("dd", stream.read(8 * 2))
        strings = []
        for i in range(4):
            [length] = struct.unpack("H", stream.read(2))
            strings.append(stream.read(length).decode("ASCII"))

        return LocationRow(id, latitude, longitude, *strings)


def get_locations(path: str) -> typing.Generator[LocationRow, None, None]:
    with open(path, "rb") as f:
        for chunk_stream in _chunkify(f, 1024):
            [item_count] = struct.unpack("H", chunk_stream.read(2))
            if item_count == 0:
                break

            for i in range(item_count):
                row = LocationRow.from_stream(chunk_stream)
                if not row:
                    break
                yield row


# endregion
