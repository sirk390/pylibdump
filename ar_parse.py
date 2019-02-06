"""
See spec of MSVC library format at (section 7):
    https://courses.cs.washington.edu/courses/cse378/03wi/lectures/LinkerFiles/coff.pdf
    
"""

from attr import dataclass
from builtins import str, int
import struct
from enum import Enum
from coff_parse import Coff
import binascii


GLOBAL_HEADER_LEN = 8
HEADER_LEN = 60

def align2(num):
    """ Returns a 2-aligned offset """
    if num % 2 == 0:
        return num
    else:
        return num+1


HeaderType = Enum("HeaderType", "BSD GNU GNU_TABLE GNU_SYMBOLS NORMAL")



@dataclass
class Header():
    name: str
    type: str
    size: str
    offset: str

    @staticmethod
    def from_bindata(bindata, offset):
        name, timestamp, uid, gid, mode, size, magic = struct.unpack("16s 12s 6s 6s 8s 10s 2s", bindata)
        if magic != b"\x60\x0a":
            raise Exception("file header magic doesn't match")
        if name.startswith(b"#1/"):
            type = HeaderType.BSD
        elif name.startswith(b"//"):
            type = HeaderType.GNU_TABLE
        elif name.strip() == b"/":
            type = HeaderType.GNU_SYMBOLS
        elif name.startswith(b"/"):
            type =  HeaderType.GNU
        else:
            type =  HeaderType.NORMAL
        size = int(size)
        name = name.rstrip()
        #name = name.rstrip(b'/')
        return (Header(name, type, size, offset))


def read_gnu_symbols(bindata, pos=0):
    nbsymbols, = struct.unpack_from(">l", bindata, pos)
    pos += 4
    addrs = []
    vtest, = struct.unpack_from("<l", bindata, pos)
    for i in range(nbsymbols):
        addr, = struct.unpack_from(">l", bindata, pos)
        #print ("ok", i, addr)
        addrs.append(addr)
        pos += 4
    symbols_names = bindata[pos:].split(b"\x00")[:-1]
    return [(a, s.decode()) for (a, s) in zip(addrs, symbols_names)]

def read_second_symbols(bindata, pos=0):
    """ Not finished implementing 
        - ADDR_INDEX to ADDR and
        - NAME TO ADDR_INDEX
    """
    nbmembers, = struct.unpack_from("l", bindata, pos)
    pos += 4
    offsets = []
    indexes = []
    for i in range(nbmembers):
        offset, = struct.unpack_from("l", bindata, pos)
        offsets.append(offset)
        pos += 4
    nbsymbols, = struct.unpack_from("l", bindata, pos)
    pos += 4
    for i in range(nbsymbols):
        index, = struct.unpack_from("H", bindata, pos)
        indexes.append(index)
        pos += 2
    symbols_names = bindata[pos:].split(b"\x00")[:-1]
    return [offsets, indexes, symbols_names]


def read_lib_file(fname):
    with open(fname, "rb") as fin:
        if fin.read(GLOBAL_HEADER_LEN) != b"!<arch>\n":
            raise Exception("file is missing the global header")

        pos = GLOBAL_HEADER_LEN
        
        headers = []
        symbols = {}
        first_symbols = True
        while True:
            #offset = fin.tell()
            header = fin.read(HEADER_LEN)
            if len(header) == 0:
                break
            if len(header) < HEADER_LEN:
                raise Exception("file header too short")
            pos += len(header)
            header = Header.from_bindata(header, pos)
            bindata = fin.read(header.size)
            #print (header, header.type == HeaderType.GNU_SYMBOLS and first_symbols)
            if header.type == HeaderType.GNU_SYMBOLS and first_symbols:
                res = read_gnu_symbols(bindata)
                symbols.update(res)
                print (res)
                first_symbols = False
            elif header.type == HeaderType.GNU_SYMBOLS and not first_symbols:
                res = read_second_symbols(bindata) # todo
                print ("-----------------------------------------")
                print (res)
            elif header.type == HeaderType.GNU_TABLE:
                assert len(bindata) == header.size
                '''for filename in bindata.split(b"\x00"):
                    print ("   ", filename[:-1]) # remove trailing '/'''
            elif header.type == HeaderType.GNU:
                hpos = pos - HEADER_LEN
                if len(bindata) >= 20:
                    coff = Coff.from_bindata(bindata)
                    yield coff
            pos = align2(pos + header.size)
            fin.seek(pos)


"""
    Notes:
        * The first GNU_SYMBOLS table maps from ADDR to NAME
        * The second GNU_SYMBOLS table maps from
            - ADDR_INDEX to ADDR and
            - NAME TO ADDR_INDEX

            18 04 2010
            18 04 20 18

            18420 10
            10 05 2010
            12 05 2010
"""