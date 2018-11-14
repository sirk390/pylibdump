from attr import dataclass
from builtins import str, int
import struct
from enum import Enum
from coff_parse import Coff


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
    for i in range(nbsymbols):
        addr, = struct.unpack_from(">l", bindata, pos)
        addrs.append(addr)
        pos += 4
    symbols_names = bindata[pos:].split(b"\x00")[:-1]
    return [(a, s.decode()) for (a, s) in zip(addrs, symbols_names)]




def read_lib_file(fname):
    with open(fname, "rb") as fin:
        if fin.read(GLOBAL_HEADER_LEN) != b"!<arch>\n":
            raise Exception("file is missing the global header")

        pos = GLOBAL_HEADER_LEN
        
        headers = []
        symbols = {}
        while True:
            #offset = fin.tell()
            header = fin.read(HEADER_LEN)
            if len(header) == 0:
                break
            if len(header) < HEADER_LEN:
                raise Exception("file header too short")
            pos += len(header)
            header = Header.from_bindata(header, pos)
            
            if header.type == HeaderType.GNU_SYMBOLS:
                bindata = fin.read(header.size)
                #print (read_gnu_symbols(bindata))
                symbols.update(dict(read_gnu_symbols(bindata)))
                #print ("    ", bindata)
                #print ("    ", read_gnu_symbols(bindata))
                #for filename in bindata.split(b"\x00"):
                #    print ("   ", filename)

            elif header.type == HeaderType.GNU:
                bindata = fin.read(header.size)
                #for dat in bindata.split(b"\x00"):
                #    print ("   ", dat) # remove trailing '/'

            elif header.type == HeaderType.GNU_TABLE:
                bindata = fin.read(header.size)
                '''for filename in bindata.split(b"\x00"):
                    print ("   ", filename[:-1]) # remove trailing '/'''
            hpos = pos - HEADER_LEN
            bindata = fin.read(header.size)
            coff = Coff.from_bindata(bindata)
            yield coff
            pos = align2(pos + header.size)
            fin.seek(pos)

        #print (len(headers))


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