from attr import dataclass
from builtins import str, int
import struct
from enum import Enum
import os
from typing import List
from capstone import Cs, CS_MODE_64, CS_ARCH_X86, CS_MODE_32
from _collections import deque


def read_string_table(bindata, pos):
    """ Read the string table inside a Coff file"""
    table_bytesize, = struct.unpack_from("<l", bindata, pos)
    string_table_end = pos + table_bytesize
    pos += 4
    strings = []
    while pos < string_table_end:
        endpos = bindata.index(b"\x00", pos)
        strings.append(bindata[pos:endpos].decode())
        pos = endpos + 1
    return strings


@dataclass
class Relocation():
    addr: str
    symbol_index: int
    relocation_type: int


@dataclass
class Symbol():
    name: str
    value: int
    section_number: int
    type: int
    storage_class: int
    aux_count: int

    @staticmethod
    def from_bindata(bindata, pos, string_table_pos):
        zeros, offset = struct.unpack_from("<ll", bindata, pos)
        name, value, section_number, type, storage_class, aux_count = struct.unpack_from("<8slhhcc", bindata, pos)
        pos += 18
        if zeros == 0:
            startstr = string_table_pos+offset
            endstr = bindata.index(b"\x00", string_table_pos+offset)
            name = bindata[startstr:endstr]
        else:
            try:
                endstr = bindata.index(b"\x00", pos, pos+8)
            except:
                endstr = pos+8
            name = bindata[pos:endstr]
        return Symbol(name, value, section_number, type, storage_class, aux_count), pos


@dataclass
class Section():
    name: int
    physical_addr: int
    virtual_addr: int
    size: int
    offset: int
    reloc_offset: int
    file_offset: int
    nb_relocs: int
    nb_linenums: int
    flags: int
    data: bytes
    relocations : List

    @staticmethod
    def from_bindata(bindata, pos):
        name, physical_addr, virtual_addr, size, offset, reloc_offset, file_offset, nb_relocs, nb_linenums, flags = struct.unpack_from("<8sllllllhhl", bindata, pos)
        pos += 40
        data = bindata[offset:offset+size]
        relocations = read_relocation_table(bindata, reloc_offset, nb_relocs)
        #print (relocations)
        assert nb_linenums == 0
        return Section(name.rstrip(b"\x00"), physical_addr, virtual_addr, size, offset, reloc_offset, file_offset, nb_relocs, nb_linenums, flags, data, relocations), pos


@dataclass
class Coff():
    version: int
    nb_section: int
    timedate: int
    symbol_table_offset: int
    nb_symbols: int
    size_opt_header: int
    flags: int
    sections : List
    symbols: List
    
    @staticmethod
    def from_bindata(bindata):
        pos = 0
        version, nb_sections, timedate, symbol_table_offset, nb_symbols, size_opt_header, flags = struct.unpack_from("<HHlllHH", bindata, pos)
        if size_opt_header != 0:
            print ("Skipped ----------------------------------------------", size_opt_header)
            return None
        pos += 20 + size_opt_header
        # TODO parse Optional Header
        sections = []
        for i in range(nb_sections):
            section, pos = Section.from_bindata(bindata, pos)
            sections.append(section)
        symbols = []
        string_table_pos = symbol_table_offset + nb_symbols * 18 # 18 = size of a symbol entry
        pos = symbol_table_offset
        
        for i in range(nb_symbols):
            symbol, pos = Symbol.from_bindata(bindata, pos, string_table_pos)
            symbols.append(symbol)
        return Coff(version, nb_sections, timedate, symbol_table_offset, nb_symbols, size_opt_header, flags, sections, symbols)


def read_relocation_table(bindata, pos, nb_entries):
    """ Read the string table inside a Coff file"""
    result = []
    for _ in range(nb_entries):
        addr, symbol_index, relocation_type= struct.unpack_from("<lls", bindata, pos)
        result.append(Relocation(addr, symbol_index, relocation_type))
        pos += 10
    return result


