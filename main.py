from attr import dataclass
from builtins import str, int
import struct
from enum import Enum
import os
from typing import List
from capstone import Cs, CS_MODE_64, CS_ARCH_X86, CS_MODE_32
from collections import deque
from ar_parse import read_lib_file


def main(fname):
    """ Basic python version of the tools:
        > objdump -d         (linux)
        > dumpbin /disasm    (MSVC)
        
        It parses the AR and COFF structures, but uses the "capstone" library to disassemble
    """ 
    for coff in read_lib_file(fname): 
        if coff:
            syms = deque(coff.symbols)
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.skipdata = True
            for i in md.disasm(coff.sections[0].data, 0x000):
                if syms and i.address >= syms[0].value:
                    if syms[0].type == 32:
                        print (syms[0].name.decode(errors="ignore"))
                    syms.popleft()
                print("    0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))


if __name__ == '__main__':
    fname = r"D:\TestObjFiles\lib\libcrypto.a"

    main(fname)
    