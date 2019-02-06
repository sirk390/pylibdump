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
    
            - "objdump -d" (linux)
            - "dumpbin /disasm" (MSVC)
        
        It parses the AR and COFF structures, but uses the "capstone" library to disassemble
    """ 
    for c, coff in enumerate(read_lib_file(fname)): 
        if coff:
            syms = deque(coff.symbols)
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.skipdata = True
            #print(coff.sections[0].data)
            for i in md.disasm(coff.sections[0].data, 0x000):
                if syms and i.address >= syms[0].value:
                    if syms[0].type == 32:
                        print (syms[0].name.decode(errors="ignore"))
                    syms.popleft()
                #print("    0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            #if c == 276:
                #print (coff.symbols)
            #    break
        #print ('---', coff.symbols)

if __name__ == '__main__':
    fname = r"D:\TestObjFiles\lib\libcrypto.a"
    #fname = r"D:\TestObjFiles\lib\x86\MSVC\2017_14.15.26726\msvcrt.lib"

    main(fname)
    