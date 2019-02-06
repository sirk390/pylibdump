from attr import dataclass
from builtins import str, int
import struct
from enum import Enum
import os
from typing import List
from capstone import Cs, CS_MODE_64, CS_ARCH_X86, CS_MODE_32
from collections import deque
from ar_parse import read_lib_file
import re

def hex_with_spaces(bytestr):
    return " ".join("%02X" % s for s in bytestr)


def format_hex_value(prevvalue):
    result = prevvalue[2:].upper() + "h"
    if not result[0].isdigit():
        return "0" + result
    return result

def format_asm(asmstr):
    """ format ASM to be like dumpbin (for testing)"""
    asmstr = asmstr.replace(", ", ",")
    asmstr = asmstr.replace(" + ", "+")
    asmstr = asmstr.replace(" - ", "-")
    asmstr = re.sub(r'0x[\da-f]+', lambda x: format_hex_value(x.group()), asmstr) # reformat 0xHH to HHh
    return asmstr
    

def main(fname):
    """ Basic python version of the tools:
    
            - "objdump -d" (linux)
            - "dumpbin /disasm" (MSVC)
        
        It parses the AR and COFF structures, but uses the "capstone" library to disassemble
    """ 
    for coff in read_lib_file(fname): 
        if coff:
            syms = deque(coff.symbols)
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.skipdata = True
            # iterate through "CsInsn"
            for i in md.disasm(coff.sections[0].data, 0x000):
                while syms and i.address >= syms[0].value:
                    if syms[0].type == 32 and syms[0].section_number == 1:
                        print (syms[0].name.decode(errors="ignore") + ":")
                    syms.popleft()
                instr_bytes = i.bytes
                remain_bytes = b""
                if len(instr_bytes) >= 6:
                    instr_bytes, remain_bytes = instr_bytes[:6], instr_bytes[6:]
                if not i.op_str:
                    asm_part = i.mnemonic
                else:
                    asm_part = "%-12s%s" % (i.mnemonic, format_asm(i.op_str))
                print("  %08X: %-19s" %(i.address, hex_with_spaces(instr_bytes)) + asm_part)
                if remain_bytes:
                    print("            %s" %(hex_with_spaces(remain_bytes)))
                    


if __name__ == '__main__':
    fname = r"D:\TestObjFiles\lib\x86\MSVC\2017_14.15.26726\msvcrt.lib"

    main(fname)
    