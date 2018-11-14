Basic python version of the tools:

    - "objdump -d" (linux)
    - "dumpbin /disasm" (MSVC)

It parses the AR and COFF structures, but uses the "capstone" library to disassemble.
