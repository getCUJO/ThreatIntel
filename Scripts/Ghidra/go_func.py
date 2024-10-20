#Recover function names in stripped Go binaries.
#@author padorka@cujoai
#@category goscripts
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.symbol.SourceType import *

pclntab_magic = [
    '\xfb\xff\xff\xff\x00\x00',
    '\xfa\xff\xff\xff\x00\x00',
    '\xf0\xff\xff\xff\x00\x00',
    '\xf1\xff\xff\xff\x00\x00',
]

#Find pclntab structure in Windows PE files
def findPclntabPE():
    section = getSection('.rdata')
    if section is None:
        return None
    start, end = section

    for magic in pclntab_magic:
        p = start
        while True:
            address_set = ghidra.program.model.address.AddressSet(p, end)
            matches = findBytes(address_set, magic, 1, 1)
            if not matches:
                break
            pclntab = matches[0]
            if isPclntab(pclntab):
                print "Pclntab found"
                return pclntab

            p = pclntab.add(1)

    return None

#Test if pclntab was found by checking pc quantum and pointer size values
def isPclntab(address):
    pc_quantum = getByte(address.add(6))
    pointer_size = getByte(address.add(7))
    return pc_quantum in (1, 2, 4) and pointer_size in (4, 8)

# find section by name
def getSection(section_name):
    block = getMemoryBlock(section_name)
    if block is None:
        print "No %s section found." % section_name
        return None

    start = block.getStart()
    end = block.getEnd()
    print "%s [start: 0x%x, end: 0x%x]" % (block.getName(), start.getOffset(), end.getOffset())
    return start, end

#Recover function names for Go versions 1.2 - 1.15
def renameFunc12(start):
    ptrsize = getByte(start.add(7))
    ptr = getInt if ptrsize == 4 else getLong
    nfunctab = ptr(start.add(8))
    functab = start.add(8 + ptrsize)

    p = functab
    for i in range (nfunctab):
        func_address = currentProgram.getAddressFactory().getAddress(hex(ptr(p)).rstrip("L"))
        p = p.add(ptrsize)
        name_offset = ptr(p)

        p = p.add(ptrsize)
        name_pointer = start.add(name_offset + ptrsize)
        name_address = start.add(getInt(name_pointer))
        func_name = getDataAt(name_address)

        #Try to define function name string.
        if func_name is None:
            try:
                func_name = createAsciiString(name_address)
            except:
                print "ERROR: No name"
                continue


        func = getFunctionAt(func_address)
        if func is not None:
            func_name_old = func.getName()
            func.setName(func_name.getValue().replace(" ", ""), USER_DEFINED)
            print "Function %s renamed as %s" % (func_name_old, func_name.getValue())
        else:
            func = createFunction(func_address, func_name.getValue())
            print "New function created: %s" % func_name

#Recover function names for Go versions 1.16 - 1.17
def renameFunc116(start):
    ptrsize = getByte(start.add(7))
    ptr = getInt if ptrsize == 4 else getLong

    nfunctab = ptr(start.add(8))
    offset = ptr(start.add(8 + 2*ptrsize))
    funcnametab = start.add(offset)
    offset = ptr(start.add(8 + 6*ptrsize))

    functab = start.add(offset)

    p = functab
    for i in range (nfunctab):
        func_address = currentProgram.getAddressFactory().getAddress(hex(ptr(p)).rstrip("L"))
        p = p.add(ptrsize)
        funcdata_offset = ptr(p)

        p = p.add(ptrsize)
        name_pointer = functab.add(funcdata_offset + ptrsize)
        name_address = funcnametab.add(getInt(name_pointer))
        func_name = getDataAt(name_address)

        #Try to define function name string.
        if func_name is None:
            try:
                func_name = createAsciiString(name_address)
            except:
                print "ERROR: No name"
                continue


        func = getFunctionAt(func_address)
        if func is not None:
            func_name_old = func.getName()
            func.setName(func_name.getValue().replace(" ", ""), USER_DEFINED)
            print "Function %s renamed as %s" % (func_name_old, func_name.getValue())
        else:
            func = createFunction(func_address, func_name.getValue())
            print "New function created: %s" % func_name

#Recover function names for Go versions 1.18 and above
def renameFunc118(start):
    ptrsize = getByte(start.add(7))
    ptr_f = getLong if ptrsize == 8 else getInt

    nfunctab = ptr_f(start.add(8))
    textStart = ptr_f(start.add(8 + 2*ptrsize))
    offset = ptr_f(start.add(8 + 3*ptrsize))
    funcnametab = start.add(offset)
    offset = ptr_f(start.add(8 + 7*ptrsize))

    functab = start.add(offset)

    p = functab
    functabFieldSize = 4
    for i in range (nfunctab):
        func_address = currentProgram.getAddressFactory().getAddress(hex(getInt(p)+textStart).rstrip("L"))
        p = p.add(functabFieldSize)
        funcdata_offset = getInt(p)
        p = p.add(functabFieldSize)
        name_pointer = functab.add(funcdata_offset + functabFieldSize)
        name_address = funcnametab.add(getInt(name_pointer))
        func_name = getDataAt(name_address)

        #Try to define function name string.
        if func_name is None:
            try:
                func_name = createAsciiString(name_address)
            except:
                print "ERROR: No name"
                continue


        func = getFunctionAt(func_address)
        if func is not None:
            func_name_old = func.getName()
            func.setName(func_name.getValue().replace(" ", ""), USER_DEFINED)
            print "Function %s renamed as %s" % (func_name_old, func_name.getValue())
        else:
            func = createFunction(func_address, func_name.getValue())
            print "New function created: %s" % func_name

magic_map = {
    0xfffffff0: renameFunc118,
    0xfffffff1: renameFunc118,  # go 1.20 magic; 1.18 renaming still works
    0xfffffffa: renameFunc116,
    0xfffffffb: renameFunc12,
}

def main():
    executable_format = currentProgram.getExecutableFormat()

    if executable_format == "Portable Executable (PE)":
        print "PE file found"
        start = findPclntabPE()
    elif executable_format == "Executable and Linking Format (ELF)":
        print "ELF file found"
        start, _ = getSection('.gopclntab')
    elif executable_format == "Mac OS X Mach-O":
        print "Mach-O file found"
        start, _ = getSection('__gopclntab')
    else:
        print "Unhandled file format."
        return

    magic = getInt(start) & 0xffffffff
    f = magic_map.get(magic)
    if f is None:
        print "WARNING: Unknown .gopclntab magic, assuming Go 1.2 compatibility"
        f = renameFunc12

    f(start)

main()
