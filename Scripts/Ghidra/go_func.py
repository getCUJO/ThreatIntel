#Recover function names in stripped Go binaries.
#@author padorka@cujoai
#@category goscripts
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.symbol.SourceType import *

#Find the .gopclntab section
def getGopclntab():
    for block in getMemoryBlocks():
        if block.getName() == ".gopclntab":
            start = block.getStart()
            end = block.getEnd()
            print "%s [start: 0x%x, end: 0x%x]" % (block.getName(), start.getOffset(), end.getOffset())
            return start
    print "No .gopclntab section found."
    return None

def renameFunc(start):
    ptr_size_address = start.add(7)
    ptr_size = getByte(ptr_size_address)
    section_size_address = start.add(8)
    section_size = getInt(section_size_address)
    p = start.add(8 + ptr_size)
    for i in range (section_size):
        func_offset = getInt(p)
        func_address = currentProgram.getAddressFactory().getAddress(hex(func_offset))
        p = p.add(ptr_size)
        name_offset = getInt(p)
        p = p.add(ptr_size)
        name_pointer = start.add(name_offset + ptr_size)
        name_address = start.add(getInt(name_pointer))
        func_name = getDataAt(name_address)

        #Try to define function name string.
        if func_name is None:
            try:
                func_name = createAsciiString(name_address)
            except:
                print "ERROR: No name" 
                continue

        #print "address:0x%x, data:%s" %(func_offset, func_name.getValue())
        
        func = getFunctionAt(func_address)
        if func is not None:
            func_name_old = func.getName()
            func.setName(func_name.getValue().replace(" ", ""), USER_DEFINED)
            print "Function %s renamed as %s" % (func_name_old, func_name.getValue())
        else:
            func = createFunction(func_address, func_name.getValue())
            print "New function created: %s" % func_name

start = getGopclntab()    
if start is not None:
    renameFunc(start)