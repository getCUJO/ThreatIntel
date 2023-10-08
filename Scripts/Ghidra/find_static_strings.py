#Find statically allocated string structures in Go binaries.
# type stringStruct struct {
#     str unsafe.Pointer
#     len int
# }
#@author padorka@cujoai
#@category goscripts
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.data import PointerDataType
from ghidra.program.model.data import IntegerDataType
from ghidra.program.model.data import LongDataType


image_base = currentProgram.getImageBase()
max_offset = currentProgram.getMaxAddress()
pointer_size = currentProgram.getDefaultPointerSize()
ptr = getInt if pointer_size == 4 else getLong

print "Image Base: 0x%x, Max offset: 0x%x" % (image_base.getOffset(), max_offset.getOffset())

#Look for strings with printable characters only to eliminate FPs.
def isPrintable(s, l):
    maybe_str = ''.join(getByte(s+i) for i in range(l))
    try:
        maybe_str.encode('utf8')
        return True
    except Exception:
        return False

def string_rename(ptr):
    for block in getMemoryBlocks():
        if block.name not in [".data", ".rodata"]:
            continue
        start = block.getStart()
        end = block.getEnd()
        while start <= end:
            string_address_pointer = start
            length_address = start.add(ptr)
            start = start.add(ptr)
            try:
                length = ptr(length_address)
                #Set the possible length to eliminate FPs.
                if length not in range(1,100):
                    continue
                string_address = currentProgram.getAddressFactory().getAddress(hex(ptr(string_address_pointer)).rstrip("L"))
                if string_address < image_base or string_address >= max_offset:
                    continue
                if not isPrintable (string_address, length):
                    continue
                #Create pointer to string.
                createData(string_address_pointer, PointerDataType.dataType)
                if getDataAt(length_address) is not None:
                    data_type = getDataAt(length_address).getDataType()
                    #Remove undefined data to be able to create int.
                    #Keep an eye on other predefined data types.
                    if data_type.getName() in ["undefined4", "undefined8"]:
                        removeData(getDataAt(length_address))
                #Create int at length.
                createData(length_address, IntegerDataType.dataType)
                #Create string.
                createAsciiString(string_address, length)
            except:
                continue

pointer = currentProgram.getDefaultPointerSize()

print "pointer: %d" % pointer

string_rename(pointer)
