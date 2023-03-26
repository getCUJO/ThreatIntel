#Find dynamically allocated string structures in Go binaries.
# type stringStruct struct {
#     str unsafe.Pointer
#     len int
# }
#Different instructions per architecture. Multiple solutions are possible.
#Future ToDo: add newly discovered instruction sequences.
#@author padorka@cujoai
#@category goscripts
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.lang import OperandType

#x86
#LEA REG, [STRING_ADDRESS]
#MOV [ESP + ..], REG
#MOV [ESP + ..], STRING_SIZE

def x86(ins):
    op_type = ins.getOperandType(1)
    reg = ins.getRegister(0)
    #Check first instruction: LEA REG, [STRING_ADDRESS]
    if not (ins.getMnemonicString() == "LEA" and reg is not None and OperandType.isAddress(op_type)):
        return None

    ins_next = getInstructionAfter(ins)

    #Check second instruction: MOV [ESP + ..], REG (where REG is the same as in previous instruction)
    if not (ins_next.getMnemonicString() == "MOV" and ins_next.getRegister(1) == reg and ins_next.getOpObjects(0)[0].toString() == "ESP"):
        return None

    ins_next2 = getInstructionAfter(ins_next)
    op_type = ins_next2.getOperandType(1)

    #Check third instruction: MOV [ESP + ..], STRING_SIZE
    if not (ins_next2.getMnemonicString() == "MOV" and ins_next2.getOpObjects(0)[0].toString() == "ESP" and OperandType.isScalar(op_type)):
        return None

    address = ins.getPrimaryReference(1).getToAddress()
    length = ins_next2.getOpObjects(1)[0].getValue()

    return address, length

#x86_64
#LEA REG, [STRING_ADDRESS]
#MOV [RSP + ..], REG
#MOV [RSP + ..], STRING_SIZE

def x86_64_stack(ins):
    op_type = ins.getOperandType(1)
    reg = ins.getRegister(0)
    #Check first instruction: LEA REG, [STRING_ADDRESS]
    if not (ins.getMnemonicString() == "LEA" and reg is not None and OperandType.isAddress(op_type)):
        return None

    ins_next = getInstructionAfter(ins)

    #Check second instruction: MOV [RSP + ..], REG (where REG is the same as in previous instruction)
    if not (ins_next.getMnemonicString() == "MOV" and ins_next.getRegister(1) == reg and ins_next.getOpObjects(0)[0].toString() == "RSP"):
        return None

    ins_next2 = getInstructionAfter(ins_next)
    op_type = ins_next2.getOperandType(1)

    #Check third instruction: MOV [RSP + ..], STRING_SIZE
    if not (ins_next2.getMnemonicString() == "MOV" and ins_next2.getOpObjects(0)[0].toString() == "RSP" and OperandType.isScalar(op_type)):
        return None

    address = ins.getPrimaryReference(1).getToAddress()
    length = ins_next2.getOpObjects(1)[0].getValue()

    return address, length


#LEA REG1, [STRING_ADDRESS]
#MOV REG2, STRING_SIZE
def x86_64_reg(ins):
    op_type = ins.getOperandType(1)
    reg = ins.getRegister(0)
    #Check first instruction: LEA REG1, [STRING_ADDRESS]
    if not (ins.getMnemonicString() == "LEA" and reg is not None and OperandType.isAddress(op_type)):
        return None

    ins_next = getInstructionAfter(ins)
    op_type = ins_next.getOperandType(1)

    #Check second instruction: MOV REG2, STRING_SIZE (where REG2 is not the same as REG1)
    if not (ins_next.getMnemonicString() == "MOV" and ins_next.getRegister(1) != reg and OperandType.isScalar(op_type)):
        return None

    address = ins.getPrimaryReference(1).getToAddress()
    length = ins_next.getOpObjects(1)[0].getValue()

    return address, length

#ARM, 32-bit
#LDR REG, [STRING_ADDRESS_POINTER]
#STR REG, [SP, ..]
#MOV REG, STRING_SIZE
#STR REG, [SP, ..]

def arm(ins):
    op_type = ins.getOperandType(1)
    #Check first instruction: LDR REG, [STRING_ADDRESS_POINTER]
    if not (ins.getMnemonicString() == "ldr" and ins.getRegister(0) is not None and OperandType.isAddress(op_type) and OperandType.isScalar(op_type)):
        return None

    reg = ins.getRegister(0)
    ins_next = getInstructionAfter(ins)

    #Check second instruction: STR REG, [SP + ..] (where REG is the same as in previous instruction)
    if not (ins_next.getMnemonicString() == "str" and ins_next.getRegister(0) == reg  and ins_next.getOpObjects(1)[0].toString() == "sp"):
        return None

    ins_next2 = getInstructionAfter(ins_next)
    op_type = ins_next2.getOperandType(1)

    #Check third instruction: MOV REG, STRING_SIZE
    if not (ins_next2.getMnemonicString() == "mov" and ins_next2.getRegister(0) is not None and OperandType.isScalar(op_type)):
        return None

    reg = ins_next2.getRegister(0)
    ins_next3 = getInstructionAfter(ins_next2)


    #Check fourth instruction: STR REG, [SP + ..] (where REG is the same as in previous instruction)
    if not (ins_next3.getMnemonicString() == "str" and ins_next3.getRegister(0) == reg and ins_next3.getOpObjects(1)[0].toString() == "sp"):
        return None

    #print "ins: %s" % ins
    address_pointer = getInt(ins.getPrimaryReference(1).getToAddress())
    address = currentProgram.getAddressFactory().getAddress(hex(address_pointer))
    length = ins_next2.getOpObjects(1)[0].getValue()

    return address, length


#ARM, 64-bit - version 1
#ADRP REG, [STRING_ADDRESS_START]
#ADD REG, REG, INT
#STR REG, [SP, ..]
#ORR REG, REG, STRING_SIZE
#STR REG, [SP, ..]

#ARM, 64-bit - version 2
#ADRP REG, [STRING_ADDRESS_START]
#ADD REG, REG, INT
#STR REG, [SP, ..]
#MOV REG, STRING_SIZE
#STR REG, [SP, ..]

def arm64(ins):
    op_type = ins.getOperandType(1)
    reg = ins.getRegister(0)

    #Check first instruction: ADRP REG, [STRING_ADDRESS_START]
    if not (ins.getMnemonicString() == "adrp" and reg is not None and OperandType.isScalar(op_type)):
        return None

    ins_next = getInstructionAfter(ins)
    op_type = ins_next.getOperandType(2)

    #Check second instruction: ADD REG, REG, INT (where REG is the same as in previous instruction)
    if not (ins_next.getMnemonicString() == "add" and ins_next.getRegister(0) == reg and OperandType.isScalar(op_type)):
        return None

    ins_next2 = getInstructionAfter(ins_next)

    #Check third instruction: STR REG, [SP + ..] (where REG is the same as in previous instruction)
    if not (ins_next2.getMnemonicString() == "str" and ins_next2.getRegister(0) == reg and ins_next2.getOpObjects(1)[0].toString() == "sp"):
        return None

    ins_next3 = getInstructionAfter(ins_next2)
    reg = ins_next3.getRegister(0)

    #Check fourth instruction: ORR REG, REG, STRING_SIZE
    if ins_next3.getMnemonicString() == "orr" and reg is not None and OperandType.isScalar(ins_next3.getOperandType(2)) is True:
        length = ins_next3.getOpObjects(2)[0].getValue()
    #Check fourth instruction: MOV REG, STRING_SIZE
    elif ins_next3.getMnemonicString() == "mov" and reg is not None and OperandType.isScalar(ins_next3.getOperandType(1)) is True:
        length = ins_next3.getOpObjects(1)[0].getValue()
    else:
        return None

    ins_next4 = getInstructionAfter(ins_next3)

    #Check fifth instruction: STR REG, [SP + ..] (where REG is the same as in previous instruction)
    if not (ins_next4.getMnemonicString() == "str" and ins_next4.getRegister(0) == reg and ins_next4.getOpObjects(1)[0].toString() == "sp"):
        return None

    #print "ins: %s" % ins
    address_int = int(ins.getOpObjects(1)[0].getValue() + ins_next.getOpObjects(2)[0].getValue())
    address = currentProgram.getAddressFactory().getAddress(hex(address_int))

    return address, length


def string_rename(l):
    for block in getMemoryBlocks():
        if block.getName() != ".text":
            continue
        start = block.getStart()
        ins = getInstructionAt(start)
        while ins:
            for f in l:
                result = f(ins)
                if result is not None:
                    address, length = result
                    #print "address %s length %s" % (address, length)
                    try:
                        #Create string.
                        createAsciiString(address, length)
                        print "SUCCESS at %s" % address
                        break
                    except ghidra.program.model.util.CodeUnitInsertionException as e:
                        print "conflict at address %s: %s" % (address, e)
                        pass
                    except Exception as e:
                        #print "ERROR at address %s: %s" % (ins.getAddress(), e)
                        pass


            ins = getInstructionAfter(ins)

def main():
    #Check program architecture.
    language_id = currentProgram.getLanguageID()
    print "lang: %s" % language_id
    pointer_size = currentProgram.getDefaultPointerSize()

    if language_id.toString().startswith("ARM"):
        print "32 BIT ARM"
        l = [arm]
    elif language_id.toString().startswith("AARCH64"):
        print "64 BIT ARM"
        l = [arm64]
    elif language_id.toString().startswith("x86") and pointer_size == 4:
        print "32 BIT x86"
        l = [x86]
    elif language_id.toString().startswith("x86") and pointer_size == 8:
        print "64 BIT x86"
        l = [x86_64_reg, x86_64_stack]
    else:
        print "ERROR: unknown arch."
        return

    string_rename(l)

main()
