# Ghidra Scripts

A set of Ghidra scripts for reverse engineering.

## Installation

Copy the scripts to your ghidra_scripts directory (default: <HomeDirectory\>/ghidra_scripts). Use Script Manager to launch the scripts.

## go_func.py

Recover function names in stripped Go ELF files.

## find_static_strings.py 
Find statically allocated string structures in Go binaries. <br />
type stringStruct struct { <br />
   str unsafe.Pointer <br />
   len int <br />
}
 
## find_dynamic_strings.py 
Find dynamically allocated string structures in Go binaries. <br />
type stringStruct struct { <br />
   str unsafe.Pointer <br />
   len int <br />
 }

