# Functions for printing ELF file information
from elftools.elf.elffile import ELFFile

def print_general_info(elf):
    print("----- General ELF Information -----")
    header = elf.header
    print(f"File Type: {header['e_type']}")
    print(f"Machine: {header['e_machine']}")
    print(f"Entry Point: {hex(header['e_entry'])}")

def print_important_info(elf):
    print("----- Important ELF Information -----")
    header = elf.header
    for key in ['e_type', 'e_machine', 'e_version', 'e_entry']:
        print(f"{key}: {header.get(key)}")
    print("\n----- Program Headers (Segments) -----")
    for segment in elf.iter_segments():
        h = segment.header
        print(f"\nSegment Type: {h['p_type']}")
        print(f"  Virtual Address: {hex(h['p_vaddr'])}")
        print(f"  File Size: {h['p_filesz']} bytes")
        print(f"  Memory Size: {h['p_memsz']} bytes")
        print(f"  Flags: {h['p_flags']}")

def print_detailed_info(elf):
    print("----- Detailed ELF Header -----")
    for key, value in elf.header.items():
        print(f"{key}: {value}")
    print("\n----- Program Headers (Segments) -----")
    for segment in elf.iter_segments():
        h = segment.header
        print(f"\nSegment Type: {h['p_type']}")
        print(f"  Virtual Address: {hex(h['p_vaddr'])}")
        print(f"  Physical Address: {hex(h['p_paddr'])}")
        print(f"  File Offset: {h['p_offset']}")
        print(f"  File Size: {h['p_filesz']} bytes")
        print(f"  Memory Size: {h['p_memsz']} bytes")
        print(f"  Flags: {h['p_flags']}")
        print(f"  Alignment: {h['p_align']}")
    print("\n----- Section Headers -----")
    for section in elf.iter_sections():
        h = section.header
        print(f"\nSection: {section.name}")
        print(f"  Type: {h['sh_type']}")
        print(f"  Address: {hex(h['sh_addr'])}")
        print(f"  Offset: {h['sh_offset']}")
        print(f"  Size: {h['sh_size']} bytes")
        print(f"  Flags: {h['sh_flags']}")
        print(f"  Link: {h['sh_link']}")
        print(f"  Info: {h['sh_info']}")
        print(f"  Address Alignment: {h['sh_addralign']}")
        print(f"  Entry Size: {h['sh_entsize']}")
