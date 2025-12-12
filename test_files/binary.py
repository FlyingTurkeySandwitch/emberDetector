import struct
import sys

def read_exe_structure(filename):
    """Read and print the structure of a PE (Portable Executable) file"""
    
    try:
        with open(filename, 'rb') as f:
            # Read DOS header
            dos_header = f.read(64)
            if dos_header[:2] != b'MZ':
                print("Not a valid PE file (missing MZ signature)")
                return
            
            print("=" * 60)
            print("DOS HEADER")
            print("=" * 60)
            print(f"Magic Number: {dos_header[:2].decode('ascii')}")
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            print(f"PE Header Offset: 0x{pe_offset:X}")
            
            # Read PE signature
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                print("Invalid PE signature")
                return
            
            print("\n" + "=" * 60)
            print("PE SIGNATURE")
            print("=" * 60)
            print(f"Signature: {pe_sig[:2].decode('ascii')}")
            
            # Read COFF header
            coff_header = f.read(20)
            machine, num_sections, timestamp, sym_table, num_symbols, opt_header_size, characteristics = \
                struct.unpack('<HHIIIHH', coff_header)
            
            print("\n" + "=" * 60)
            print("COFF HEADER")
            print("=" * 60)
            print(f"Machine Type: 0x{machine:X}")
            print(f"Number of Sections: {num_sections}")
            print(f"Optional Header Size: {opt_header_size}")
            print(f"Characteristics: 0x{characteristics:X}")
            
            # Read Optional Header 
            opt_header_start = f.tell()
            magic = struct.unpack('<H', f.read(2))[0]
            
            print("\n" + "=" * 60)
            print("OPTIONAL HEADER")
            print("=" * 60)
            print(f"Magic: 0x{magic:X} ({'PE32' if magic == 0x10b else 'PE32+' if magic == 0x20b else 'Unknown'})")
            
            # Skip to section headers
            f.seek(opt_header_start + opt_header_size)
            
            # Read section headers
            print("\n" + "=" * 60)
            print("SECTION HEADERS")
            print("=" * 60)
            
            for i in range(num_sections):
                section_header = f.read(40)
                name = section_header[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size, virtual_addr, raw_size, raw_addr = struct.unpack('<IIII', section_header[8:24])
                characteristics = struct.unpack('<I', section_header[36:40])[0]
                
                print(f"\nSection {i+1}: {name}")
                print(f"  Virtual Size: 0x{virtual_size:X}")
                print(f"  Virtual Address: 0x{virtual_addr:X}")
                print(f"  Raw Size: 0x{raw_size:X}")
                print(f"  Raw Address: 0x{raw_addr:X}")
                print(f"  Characteristics: 0x{characteristics:X}")
            
            print("\n" + "=" * 60)
            
    except FileNotFoundError:
        print(f"Error: File '{filename}' not found")
    except Exception as e:
        print(f"Error reading file: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python binary.py <path_to_exe_file>")
        sys.exit(1)
    
    exe_file = sys.argv[1]
    read_exe_structure(exe_file)