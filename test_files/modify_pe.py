# import lief
# import random
# import struct
# import argparse
# import os

# class PEModifier:
#     """
#     A class to hold a PE file and apply your modification functions.
#     """
#     def __init__(self, file_path: str):
#         """
#         Loads the PE file bytes into self.bytez.
#         """
#         if not os.path.exists(file_path):
#             raise FileNotFoundError(f"Input file not found: {file_path}")
#         with open(file_path, 'rb') as f:
#             self.bytez = f.read()
#         print(f"Loaded '{file_path}' ({len(self.bytez)} bytes)")

#     def save(self, output_path: str):
#         """
#         Saves the modified bytes to a new file.
#         """
#         with open(output_path, 'wb') as f:
#             f.write(self.bytez)
#         print(f"Successfully saved modified file to '{output_path}'")

#     # --- (HELPER FUNCTIONS) ---
    
#     # --- (HELPER FUNCTIONS) ---
    
#     def __binary_to_bytez(self, binary: lief.PE.Binary) -> bytes:
#         """
#         Rebuilds the LIEF binary object back into bytes.
#         (FIXED: Using modern Builder API correctly)
#         """
#         # 1. Instantiate the builder WITH the binary
#         builder = lief.PE.Builder(binary)
        
#         # 2. Call build() with NO arguments
#         builder.build()
        
#         # 3. Get the result
#         return bytes(builder.get_build())

#     def __random_length(self) -> int:
#         """
#         Returns a sensible random length for new data.
#         """
#         return random.randint(512, 2048)
#     # --- Your `section_add` function (FIXED) ---
#     def section_add(self, seed=None):
#         random.seed(seed)
#         # FIXED: Use modern lief.parse()
#         binary = lief.parse(self.bytez) 
#         if binary is None or not isinstance(binary, lief.PE.Binary):
#             raise ValueError("LIEF could not parse the file as a PE binary.")
        
#         new_section = lief.PE.Section(
#             "".join(chr(random.randrange(ord('.'), ord('z'))) for _ in range(6)))

#         # fill with random content
#         upper = random.randrange(256)
#         L = self.__random_length() 
#         new_section.content = [random.randint(0, upper) for _ in range(L)]

#         new_section.virtual_address = max(
#             [s.virtual_address + s.size for s in binary.sections])

#         # Define the modern characteristics
#         text_chars = (
#             lief.PE.Section.CHARACTERISTICS.CNT_CODE |
#             lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE |
#             lief.PE.Section.CHARACTERISTICS.MEM_READ
#         )
#         data_chars = (
#             lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA |
#             lief.PE.Section.CHARACTERISTICS.MEM_READ |
#             lief.PE.Section.CHARACTERISTICS.MEM_WRITE
#         )
#         bss_chars = (
#             lief.PE.Section.CHARACTERISTICS.CNT_UNINITIALIZED_DATA |
#             lief.PE.Section.CHARACTERISTICS.MEM_READ |
#             lief.PE.Section.CHARACTERISTICS.MEM_WRITE
#         )
        
#         # Set the characteristics directly on the section object
#         new_section.characteristics = random.choice([text_chars, data_chars, bss_chars])

#         # Add the section (with only one argument)
#         binary.add_section(new_section)

#         self.bytez = self.__binary_to_bytez(binary) 
#         print(f"Action: Added new section named '{new_section.name}'")
#         return self.bytez

#     # --- Your `section_append` function (FIXED) ---
#     def section_append(self, section_name: str = None, seed=None):
#         """
#         Appends to a section.
#         If section_name is provided, appends to that section.
#         If not, appends to a random, safe section (.text, .rdata, .data).
#         """
#         random.seed(seed)
#         # FIXED: Use modern lief.parse()
#         binary = lief.parse(self.bytez) 
#         if binary is None or not isinstance(binary, lief.PE.Binary):
#             raise ValueError("LIEF could not parse the file as a PE binary.")
            
#         targeted_section = None

#         if section_name:
#             # --- 1. User specified a section ---
#             print(f"Attempting to find specified section: '{section_name}'")
#             targeted_section = binary.get_section(section_name)
#             if not targeted_section:
#                 raise ValueError(f"Error: Section '{section_name}' not found in the file.")
#         else:
#             # --- 2. User did NOT specify a section ---
#             print("No section specified. Finding a random, safe section...")
#             # Find common, safe-to-append sections
#             safe_sections = [s for s in binary.sections if s.name.startswith(('.text', '.rdata', '.data'))]
            
#             if not safe_sections:
#                 # Fallback if no safe sections are found
#                 print("Warning: No .text, .rdata, or .data sections found. Appending to a random section.")
#                 targeted_section = random.choice(binary.sections)
#             else:
#                 targeted_section = random.choice(safe_sections)

#         L = self.__random_length()
#         available_size = targeted_section.size - len(targeted_section.content)
        
#         print(f"Targeted section: '{targeted_section.name}' (Available size: {available_size} bytes)")

#         if L > available_size:
#             print(f"  Warning: Random length {L} is larger than available size {available_size}. Truncating.")
#             L = available_size
            
#         if L <= 0:
#             print("  Error: No available space in this section to append data.")
#             return self.bytez

#         upper = random.randrange(256)
#         targeted_section.content = targeted_section.content + \
#             [random.randint(0, upper) for _ in range(L)]

#         self.bytez = self.__binary_to_bytez(binary)
#         print(f"Action: Appended {L} random bytes to section '{targeted_section.name}'")
#         return self.bytez


# # --- This part runs the script from your command line ---
# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(
#         description="Modify PE files by adding or appending sections.",
#         formatter_class=argparse.RawTextHelpFormatter
#     )
    
#     parser.add_argument("input_file", 
#                         help="The path to the input PE file (e.g., whois64.exe).")
#     parser.add_argument("output_file", 
#                         help="The path to save the modified PE file.")
#     parser.add_argument("action", 
#                         choices=['add', 'append'], 
#                         help="The action to perform: \n"
#                              "  'add'    - Add a new, random section.\n"
#                              "  'append' - Append data to an existing section.")
#     parser.add_argument("-s", "--section", 
#                         dest="section_name", 
#                         default=None,
#                         help="(For 'append' action only) The specific section to append to.\n"
#                              "If not provided, appends to a random safe section (.text, .rdata, .data).")

#     args = parser.parse_args()

#     # --- Main execution logic ---
#     try:
#         # 1. Load the file
#         modifier = PEModifier(args.input_file)

#         # 2. Perform the action
#         if args.action == 'add':
#             modifier.section_add()
        
#         elif args.action == 'append':
#             if args.section_name and args.action != 'append':
#                 print(f"Warning: --section argument '{args.section_name}' is ignored for 'add' action.")
#             modifier.section_append(section_name=args.section_name)

#         # 3. Save the result
#         modifier.save(args.output_file)

#     except (FileNotFoundError, ValueError) as e:
#         print(f"\n--- An Error Occurred ---")
#         print(f"{e}")
#     except Exception as e:
#         print(f"\n--- An Unexpected Error Occurred ---")
#         print(f"{e}")





import lief
import random
import sys
import io
from typing import Optional
import tempfile
import os


class PEModifier:
    def __init__(self, file_path: str):
        # Read the original file bytes
        with open(file_path, 'rb') as f:
            self.bytez = bytearray(f.read())
    
        # Store the file path for reference
        self.file_path = file_path
        
        print(f"[*] Loaded PE file: {file_path} ({len(self.bytez)} bytes)")
    
    
    def _parse_binary(self) -> lief.PE.Binary:
        bytes_io = io.BytesIO(bytes(self.bytez))
        binary = lief.PE.parse(bytes_io)

        return binary
    
    
    def _binary_to_bytez(self, binary: lief.PE.Binary) -> bytearray:

        temp_fd, temp_path = tempfile.mkstemp(suffix='.exe')
        
        try:
            os.close(temp_fd)
            binary.write(temp_path)

            with open(temp_path, 'rb') as f:
                rebuilt_bytes = f.read()
            
            return bytearray(rebuilt_bytes)
        finally:
            # Clean up temp file
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    
    def _random_length(self, min_size: int = 100, max_size: int = 2048) -> int:
        return random.randint(min_size, max_size)
    
    
    def _generate_section_name(self, name: Optional[str] = None) -> str:
        if name is None:
            # Valid characters for section names 
            chars = 'abcdefghijklmnopqrstuvwxyz0123456789_'
            name_len = random.randint(5, 7)
            name = '.' + ''.join(random.choice(chars) for _ in range(name_len))
        return name
    
    
    def add_section(self, seed: Optional[int] = None, name: Optional[str] = None) -> bytearray:

        if seed is not None:
            random.seed(seed)
        
        print("Adding new section...")
        
        # Parse the PE binary
        binary = self._parse_binary()
        
        # Create a new section with random name
        section_name = self._generate_section_name(name)
        new_section = lief.PE.Section(section_name)
        
        print(f"Section name: {section_name}")
        
        # Generate random content for the section
        content_length = self._random_length()
        # Random byte values (0-255)
        random_content = [random.randint(0, 255) for _ in range(content_length)]
        new_section.content = random_content
        
        print(f"Content size: {content_length} bytes")
        
        # Calculate virtual address (place after all existing sections)
        # Each section has virtual_address + size
        if binary.sections:
            last_section = max(binary.sections, 
                             key=lambda s: s.virtual_address + s.virtual_size)
            new_virtual_address = last_section.virtual_address + last_section.virtual_size

        
        new_section.virtual_address = new_virtual_address
        print(f"    Virtual address: 0x{new_virtual_address:08x}")
        
        # CNT_INITIALIZED_DATA = 0x00000040
        # MEM_READ = 0x40000000
        # MEM_WRITE = 0x80000000
        data_characteristics = 0x40000000 | 0x80000000 | 0x00000040
        
        new_section.characteristics = data_characteristics
        print(f"Characteristics: CNT_INITIALIZED_DATA | MEM_READ | MEM_WRITE")
        
        # Add the section to the binary
        binary.add_section(new_section)
        
        # Convert back to bytes
        self.bytez = self._binary_to_bytez(binary)
        
        print(f"added section '{section_name}'")
        return self.bytez
    
    
    def pad_section(self, section_name: Optional[str] = None, 
                   seed: Optional[int] = None) -> bytearray:

        if seed is not None:
            random.seed(seed)
        
        print("Padding section...")
        
        # Parse the PE binary
        binary = self._parse_binary()
        
        # Determine which section to pad
        target_section = None
        
        if section_name:

            print(f"for section: {section_name}")
            target_section = binary.get_section(section_name)
            
            if not target_section:
                raise ValueError(f"Section: {section_name} not found")
        else:

            # Safe sections: .text (code), .data (data), .rdata (read-only data)
            safe_section_names = ['.text', '.data', '.rdata']
            
            # Find all safe sections that exist in this binary
            safe_sections = [s for s in binary.sections 
                           if any(s.name.startswith(name) for name in safe_section_names)]
            
            if not safe_sections:
                print(" No standard sections found, using random section")
                safe_sections = list(binary.sections)
            
            if not safe_sections:
                raise ValueError("No sections available to pad")
            
            target_section = random.choice(safe_sections)
            print(f"Randomly selected section: {target_section.name}")
        
        print(f"Target section: {target_section.name}")
        
        # Calculate slack space (available space for padding)
        # size = allocated size in file
        # len(content) = actual bytes used
        current_content_size = len(target_section.content)
        allocated_size = target_section.size
        slack_space = allocated_size - current_content_size
        
        print(f"Allocated size: {allocated_size} bytes")
        print(f"Current content: {current_content_size} bytes")
        print(f"Slack space: {slack_space} bytes")
        
        if slack_space <= 0:
            print("No slack space available in this section")
            return self.bytez
        
        # Determine how much to pad (don't exceed slack space)
        desired_pad_length = self._random_length()
        actual_pad_length = min(desired_pad_length, slack_space)
        
        print(f"Padding with: {actual_pad_length} bytes")
        
        # Generate random padding bytes
        padding = [random.randint(0, 255) for _ in range(actual_pad_length)]
        
        existing_content = list(target_section.content)

        # Append to existing content
        target_section.content = existing_content + padding
        
        # Convert back to bytes
        self.bytez = self._binary_to_bytez(binary)
        
        print(f"Successfully padded section '{target_section.name}'")
        return self.bytez
    
    
    def save(self, output_path: str):
        with open(output_path, 'wb') as f:
            f.write(self.bytez)
        
        print(f"Saved modified PE to: {output_path} ({len(self.bytez)} bytes)")


# Example usage
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("python modify_pe.py <input_pe_file> <output_pe_file>")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    
    try:
        # Create modifier instance
        modifier = PEModifier(input_file)
        
        # # Perform modifications
        # modifier.add_section(seed=42)  
        # modifier.pad_section(seed=42) 

        # Perform modifications
        # modifier.add_section(seed=40) 
        # modifier.pad_section(seed=40) 
        for i in range(50):
            modifier.add_section()
            modifier.pad_section()
            
        

        # Save the result
        modifier.save(output_file)
        
        print("\n[✓] Modification complete!")
        
    except Exception as e:
        print(f"\n[✗] Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)