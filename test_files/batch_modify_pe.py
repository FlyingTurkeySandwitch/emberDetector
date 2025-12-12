"""
Batch PE File Generator and Analyzer
====================================
Generates multiple modified PE files and analyzes their structure.

Usage: python batch_generator.py <input_exe> <batch_number> [--count 10]
"""

import os
import sys
import random
import argparse
from pathlib import Path
from typing import Optional
import io

# Import the modify_pe module (using relative import for package structure)
try:
    from .modify_pe import PEModifier
except ImportError:
    # Fallback to absolute import if not running as a module
    try:
        from modify_pe import PEModifier
    except ImportError:
        print("[!] Error: Cannot import modify_pe.py. Make sure it's in the same directory.")
        print("[!] Or run with: python -m test_files.batch_modify_pe")
        sys.exit(1)

# Import binary analysis (we'll embed the function here)
import struct


def read_exe_structure_to_string(filename: str) -> str:
    """
    Read and return the structure of a PE file as a string.
    Modified version of binary.py that returns output instead of printing.
    """
    output_lines = []
    
    try:
        with open(filename, 'rb') as f:
            # Read DOS header
            dos_header = f.read(64)
            if dos_header[:2] != b'MZ':
                return "Not a valid PE file (missing MZ signature)"
            
            output_lines.append("=" * 60)
            output_lines.append("DOS HEADER")
            output_lines.append("=" * 60)
            output_lines.append(f"Magic Number: {dos_header[:2].decode('ascii')}")
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            output_lines.append(f"PE Header Offset: 0x{pe_offset:X}")
            
            # Read PE signature
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                return "Invalid PE signature"
            
            output_lines.append("\n" + "=" * 60)
            output_lines.append("PE SIGNATURE")
            output_lines.append("=" * 60)
            output_lines.append(f"Signature: {pe_sig[:2].decode('ascii')}")
            
            # Read COFF header
            coff_header = f.read(20)
            machine, num_sections, timestamp, sym_table, num_symbols, opt_header_size, characteristics = \
                struct.unpack('<HHIIIHH', coff_header)
            
            output_lines.append("\n" + "=" * 60)
            output_lines.append("COFF HEADER")
            output_lines.append("=" * 60)
            output_lines.append(f"Machine Type: 0x{machine:X}")
            output_lines.append(f"Number of Sections: {num_sections}")
            output_lines.append(f"Optional Header Size: {opt_header_size}")
            output_lines.append(f"Characteristics: 0x{characteristics:X}")
            
            # Read Optional Header
            opt_header_start = f.tell()
            magic = struct.unpack('<H', f.read(2))[0]
            
            output_lines.append("\n" + "=" * 60)
            output_lines.append("OPTIONAL HEADER")
            output_lines.append("=" * 60)
            output_lines.append(f"Magic: 0x{magic:X} ({'PE32' if magic == 0x10b else 'PE32+' if magic == 0x20b else 'Unknown'})")
            
            # Skip to section headers
            f.seek(opt_header_start + opt_header_size)
            
            # Read section headers
            output_lines.append("\n" + "=" * 60)
            output_lines.append("SECTION HEADERS")
            output_lines.append("=" * 60)
            
            for i in range(num_sections):
                section_header = f.read(40)
                name = section_header[:8].rstrip(b'\x00').decode('ascii', errors='ignore')
                virtual_size, virtual_addr, raw_size, raw_addr = struct.unpack('<IIII', section_header[8:24])
                characteristics = struct.unpack('<I', section_header[36:40])[0]
                
                output_lines.append(f"\nSection {i+1}: {name}")
                output_lines.append(f"  Virtual Size: 0x{virtual_size:X}")
                output_lines.append(f"  Virtual Address: 0x{virtual_addr:X}")
                output_lines.append(f"  Raw Size: 0x{raw_size:X}")
                output_lines.append(f"  Raw Address: 0x{raw_addr:X}")
                output_lines.append(f"  Characteristics: 0x{characteristics:X}")
            
            output_lines.append("\n" + "=" * 60)
            
    except FileNotFoundError:
        return f"Error: File '{filename}' not found"
    except Exception as e:
        return f"Error reading file: {e}"
    
    return "\n".join(output_lines)


class BatchPEGenerator:
    """
    Generates batches of modified PE files and their binary analysis.
    """
    
    def __init__(self, input_exe: str, batch_number: int, base_output_dir: str = "."):
        """
        Initialize the batch generator.
        
        Args:
            input_exe: Path to the input .exe file
            batch_number: Batch number for organizing outputs
            base_output_dir: Base directory for outputs (default: current directory)
        """
        self.input_exe = input_exe
        self.batch_number = batch_number
        self.base_output_dir = Path(base_output_dir)
        
        # Create output directories
        self.samples_dir = self.base_output_dir / "generated_samples" / f"generated_sample_batch{batch_number}"
        self.binary_dir = self.base_output_dir / "generated_samples" / f"sample_binary_batch{batch_number}"
        
        self.samples_dir.mkdir(parents=True, exist_ok=True)
        self.binary_dir.mkdir(parents=True, exist_ok=True)
        
        print(f"[*] Batch Generator initialized")
        print(f"    Input file: {input_exe}")
        print(f"    Batch number: {batch_number}")
        print(f"    Samples directory: {self.samples_dir}")
        print(f"    Binary analysis directory: {self.binary_dir}")
    
    
    def generate_sample(self, sample_number: int, section_name: Optional[str] = None) -> tuple[str, str]:
        """
        Generate a single modified PE sample and its binary analysis.
        
        Args:
            sample_number: Sample number (1-indexed)
            section_name: Optional custom section name for the added section
            
        Returns:
            Tuple of (modified_exe_path, binary_analysis_path)
        """
        print(f"\n{'='*70}")
        print(f"[*] Generating Sample {sample_number}/10 for Batch {self.batch_number}")
        print(f"{'='*70}")
        
        # Generate unique seed for this sample
        seed = self.batch_number * 1000 + sample_number
        
        # Define output paths
        modified_exe_name = f"sample_{self.batch_number}_{sample_number}.exe"
        modified_exe_path = self.samples_dir / modified_exe_name
        
        binary_output_name = f"sample_{self.batch_number}_{sample_number}_structure.txt"
        binary_output_path = self.binary_dir / binary_output_name
        
        try:
            # Step 1: Modify the PE file
            print(f"\n[Step 1] Modifying PE file with seed={seed}")
            modifier = PEModifier(self.input_exe)
            
            # Add section with custom name if provided
            if section_name:
                print(f"    Using custom section name: {section_name}")
                # We need to modify the add_section method to accept custom names
                # For now, we'll use the random name generation
            
            modifier.add_section(seed=seed)
            modifier.pad_section(seed=seed)
            
            # Save modified file
            modifier.save(str(modified_exe_path))
            print(f"[✓] Modified PE saved: {modified_exe_path}")
            
            # Step 2: Analyze the modified file
            print(f"\n[Step 2] Analyzing binary structure")
            binary_analysis = read_exe_structure_to_string(str(modified_exe_path))
            
            # Save binary analysis to file
            with open(binary_output_path, 'w') as f:
                f.write(f"Binary Structure Analysis\n")
                f.write(f"File: {modified_exe_name}\n")
                f.write(f"Batch: {self.batch_number}\n")
                f.write(f"Sample: {sample_number}\n")
                f.write(f"Seed: {seed}\n")
                f.write(f"{'='*60}\n\n")
                f.write(binary_analysis)
            
            print(f"[✓] Binary analysis saved: {binary_output_path}")
            
            return str(modified_exe_path), str(binary_output_path)
            
        except Exception as e:
            print(f"\n[✗] Error generating sample {sample_number}: {e}")
            import traceback
            traceback.print_exc()
            raise
    
    
    def generate_batch(self, count: int = 10, section_names: Optional[list[str]] = None):
        """
        Generate a complete batch of modified PE files.
        
        Args:
            count: Number of samples to generate (default: 10)
            section_names: Optional list of custom section names (one per sample)
        """
        print(f"\n{'#'*70}")
        print(f"# Starting Batch {self.batch_number} Generation")
        print(f"# Total samples to generate: {count}")
        print(f"{'#'*70}\n")
        
        successful_samples = []
        failed_samples = []
        
        for i in range(1, count + 1):
            try:
                section_name = section_names[i-1] if section_names and i-1 < len(section_names) else None
                exe_path, binary_path = self.generate_sample(i, section_name)
                successful_samples.append((i, exe_path, binary_path))
                print(f"\n[✓] Sample {i} completed successfully")
            except Exception as e:
                failed_samples.append((i, str(e)))
                print(f"\n[✗] Sample {i} failed: {e}")
                continue
        
        # Print summary
        print(f"\n\n{'#'*70}")
        print(f"# Batch {self.batch_number} Generation Complete")
        print(f"{'#'*70}")
        print(f"\n[Summary]")
        print(f"  Total samples: {count}")
        print(f"  Successful: {len(successful_samples)}")
        print(f"  Failed: {len(failed_samples)}")
        
        if successful_samples:
            print(f"\n[Successful Samples]")
            for sample_num, exe_path, binary_path in successful_samples:
                print(f"  Sample {sample_num}:")
                print(f"    EXE: {exe_path}")
                print(f"    Analysis: {binary_path}")
        
        if failed_samples:
            print(f"\n[Failed Samples]")
            for sample_num, error in failed_samples:
                print(f"  Sample {sample_num}: {error}")
        
        print(f"\n[Output Directories]")
        print(f"  Modified EXEs: {self.samples_dir}")
        print(f"  Binary Analyses: {self.binary_dir}")
        print(f"\n{'#'*70}\n")


def main():
    """Main entry point for the batch generator."""
    parser = argparse.ArgumentParser(
        description="Generate batches of modified PE files and analyze their structure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python batch_generator.py input.exe 1
  python batch_generator.py input.exe 2 --count 10
  python batch_generator.py input.exe 3 --count 5 --output ./my_outputs
        """
    )
    
    parser.add_argument('input_exe', help='Path to the input .exe file')
    parser.add_argument('batch_number', type=int, help='Batch number for organizing outputs')
    parser.add_argument('--count', type=int, default=10, help='Number of samples to generate (default: 10)')
    parser.add_argument('--output', default='.', help='Base output directory (default: current directory)')
    parser.add_argument('--section-names', nargs='+', help='Optional custom section names (space-separated)')
    
    args = parser.parse_args()
    
    # Validate input file exists
    if not os.path.exists(args.input_exe):
        print(f"[✗] Error: Input file '{args.input_exe}' not found")
        sys.exit(1)
    
    # Create generator and run
    try:
        generator = BatchPEGenerator(
            input_exe=args.input_exe,
            batch_number=args.batch_number,
            base_output_dir=args.output
        )
        
        generator.generate_batch(
            count=args.count,
            section_names=args.section_names
        )
        
        print("[✓] Batch generation completed successfully!")
        
    except Exception as e:
        print(f"\n[✗] Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()