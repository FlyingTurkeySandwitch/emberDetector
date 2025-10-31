import lief
import random
import struct

#===================
#code adapted from:

# Hyrum S. Anderson, Anant Kharkar, Bobby Filar, David Evans, Phil Roth, "Learning to Evade Static PE Machine Learning Malware Models via Reinforcement Learning", in ArXiv e-prints. Jan. 2018.

# @ARTICLE{anderson2018learning,
#   author={Anderson, Hyrum S and Kharkar, Anant and Filar, Bobby and Evans, David and Roth, Phil},
#   title={Learning to Evade Static PE Machine Learning Malware Models via Reinforcement Learning},
#   journal={arXiv preprint arXiv:1801.08917},
#   archivePrefix = "arXiv",
#   eprint = {1801.08917},
#   primaryClass = "cs.CR",
#   keywords = {Computer Science - Cryptography and Security},
#   year = 2018,
#   month = jan,
#   adsurl = {http://adsabs.harvard.edu/abs/2018arXiv180108917A},
# }

#===================


# Load the executable

COMMON_SECTION_NAMES = [".text", ".rdata", ".data", ".bss",
                        ".idata", ".edata"]

def section_rename(self, seed=None):
        # rename a random section
    random.seed(seed)
    binary = lief.PE.parse(self.bytez)
    targeted_section = random.choice(binary.sections)
    targeted_section.name = random.choice(COMMON_SECTION_NAMES)[:7] # current version of lief not allowing 8 chars?

    self.bytez = self.__binary_to_bytez(binary)

    return self.bytez

def section_add(self, seed=None):
    random.seed(seed)
    binary = lief.PE.parse(self.bytez)
    new_section = lief.PE.Section(
        "".join(chr(random.randrange(ord('.'), ord('z'))) for _ in range(6)))

    # fill with random content
    upper = random.randrange(256)
    L = self.__random_length()
    new_section.content = [random.randint(0, upper) for _ in range(L)]

    new_section.virtual_address = max(
        [s.virtual_address + s.size for s in binary.sections])
        # add a new empty section

    binary.add_section(new_section,
                           random.choice([
                               lief.PE.SECTION_TYPES.BSS,
                               lief.PE.SECTION_TYPES.DATA,
                               lief.PE.SECTION_TYPES.EXPORT,
                               lief.PE.SECTION_TYPES.IDATA,
                               lief.PE.SECTION_TYPES.RELOCATION,
                               lief.PE.SECTION_TYPES.RESOURCE,
                               lief.PE.SECTION_TYPES.TEXT,
                               lief.PE.SECTION_TYPES.TLS_,
                               lief.PE.SECTION_TYPES.UNKNOWN,
                           ]))

    self.bytez = self.__binary_to_bytez(binary)
    return self.bytez

def section_append(self, seed=None):
        # append to a section (changes size and entropy)
    random.seed(seed)
    binary = lief.PE.parse(self.bytez)
    targeted_section = random.choice(binary.sections)
    L = self.__random_length()
    available_size = targeted_section.size - len(targeted_section.content)
    if L > available_size:
        L = available_size

    upper = random.randrange(256)
    targeted_section.content = targeted_section.content + \
        [random.randint(0, upper) for _ in range(L)]

    self.bytez = self.__binary_to_bytez(binary)
    return self.bytez

# def section_reorder(self,param,seed=None):
#   # reorder directory of sections
#   pass

def create_new_entry(self, seed=None):
    # create a new section with jump to old entry point, and change entry point
    # DRAFT: this may have a few technical issues with it (not accounting for relocations), but is a proof of concept for functionality
    random.seed(seed)

    binary = lief.PE.parse(self.bytez)

    # get entry point
    entry_point = binary.optional_header.addressof_entrypoint

    # get name of section
    entryname = binary.section_from_rva(entry_point).name

    # create a new section
    new_section = lief.PE.Section(entryname + "".join(chr(random.randrange(
        ord('.'), ord('z'))) for _ in range(3)))  # e.g., ".text" + 3 random characters
    # push [old_entry_point]; ret
    new_section.content = [
        0x68] + list(struct.pack("<I", entry_point + 0x10000)) + [0xc3]
    new_section.virtual_address = max(
        [s.virtual_address + s.size for s in binary.sections])
    # TO DO: account for base relocation (this is just a proof of concepts)

    # add new section
    binary.add_section(new_section, lief.PE.SECTION_TYPES.TEXT)

    # redirect entry point
    binary.optional_header.addressof_entrypoint = new_section.virtual_address

    self.bytez = self.__binary_to_bytez(binary)
    return self.bytez

# def upx_pack(self, seed=None):
#     # tested with UPX 3.91
#     random.seed(seed)
#     tmpfilename = os.path.join(
#         tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

#     # dump bytez to a temporary file
#     with open(tmpfilename, 'wb') as outfile:
#         outfile.write(self.bytez)

#     options = ['--force', '--overlay=copy']
#     compression_level = random.randint(1, 9)
#     options += ['-{}'.format(compression_level)]
#     # --exact
#     # compression levels -1 to -9
#     # --overlay=copy [default]

#     # optional things:
#     # --compress-exports=0/1
#     # --compress-icons=0/1/2/3
#     # --compress-resources=0/1
#     # --strip-relocs=0/1
#     options += ['--compress-exports={}'.format(random.randint(0, 1))]
#     options += ['--compress-icons={}'.format(random.randint(0, 3))]
#     options += ['--compress-resources={}'.format(random.randint(0, 1))]
#     options += ['--strip-relocs={}'.format(random.randint(0, 1))]

#     with open(os.devnull, 'w') as DEVNULL:
#         retcode = subprocess.call(
#             ['upx'] + options + [tmpfilename, '-o', tmpfilename + '_packed'], stdout=DEVNULL, stderr=DEVNULL)

#     os.unlink(tmpfilename)

#     if retcode == 0:  # successfully packed

#         with open(tmpfilename + '_packed', 'rb') as infile:
#             self.bytez = infile.read()

#         os.unlink(tmpfilename + '_packed')

#     return self.bytez

# def upx_unpack(self, seed=None):
#     # dump bytez to a temporary file
#     tmpfilename = os.path.join(
#         tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

#     with open(tmpfilename, 'wb') as outfile:
#         outfile.write(self.bytez)

#     with open(os.devnull, 'w') as DEVNULL:
#         retcode = subprocess.call(
#             ['upx', tmpfilename, '-d', '-o', tmpfilename + '_unpacked'], stdout=DEVNULL, stderr=DEVNULL)

#     os.unlink(tmpfilename)

#     if retcode == 0:  # sucessfully unpacked
#         with open(tmpfilename + '_unpacked', 'rb') as result:
#             self.bytez = result.read()

#         os.unlink(tmpfilename + '_unpacked')

#     return self.bytez

def remove_signature(self, seed=None):
    random.seed(seed)
    binary = lief.PE.parse(self.bytez)

    if binary.has_signature:
        for i, e in enumerate(binary.data_directories):
            if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
                break
        if e.type == lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE:
            # remove signature from certificate table
            e.rva = 0
            e.size = 0
            self.bytez = self.__binary_to_bytez(binary)
            return self.bytez
    # if no signature found, self.bytez is unmodified
    return self.bytez

def remove_debug(self, seed=None):
    random.seed(seed)
    binary = lief.PE.parse(self.bytez)

    if binary.has_debug:
        for i, e in enumerate(binary.data_directories):
            if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
                break
        if e.type == lief.PE.DATA_DIRECTORY.DEBUG:
            # remove signature from certificate table
            e.rva = 0
            e.size = 0
            self.bytez = self.__binary_to_bytez(binary)
            return self.bytez
    # if no signature found, self.bytez is unmodified
    return self.bytez

def break_optional_header_checksum(self, seed=None):
    binary = lief.PE.parse(self.bytez)
    binary.optional_header.checksum = 0
    self.bytez = self.__binary_to_bytez(binary)
    return self.bytez
