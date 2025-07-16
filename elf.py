import helper
from enum import Enum


class ElfHeader:
    """
    Position (32 bit)	Position (64 bit)	Value
    0-3	                0-3	                Magic number - 0x7F, then 'ELF' in ASCII
    4	                4	                1 = 32 bit, 2 = 64 bit
    5	                5	                1 = little endian, 2 = big endian
    6	                6	                ELF header version
    7	                7	                OS ABI - usually 0 for System V
    8-15	            8-15	            Unused/padding
    16-17	            16-17	            Type (1 = relocatable, 2 = executable, 3 = shared, 4 = core)
    18-19	            18-19	            Instruction set - see table below
    20-23	            20-23	            ELF Version (currently 1)
    24-27	            24-31	            Program entry offset
    28-31	            32-39	            Program header table offset
    32-35	            40-47	            Section header table offset
    36-39	            48-51	            Flags - architecture dependent; see note below
    40-41	            52-53	            ELF Header size
    42-43	            54-55	            Size of an entry in the program header table
    44-45	            56-57	            Number of entries in the program header table
    46-47	            58-59	            Size of an entry in the section header table
    48-49	            60-61	            Number of entries in the section header table
    50-51	            62-63	            Section index to the section header string table
    """

    instr_set = {
        0x00: "No specific",
        0x02: "Sparc",
        0x03: "x86",
        0x08: "MIPS",
        0x14: "PowerPC",
        0x28: "ARM",
        0x2A: "SuperH",
        0x32: "IA-64",
        0x3E: "x64-64",
        0xB7: "AArch64",
        0xF3: "RISC-V",
    }

    def __init__(self, content: bytes) -> None:
        self.magic = content[0:4]
        assert helper.Bytes.big_ed(self.magic) == 0x7F454C46

        self.bit = content[4]
        assert self.bit == 1

        self.byte_order = content[5]
        self.header_ver = content[6]
        self.os_abi = content[7]
        self.type = helper.Bytes.val(content[16:18], self.byte_order)

        self.instruction_set = content[18:20]
        assert helper.Bytes.val(self.instruction_set, self.bit) == 0x28

        self.elf_ver = helper.Bytes.val(content[20:24], self.bit)
        assert self.elf_ver == 1

        self.program_entry = helper.Bytes.val(content[24:28], self.bit)
        self.program_header_offset = helper.Bytes.val(content[28:32], self.bit)
        self.section_header_offset = helper.Bytes.val(content[32:36], self.bit)
        self.elf_header_size = helper.Bytes.val(content[40:42], self.bit)

        self.program_header_entry_size = helper.Bytes.val(content[42:44], self.bit)
        self.program_header_entries = helper.Bytes.val(content[44:46], self.bit)

        print(f"MAGIC: {helper.Bytes.big_ed_str(self.magic)} & {self.bit} bits")
        print(f"byte order: {self.byte_order}")
        print(f"program entry : {hex(self.program_entry)}")
        print(f"program header table offset: {hex(self.program_header_offset)}")
        print(
            f"size of an entry in program header table {hex(self.program_header_entry_size)}"
        )
        print(
            f"number of entries in program header table {hex(self.program_header_entries)}"
        )

        pass


class ProgramHeaderType(Enum):
    Null = 0x0
    Load = 0x1
    Dynamic = 0x2
    Interp = 0x3
    Note = 0x4


class ProgramHeader:
    def __init__(self, content: bytes, order: int) -> None:
        self.type = helper.Bytes.val(content[0:4], order)
        self.data_offset = helper.Bytes.val(content[4:8], order)
        self.virt_addr = helper.Bytes.val(content[8:12], order)
        self.phy_addr = helper.Bytes.val(content[12:16], order)
        self.seg_size = helper.Bytes.val(content[16:20], order)
        self.seg_memory_size = helper.Bytes.val(content[20:24], order)
        self.flags = helper.Bytes.val(content[24:28], order)
        self.alignment = helper.Bytes.val(content[28:32], order)
        return

    def __str__(self) -> str:
        display = {
            "type": {
                0x0: "NULL",
                0x1: "LOAD",
                0x2: "DYNAMIC",
                0x3: "INTERP",
                0x4: "NOTE",
            }.get(self.type),
            # "type": ProgramHeaderType(self.type),
            "data offset": hex(self.data_offset),
            "setment size": hex(self.seg_size),
            "flags": hex(self.flags),
        }

        return f"{display}"


class ProgramHeaderTable:
    def __init__(self, content: bytes, header: ElfHeader) -> None:
        self.table = [
            ProgramHeader(content[i : i + header.program_header_entry_size], header.bit)
            for i in range(
                header.program_header_offset,
                header.program_header_entry_size * header.program_header_entries
                + header.program_header_offset,
                header.program_header_entry_size,
            )
        ]
        pass


class ProgramData:
    @staticmethod
    def get(header: ProgramHeader, content: bytes) -> bytes:
        return content[header.data_offset : header.data_offset + header.seg_size]

    # def __init__(self, pheader: ProgramHeader, content: bytes) -> None:
    #     self.data = content[
    #         pheader.data_offset : pheader.data_offset + pheader.seg_size
    #     ]
    #     pass


class ElfFile:
    def __init__(self, file: str) -> None:
        self.__file = open(file, "rb")
        self.__file.seek(0)
        self.__content = self.__file.read()
        self.header = ElfHeader(self.__content)

        self.segment_table = ProgramHeaderTable(self.__content, self.header)

    def get_segment_data(self, header: ProgramHeader) -> bytes:
        return ProgramData.get(header, self.__content)

    def get_segment_size(self) -> int:
        return sum(
            map(
                lambda x: x.seg_size,
                filter(lambda x: x.type == 0x1, self.segment_table.table),
            )
        )
