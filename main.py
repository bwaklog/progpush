import argparse
from contextlib import ContextDecorator
from enum import Enum
from typing import Literal


class Boards(Enum):
    rp2040 = 0xE48BFF56


class Helper:
    @staticmethod
    def val_hex(content: bytes, order: int) -> str:
        if order == 1:
            return hex(int.from_bytes(content, byteorder="little"))
        elif order == 2:
            return hex(int.from_bytes(content, byteorder="big"))

        return ""

    @staticmethod
    def val(content: bytes, order: int) -> int:
        if order == 1:
            return int.from_bytes(content, byteorder="little")
        elif order == 2:
            return int.from_bytes(content, byteorder="big")

        return -1

    @staticmethod
    def little_ed_str(content: bytes) -> str:
        return hex(int.from_bytes(content, byteorder="little"))

    @staticmethod
    def big_ed_str(content: bytes) -> str:
        return hex(int.from_bytes(content, byteorder="big"))

    @staticmethod
    def little_ed(content: bytes) -> int:
        return int.from_bytes(content, byteorder="little")

    @staticmethod
    def big_ed(content: bytes) -> int:
        return int.from_bytes(content, byteorder="big")


class Uf2Block:
    """
    0	    4	First magic number, 0x0A324655 ("UF2\n")
    4	    4	Second magic number, 0x9E5D5157
    8	    4	Flags
    12	    4	Address in flash where the data should be written
    16	    4	Number of bytes used in data (often 256)
    20	    4	Sequential block number; starts at 0
    24	    4	Total number of blocks in file
    28	    4	File size or board family ID or zero
    32	    476	Data, padded with zeros
    508	    4	Final magic number, 0x0AB16F30
    """

    def __init__(self, block: bytes, board: Boards) -> None:
        self.magic = block[0:4]
        self.second_magic = block[4:8]
        self.flags = block[8:12]
        self.address = block[12:16]
        self.nbytes = block[16:20]
        self.block_num = block[20:24]
        self.blocks = block[24:28]
        self.family = block[28:32]
        self.data = block[32:508]
        self.final_magic = block[508:512]

        assert int.from_bytes(self.magic, byteorder="little") == 0x0A324655
        assert int.from_bytes(self.second_magic, byteorder="little") == 0x9E5D5157
        assert int.from_bytes(self.final_magic, byteorder="little") == 0x0AB16F30

        print(
            f"[FAMILY {board}] block {Helper.little_ed(self.block_num)}: flash addr: {Helper.little_ed_str(self.address)} | [FLAG] {Helper.little_ed_str(self.flags)}"
        )

        pass


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
        assert Helper.big_ed(self.magic) == 0x7F454C46

        self.bit = content[4]
        assert self.bit == 1

        self.byte_order = content[5]
        self.header_ver = content[6]
        self.os_abi = content[7]
        self.type = Helper.val(content[16:18], self.byte_order)

        self.instruction_set = content[18:20]
        assert Helper.val(self.instruction_set, self.bit) == 0x28

        self.elf_ver = Helper.val(content[20:24], self.bit)
        assert self.elf_ver == 1

        self.program_entry = Helper.val(content[24:28], self.bit)
        self.program_header_offset = Helper.val(content[28:32], self.bit)
        self.section_header_offset = Helper.val(content[32:36], self.bit)
        self.elf_header_size = Helper.val(content[40:42], self.bit)

        self.program_header_entry_size = Helper.val(content[42:44], self.bit)
        self.program_header_entries = Helper.val(content[44:46], self.bit)

        print(f"MAGIC: {Helper.big_ed_str(self.magic)} & {self.bit} bits")
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


class ProgramHeader:
    def __init__(self, content: bytes, order: int) -> None:
        self.type = Helper.val(content[0:4], order)
        self.data_offset = Helper.val(content[4:8], order)
        self.virt_addr = Helper.val(content[8:12], order)
        self.phy_addr = Helper.val(content[12:16], order)
        self.seg_size = Helper.val(content[16:20], order)
        self.seg_memory_size = Helper.val(content[20:24], order)
        self.flags = Helper.val(content[24:28], order)
        self.alignment = Helper.val(content[28:32], order)
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
            "data offset": hex(self.data_offset),
            "setment size": hex(self.seg_size),
            "flags": hex(self.flags),
        }

        return f"{display}"


class ProgramData:
    def __init__(self, pheader: ProgramHeader, content: bytes) -> None:
        self.data = content[
            pheader.data_offset : pheader.data_offset + pheader.seg_size
        ]
        pass


def main():
    parser = argparse.ArgumentParser(
        description="strip out machine instructions from a uf2 file"
    )

    parser.add_argument("-t", "--type", required=True, help="file format")
    parser.add_argument("-f", "--file", required=True, help="The uf2 file path")
    parser.add_argument("-b", "--board", required=False, help="board", default="pico")

    args = parser.parse_args()

    print(f"Hello from file parse! {args.file}")

    file = open(args.file, "rb")
    file.seek(0)

    dump = open("elf.dump", "wb")
    dump.seek(0)

    if args.type == "uf2":
        content = file.read()
        for i in range(0, len(content), 512):
            block_bytes = content[i : i + 512]

            block = Uf2Block(block_bytes, Boards.rp2040)
            _ = block

    elif args.type == "elf":
        content = file.read()
        header = ElfHeader(content)

        program_header_table = content[
            header.program_header_offset : header.program_header_offset
            + header.program_header_entry_size * header.program_header_entries
        ]

        dump.write(b"LOADPROG\r\n")

        pheaders = []

        for i in range(
            header.program_header_offset,
            len(program_header_table) + header.program_header_offset,
            header.program_header_entry_size,
        ):
            program_header_content = content[i : i + header.program_header_entry_size]
            pheader = ProgramHeader(program_header_content, header.bit)
            if pheader.type == 0x1:
                pheaders.append(pheader)

        size = sum(map(lambda x: x.seg_size, pheaders))
        dump.write(f"{size}\r\n".encode())

        for pheader in pheaders:
            print(pheader)
            program_data = ProgramData(pheader, content)
            dump.write(program_data.data)
            # print(list(map(int, program_data.data)))
            dump.write(b"\r\n")

        dump.write(b"ENDTASK")

        dump.flush()
        dump.close()


if __name__ == "__main__":
    main()
