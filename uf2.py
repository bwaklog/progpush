from enum import Enum
from io import BufferedReader
import helper


class Boards(Enum):
    """
    Board family ID's part of the UF2 Header
    """

    rp2040 = 0xE48BFF56


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
            f"[FAMILY {board}] block {helper.Bytes.little_ed(self.block_num)}: flash addr: {helper.Bytes.little_ed_str(self.address)} | [FLAG] {helper.Bytes.little_ed_str(self.flags)}"
        )

        pass


def handle_uf2(file: BufferedReader) -> None:
    content = file.read()
    for i in range(0, len(content), 512):
        block_bytes = content[i : i + 512]

        block = Uf2Block(block_bytes, Boards.rp2040)
        _ = block
    pass
