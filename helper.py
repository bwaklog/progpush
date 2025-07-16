class Bytes:
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
