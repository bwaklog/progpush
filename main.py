from os import error
import serial
import elf

import argparse
import uf2


class SerialWriter:
    def __init__(self, device, baud=115200) -> None:
        self.device = serial.Serial(device, baudrate=baud)
        pass

    def write_bytes_all(self, content: bytes) -> None:
        self.device.write(content)
        pass


def main():
    parser = argparse.ArgumentParser(
        description="strip out machine instructions from a uf2 file"
    )

    parser.add_argument("-t", "--type", required=True, help="file format")
    parser.add_argument("-f", "--file", required=True, help="The uf2 file path")
    parser.add_argument("-b", "--board", required=False, help="board", default="pico")
    parser.add_argument(
        "-l", "--load", required=False, default=False, help="Load via serial"
    )
    parser.add_argument(
        "-d", "--device", required=False, default="", help="Serial device"
    )

    args = parser.parse_args()

    if args.load and args.device == "":
        error("No serial device provided")
        return

    if args.type == "uf2":
        file = open(args.file, "rb")
        file.seek(0)

        uf2.handle_uf2(file=file)
        print("unimplmented")
        file.close()
        return

    elif args.type == "elf":
        elf_file = elf.ElfFile(args.file)
        dump = open("elf.dump", "wb")
        dump.seek(0)

        dump.write(b"LOADPROG\r\n")
        dump.write(f"{elf_file.get_segment_size()}\r\n".encode())

        for pheader in elf_file.segment_table.table:
            if pheader.type == elf.ProgramHeaderType.Load.value:
                print(pheader)
                data = elf_file.get_segment_data(pheader)
                print(data)

                dump.write(data)

                # print(hex(data.data_offset))

        dump.write(b"ENDPROG")
        dump.flush()
        dump.close()

    if args.load:
        writer = SerialWriter(args.device)

        dump = open("elf.dump", "rb")
        dump.seek(0)
        content = dump.read()

        writer.write_bytes_all(content)


if __name__ == "__main__":
    main()
