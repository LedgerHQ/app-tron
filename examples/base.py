import struct


def parse_bip32_path(path):
    if len(path) == 0:
        return ""
    result = ""
    elements = path.split('/')
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack(">I", int(element[0])).hex()
        else:
            result = result + struct.pack(">I",
                                          0x80000000 | int(element[0])).hex()
    return result


def parse_bip32_path_to_bytes(path):
    if len(path) == 0:
        return b""
    result = b""
    elements = path.split('/')
    for pathElement in elements:
        element = pathElement.split('\'')
        if len(element) == 1:
            result = result + struct.pack(">I", int(element[0]))
        else:
            result = result + struct.pack(">I", 0x80000000 | int(element[0]))
    return result


def apduMessage(INS, P1, P2, PATH, MESSAGE):
    hexString = ""
    if PATH:
        hexString = "E0{:02x}{:02x}{:02x}{:02x}{:02x}{}".format(
            INS, P1, P2, (len(PATH) + len(MESSAGE)) // 2 + 1,
            len(PATH) // 4 // 2, PATH + MESSAGE)
    else:
        hexString = "E0{:02x}{:02x}{:02x}{:02x}{}".format(
            INS, P1, P2,
            len(MESSAGE) // 2, MESSAGE)
    return bytearray.fromhex(hexString)
