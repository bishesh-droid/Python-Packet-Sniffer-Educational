
import os

def is_root():
    """
    Checks if the script is running with root privileges.
    """
    return os.geteuid() == 0

def hexdump(x):
    """
    Returns a hexdump of the given data.
    """
    x = bytes(x)
    len_x = len(x)
    i = 0
    res = []
    while i < len_x:
        res.append("%04x  " % i + " ".join(["%02x" % b for b in x[i:i+16]]).ljust(48) + " ".join([chr(b) if 32 <= b < 127 else "." for b in x[i:i+16]]))
        i += 16
    return "\n".join(res)
