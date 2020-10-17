# partition table in MBR starts in byte 446
from hashlib import sha256
import sys

if len(sys.argv) < 2:
    print "Missing mode: -m for MBR, -g for GPT"
    exit()

# assigning correct checksum based on mode (MBR or GPT)
mode = sys.argv[1]
if mode == "-m":
    checksum = "a8a0e1dd8799459e6288b918d16b6efe2ef68809c7084f2dc968ec967d4574f3"
elif mode == "-g":
    checksum = "5bf5860dfda9dd8cd13eb6d001c6667c43be34424bbf60bc62a722479c0bfb14"
else:
    print "Mode not supported, try \"-m\" for MBR, or \"-g\" for GPT"
    exit()

# opening file and reading it to isoFile
with open('mbr_dump.iso', 'r') as f:
    isoFile = f.read()

# checking integrity of .iso file
isoHash = sha256(isoFile).hexdigest()
if isoHash != checksum:
    print ".iso hash does not match hash provided, exiting..."
    exit(-1)

# entering .iso hex contents into a list
hex_list = ["{:02x}".format(ord(c)) for c in isoFile]

print hex_list
