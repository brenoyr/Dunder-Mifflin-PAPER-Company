from hashlib import sha256
import sys
import csv

if len(sys.argv) < 2:
    print "Missing mode: -m for MBR, -g for GPT"
    exit()

# assigning correct checksum and file directory based on mode (MBR or GPT)
mode = sys.argv[1]
if mode == "-m":
    FILE_DIR = 'mbr_dump.iso'
    PARTITION_TYPES_LIST = 'mbr_partition_types.csv'
    CHECKSUM = "a8a0e1dd8799459e6288b918d16b6efe2ef68809c7084f2dc968ec967d4574f3"
elif mode == "-g":
    FILE_DIR = 'gpt_dump.iso'
    PARTITION_TYPES_LIST = 'gpt_partition_guids.csv'
    CHECKSUM = "5bf5860dfda9dd8cd13eb6d001c6667c43be34424bbf60bc62a722479c0bfb14"
else:
    print "Mode not supported, try \"-m\" for MBR, or \"-g\" for GPT"
    exit()

# opening file and reading it to isoFile
with open(FILE_DIR, 'r') as f:
    isoFile = f.read()

# checking integrity of .iso file
isoHash = sha256(isoFile).hexdigest()
if isoHash != CHECKSUM:
    print ".iso hash does not match hash provided, exiting..."
    exit(-1)

# putting partition types into a dictionary for easy access later
partitionTypes = {}
with open(PARTITION_TYPES_LIST, mode='r') as csvfile:
    entries = csv.reader(csvfile, delimiter=',')
    for row in entries:
        # hex -> partition type
        partitionTypes[row[0]] = row[1]

# entering .iso hex contents into a list
hex_list = ["{:02x}".format(ord(c)) for c in isoFile]

# "The MBR contains boot code, a partition table, and a signature value"
# partition table in MBR starts in byte 446
cur = 446

# 1. Number of partitions
partitionNumber = 0

# getting number of partitions based on system indicator
while hex_list[cur + 4] != "00":
    partitionNumber += 1
    cur = cur + 16

# reset current pointer
cur = 446

print "Number of partitions: {}\n".format(partitionNumber)

for i in range(partitionNumber):
    print "Partition {} Details:".format(i + 1)\
    
    # get partition type
    curPartitionType = partitionTypes[str(hex_list[cur + 4]).upper()]
    print "Partition Type: \"{}\"".format(curPartitionType)

    # get partition address (LBA)
    hexString = str(hex_list[cur+11]+hex_list[cur+10]+hex_list[cur+9]+hex_list[cur+8])
    lbaDecAddress = int(hexString, 16)
    print "Partition Address (LBA): {}".format(lbaDecAddress)

    # get the size of the partition (in sectors)
    hexString = str(hex_list[cur+15]+hex_list[cur+14]+hex_list[cur+13]+hex_list[cur+12])
    sizeInSectors = int(hexString, 16)
    print "Number of Sectors in Partition: {}\n".format(sizeInSectors)

    cur += 16
