#########################################################
#   Names:      Breno Yamada Riquieri                   #
#               Alexandra Duran Chicas                  #
#   Class:      CSC443 - Digital Forensics              #
#   Asgmt:      Partition Analysis                      #
#   Due Date:   10/19/2020                              #
#   Comments:   Python 2.7.17                           #
#               Ubuntu 18.04.5 LTS                      #
#########################################################

from hashlib import sha256
import sys
import csv


def mbr():
    # "The MBR contains boot code, a partition table, and a signature value"
    # partition table in MBR starts in byte 446
    cur = 446

    # 1. Number of partitions
    partitionNumber = 0

    # getting number of partitions based on system indicator
    while hex_list[cur+4] != "00":
        partitionNumber += 1
        cur += 16

    # reset current pointer
    cur = 446

    print "Number of partitions: {}\n".format(partitionNumber)

    for i in range(partitionNumber):        
        # 2. get partition type
        curPartitionType = partitionTypes[str(hex_list[cur+4]).upper()]

        # 3. get partition address (LBA)
        hexString = str(hex_list[cur+11]+hex_list[cur+10]+hex_list[cur+9]+hex_list[cur+8])
        lbaDecAddress = int(hexString, 16)

        # 4. get the size of the partition (in sectors)
        hexString = str(hex_list[cur+15]+hex_list[cur+14]+hex_list[cur+13]+hex_list[cur+12])
        sizeInSectors = int(hexString, 16)

        print "Partition {} Details:".format(i+1)
        print "Partition Type: \"{}\"".format(curPartitionType)
        print "Partition Address (LBA): {}".format(lbaDecAddress)
        print "Number of Sectors in Partition: {}\n".format(sizeInSectors)

        # point to next partition
        cur += 16

def gpt():
    # GPT part starts at byte 512 (right after MBR)
    # + 512 to get to partition entries table
    cur = 1024

    partitionNumber = 0

    # getting number of partitions based on
    # how many partition entries exist every 128 bytes
    while cur < len(hex_list) and hex_list[cur] != "00" :
        partitionNumber += 1
        cur += 128

    # reset current pointer
    cur = 1024

    print "Number of partitions: {}\n".format(partitionNumber)

    for i in range(partitionNumber):
        # partition GUID starts at cur += 16 (16 bytes)
        # we get very messy here
        # first 8 bytes are in little endian
        # last 8 bytes are in big endian
        guid = (hex_list[cur+3]+hex_list[cur+2]+hex_list[cur+1]+hex_list[cur]+"-"\
            +hex_list[cur+5]+hex_list[cur+4]+"-"\
            +hex_list[cur+7]+hex_list[cur+6]+"-"\
            +hex_list[cur+8]+hex_list[cur+9]+"-"\
            +hex_list[cur+10]+hex_list[cur+11]+hex_list[cur+12]+hex_list[cur+13]+hex_list[cur+14]+hex_list[cur+15]).upper()

        # starting LBA address starts at cur += 32 (8 bytes)
        hexString = ""
        for j in range(cur+39, cur+31, -1):
            hexString += str(hex_list[j])
        lbaStartDecAddress = int(hexString, 16)
        print "START ADDRESS"
        print hexString

        # ending LBA address starts at cur += 40 (8 bytes)
        hexString = str(hex_list[cur+47]+hex_list[cur+46]+hex_list[cur+45]+hex_list[cur+44]\
            +hex_list[cur+43]+hex_list[cur+42]+hex_list[cur+41]+hex_list[cur+40])
        lbaEndDecAddress = int(hexString, 16)
        print "END ADDRESS"
        print hexString

        # name starts at byte cur+56
        nameChar = cur+56
        name = ""
        while hex_list[nameChar] != "00":
            name += hex_list[nameChar]
            nameChar += 2
        name = name.decode("hex")

        cur += 128

        print "Partition {} Details:".format(i+1)
        print "Partition Name: {}".format(name)
        print "Partition GUID: {}".format(guid)
        print "Partition Type: {}".format(partitionTypes[guid])
        print "Partition Starting Address: {}".format(lbaStartDecAddress)
        print "Partition Ending Address: {}\n".format(lbaEndDecAddress)

def fat32():
    # get bytes per sector
    # given by bytes 11-12 (in little endian) from the FAT boot sector
    bytesPerSector = int(hex_list[12]+hex_list[11], 16)

    # get sectors per cluster
    # given by byte 13
    sectorsPerCluster = int(hex_list[13], 16)

    # get size of reserved area in sectors
    reservedAreaSize = int(hex_list[15]+hex_list[14], 16)

    # get start address of 1st FAT
    # ** reserved area is immediately followed by the 1st FAT section.
    # ** sectors start at index 0. reserved area in sectors is 32 (for example),
    # ** which means the last sector in the reserved area is the 31st.
    # ** therefore, startAddress is 32 (right where reservedAreaSize ends)
    startAddress = reservedAreaSize

    # get # of FATs
    # given by byte 16
    numOfFats = int(hex_list[16], 16)

    # get sectors per FAT
    # given by bytes 36-39 (in little endian)
    sectorsPerFAT = int(hex_list[39]+hex_list[38]+hex_list[37]+hex_list[36], 16)

    # get cluster address of root directory
    # given by bytes 44-47 (in little endian)
    clusterAddrRoot = int(hex_list[47]+hex_list[46]+hex_list[45]+hex_list[44], 16)

    # get starting sector address of the data section a.k.a. root directory
    # (size in sectors of each fat)(# of fats) + # of sectors in reserved area
    dataSectionAddr = (sectorsPerFAT * numOfFats) + reservedAreaSize

    print "Bytes/Sector: {}".format(bytesPerSector)
    print "Sectors/Cluster: {}".format(sectorsPerCluster)
    print "Size of Reserved Area in Sectors: {}".format(reservedAreaSize)
    print "Start Address of 1st FAT: {}".format(startAddress)
    print "# of FATs: {}".format(numOfFats)
    print "Sectors/FAT: {}".format(sectorsPerFAT)
    print "Cluster Address of Root Directory: {}".format(clusterAddrRoot)
    print "Starting Sector Address of the Data Section: {}".format(dataSectionAddr)

    # THE FUN STARTS HERE
    # LOOKING FOR "/Photos/homework.jpg"
    DIRECTORY = "Norway"
    FILE = "norway"

    # go to root's first entry
    cluster = (dataSectionAddr * bytesPerSector) + 32
    cur = cluster

    # this while loop goes to the next entry if name doesn't match
    # (as long as we are still in the same cluster (?))
    while cur < cluster * 2:
        if hex_list[cur] == "00":
            print "\nDirectory not found, exiting...\n"
            exit()

        # translating first 8 bytes
        fileName = hex_list[cur]+hex_list[cur+1]+hex_list[cur+2]+hex_list[cur+3]\
            +hex_list[cur+4]+hex_list[cur+5]+hex_list[cur+6]+hex_list[cur+7]

        fileName = fileName.decode("hex")

        # "is the directory name a substring of those 8 bytes?"
        if DIRECTORY.upper() not in fileName:
            cur += 32
        else:
            print "DIRECTORY BYTES IN DECIMAL: {}".format(fileName) # added
            # if it is, we found it. proceed...
            break
    
    # get cluster address of directory entry
    # given by bytes 20-21 + 26-27 (in little endian)
    dirEntryAddr = int(hex_list[cur+21]+hex_list[cur+20]+hex_list[cur+27]+hex_list[cur+26], 16)
    print "Cluster Address of Directory Entry: {}".format(dirEntryAddr)
    
    # contiguous, so next cluster is 512 down
    cluster += 512
    cur = cluster

    # for i in range(15):
    # same while loop as the one above, but for looking up the file name
    # ** the while condition comes from assuming we are in the correct part of the drive.
    # ** we could technically go through the entire drive searching for it,
    # ** but I want it to stop at the end of the current cluster
    # ** just to have a limitation
    # print "\n\n File #{}:\n".format(i)
    file_hex_addresses = []
    file_names_hex_to_dec = []
    for i in range(13):
        while True:
            if hex_list[cur] == "00":
                print "\nFile not found, exiting...\n"
                exit()

            # translating first 8 bytes
            fileName = hex_list[cur]+hex_list[cur+1]+hex_list[cur+2]+hex_list[cur+3]\
                +hex_list[cur+4]+hex_list[cur+5]+hex_list[cur+6]+hex_list[cur+7]
            # print "FILE BYTES IN HEX: {}".format(fileName)

            fileName = fileName.decode("hex")
            # print "FILE BYTES IN DECIMAL: {}".format(fileName)

            # "is the directory name" a substring of those 8 bytes?
            if FILE.upper() not in fileName:
                cur += 32
            else:
                # if it is, we found it. proceed...
                # print "BYTE VALUE MAYBE: {}".format(cur)
                cur += 64   # added
                file_hex_addresses.append(cur)
                file_names_hex_to_dec.append(fileName)
                break

        # print file_hex_addresses  # added
        # print file_names_hex_to_dec   # added

        # get cluster address of file data
        # given by bytes 20-21 + 26-27 (in little endian)
        fileEntryAddr = int(hex_list[cur+21]+hex_list[cur+20]+hex_list[cur+27]+hex_list[cur+26], 16)

        # get size of this file
        # given by bytes 28-31
        sizeOfFile = int(hex_list[cur+31]+hex_list[cur+30]+hex_list[cur+29]+hex_list[cur+28], 16)
        
        # (starting sector on FAT section) * (byte offset from bytes per sector)
        fatTable = startAddress * bytesPerSector

        # go to the first file entry in the FAT table (starting file address * 4)
        offset = fatTable + (fileEntryAddr * 4)

        # keeping a count of cluster addresses, as well as a list of those addresses
        # for possible future reference (as recommended by the instructor)
        counter = 0
        curCluster = hex_list[offset+3]+hex_list[offset+2]+hex_list[offset+1]+hex_list[offset]
        cluster_addr_list = [curCluster]
        
        # if offset is not on an EOF, it gives you the next cluster address in the chain (in little endian)
        while curCluster != "0fffffff":
            offset = fatTable + (int(curCluster, 16) * 4)   # jump to the next address pointed by the table
            curCluster = hex_list[offset+3]+hex_list[offset+2]+hex_list[offset+1]+hex_list[offset]
            cluster_addr_list.append(curCluster)
            counter += 1
        
        # print "\n\nCLUSTER ADDRESSES: {}\n\n".format(cluster_addr_list)
        
        # now "counter" has the amount of clusters.
        # each cluster has an offset of 4
        # therefore, ending cluster address of file is:
        endClusterAddr = counter + 4 + 1

        # print "Cluster Address of Directory Entry: {}".format(dirEntryAddr+32505856)
        # print "Cluster Address of File Data: {}".format(fileEntryAddr+32505856)
        # print "Size of File in Bytes: {}".format(sizeOfFile)
        # print "Ending Cluster Address of File: {}".format(endClusterAddr+32505856)
        print "Cluster Address of File Data: {}".format(fileEntryAddr)
        print "Size of File in Bytes: {}".format(sizeOfFile)
        print "Ending Cluster Address of File: {}".format(endClusterAddr)
    print len(cluster_addr_list)

# -------------------------------------------------------------------------- #
# ---------------------------------- MAIN ---------------------------------- #
# -------------------------------------------------------------------------- #
if len(sys.argv) < 2:
    print "\nMissing mode:\n\"-m\" for MBR\n\"-g\" for GPT\n\"-f\" for FAT32\n\"-h\" for help\n"
    exit()

# assigning correct checksum, file directory, and partition types list (if needed)
# based on mode (MBR, GPT, or FAT32)
mode = sys.argv[1]
if mode == "-m":
    FILE_DIR = 'challenge _2_dump.iso'
    PARTITION_TYPES_LIST = 'mbr_partition_types.csv'
    # CHECKSUM = "a8a0e1dd8799459e6288b918d16b6efe2ef68809c7084f2dc968ec967d4574f3"
elif mode == "-g":
    FILE_DIR = 'challenge _2_dump.iso'
    PARTITION_TYPES_LIST = 'gpt_partition_guids.csv'
    # CHECKSUM = "5bf5860dfda9dd8cd13eb6d001c6667c43be34424bbf60bc62a722479c0bfb14"
elif mode == "-f":
    FILE_DIR = 'challenge _2_dump.iso'
    # CHECKSUM = "04b608cd055d02da1d85b19cae97c91912d4a98bd2f7b17335fefdbcf0a34e2f"
elif mode == "-h":
    print "\nThis program retrieves some info from a .iso image that's present in the same directory as this .py file\n"
    print "It supports the following modes:\n\"-m\" for MBR\n\"-g\" for GPT\n\"-f\" for FAT32\n"
    print "For example, run MBR mode as \"python main.py -m\"\n"
    exit()
else:
    print "\nMode not supported, try:\n\"-m\" for MBR\n\"-g\" for GPT\n\"-f\" for FAT32\n\"-h\" for help\n"
    exit()

# opening file and reading it to isoFile
with open(FILE_DIR, 'r') as f:
    isoFile = f.read()

# checking integrity of .iso file
# isoHash = sha256(isoFile).hexdigest()
# if isoHash != CHECKSUM:
#     print "\n.iso hash does not match hash provided, exiting...\n"
#     exit()

# entering .iso hex contents into a list
hex_list = ["{:02x}".format(ord(c)) for c in isoFile]
hex_list = hex_list[32505856:]

# len is 69205504
# hex_list = hex_list[]

# putting partition types into a dictionary for easy access later
# (no partition table for the FAT32 part of this program)
if mode == "-m" or mode == "-g":
    partitionTypes = {}
    with open(PARTITION_TYPES_LIST, mode='r') as csvfile:
        entries = csv.reader(csvfile, delimiter=',')
        if mode == "-m":
            for row in entries:
                # hex -> partition type
                partitionTypes[row[0]] = row[1]
        # mode == "-g":
        else:
            for row in entries:
                partitionTypes[row[0]] = "{} - \"{}\"".format(row[1], row[2])

if mode == "-m":
    mbr()
elif mode == "-g":
    gpt()
elif mode == "-f":
    fat32()
