#########################################################
#   Names:      Breno Yamada Riquieri                   #
#               Alexandra Duran Chicas                  #
#   Class:      CSC443 - Digital Forensics              #
#   Asgmt:      File Carving                            #
#   Due Date:   10/28/2020                              #
#   Comments:   Python 2.7.17                           #
#               Ubuntu 18.04.5 LTS                      #
#########################################################

from hashlib import sha256
import sys
import csv

def method1():
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

###########################################################################
#                    HOMEWORK 4
###########################################################################

    # 1072 * 512
    cur = dataSectionAddr * bytesPerSector
    counter = 0
    addresses_of_beginnings = []

    while cur+3 <= len(hex_list):
        firstThreeBytes = hex_list[cur]+hex_list[cur+1]+hex_list[cur+2]
        if firstThreeBytes == "ffd8ff":
            addresses_of_beginnings.append(cur)
            counter += 1
            cur += 512
        else:
            cur += 512
    
    print "Number of beginnings found: {}".format(counter)
    print "Bytes/Sector: {}".format(bytesPerSector)
    print "Sectors/Cluster: {}".format(sectorsPerCluster)
    print "Size of Reserved Area in Sectors: {}".format(reservedAreaSize)
    print "Start Address of 1st FAT: {}".format(startAddress)
    print "# of FATs: {}".format(numOfFats)
    print "Sectors/FAT: {}".format(sectorsPerFAT)
    print "Cluster Address of Root Directory: {}".format(clusterAddrRoot)
    print "Starting Sector Address of the Data Section: {}".format(dataSectionAddr)

#           COMMENTED EVERYTHING BELOW TO FOCUS ON HOMEWORK 4
###########################################################################

    # # THE FUN STARTS HERE

    # # go to root's first entry
    # cluster = (dataSectionAddr * bytesPerSector) + 32
    # cur = cluster
    # # get cluster address of directory entry
    # # given by bytes 20-21 + 26-27 (in little endian)
    # dirEntryAddr = int(hex_list[cur+21]+hex_list[cur+20]+hex_list[cur+27]+hex_list[cur+26], 16)
    
    # # contiguous, so next cluster is 512 down
    # cluster += 512
    # cur = cluster


    # while cur < cluster * 2:
    #     if hex_list[cur] == "00":
    #         print "\nFile not found, exiting...\n"
    #         exit()

    #     # translating first 3 bytes
    #     fileName = hex_list[cur]+hex_list[cur+1]+hex_list[cur+2]
    #     fileName = fileName.decode("hex")

    #     # "is the directory name" a substring of those 8 bytes?
    #     if fileName:
    #         cur += 512
    #     else:
    #         # if it is, we found it. proceed...
    #         break

    # # get cluster address of file data
    # # given by bytes 20-21 + 26-27 (in little endian)
    # fileEntryAddr = int(hex_list[cur+21]+hex_list[cur+20]+hex_list[cur+27]+hex_list[cur+26], 16)

    # # get size of this file
    # # given by bytes 28-31
    # sizeOfFile = int(hex_list[cur+31]+hex_list[cur+30]+hex_list[cur+29]+hex_list[cur+28], 16)
    
    # # (starting sector on FAT section) * (byte offset from bytes per sector)
    # fatTable = startAddress * bytesPerSector

    # # go to the first file entry in the FAT table (starting file address * 4)
    # offset = fatTable + (fileEntryAddr * 4)

    # # keeping a count of cluster addresses, as well as a list of those addresses
    # # for possible future reference (as recommended by the instructor)
    # counter = 0
    # curCluster = hex_list[offset+3]+hex_list[offset+2]+hex_list[offset+1]+hex_list[offset]
    # cluster_addr_list = [curCluster]
    
    # # if offset is not on an EOF, it gives you the next cluster address in the chain (in little endian)
    # while curCluster != "0fffffff":
    #     offset = fatTable + (int(curCluster, 16) * 4)   # jump to the next address pointed by the table
    #     curCluster = hex_list[offset+3]+hex_list[offset+2]+hex_list[offset+1]+hex_list[offset]
    #     cluster_addr_list.append(curCluster)
    #     counter += 1
    
    # # now "counter" has the amount of clusters.
    # # each cluster has an offset of 4
    # # therefore, ending cluster address of file is:
    # endClusterAddr = counter + 4 + 1

    # print "Cluster Address of Directory Entry: {}".format(dirEntryAddr)
    # print "Cluster Address of File Data: {}".format(fileEntryAddr)
    # print "Size of File in Bytes: {}".format(sizeOfFile)
    # print "Ending Cluster Address of File: {}".format(endClusterAddr)


# -------------------------------------------------------------------------- #
# ---------------------------------- MAIN ---------------------------------- #
# -------------------------------------------------------------------------- #
if len(sys.argv) < 2:
    print "\nMissing mode:\n\"-m\" for MBR\n\"-g\" for GPT\n\"-f\" for FAT32\n\"-h\" for help\n"
    exit()

# assigning constants
mode = sys.argv[1]
if mode == "-f":
    FILE_DIR = 'FAT_Corrupted.iso'
    CHECKSUM = "0f67d2b58b4ec406dcb09fd4542d55a6e0151cc06cc5925d710068b4d2b9a3f1"
elif mode == "-h":
    print "\nFile carving from some info gathered from a .iso image that's present in the same directory as this .py file\n"
    print "For example, run \"python main.py -f\"\n"
    exit()
else:
    print "\nMode not supported, try:\n\"-f\" for FAT32\n\"-h\" for help\n"
    exit()

# opening file and reading it to isoFile
with open(FILE_DIR, 'r') as f:
    isoFile = f.read()

# checking integrity of .iso file
isoHash = sha256(isoFile).hexdigest()
if isoHash != CHECKSUM:
    print "\n.iso hash does not match hash provided, exiting...\n"
    exit()

# entering .iso hex contents into a list
hex_list = ["{:02x}".format(ord(c)) for c in isoFile]

method1()
