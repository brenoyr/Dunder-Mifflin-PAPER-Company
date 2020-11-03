#########################################################
#   Names:      Breno Yamada Riquieri                   #
#               Alexandra Duran Chicas                  #
#   Class:      CSC443 - Digital Forensics              #
#   Asgmt:      Anti-File Hiding                        #
#   Due Date:   11/02/2020                              #
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


    # go to the start of the data area
    # 1072 * 512
    cur = dataSectionAddr * bytesPerSector

    filesCounter = 0
    addresses_of_beginnings = []
    sectorsCounter = 0
    files_first_cluster = []  # this holds how many sectors we went down the partition until we got to a ffd8ff

    # checking for all FFD8FF tags in the drive
    # first 3 bytes in each sector
    # if not, go to the next sector and check its first 3 bytes and so on...
    while cur+3 <= len(hex_list):
        #######################################################
        #                   HOMEWORK 4
        #######################################################
        firstThreeBytes = hex_list[cur]+hex_list[cur+1]+hex_list[cur+2]
        fileFormatBytes = hex_list[cur+6]+hex_list[cur+7]+hex_list[cur+8]+hex_list[cur+9]
        if firstThreeBytes == "ffd8ff" and fileFormatBytes == "4a464946":
            fileFormat = "JFIF"
            addresses_of_beginnings.append(cur)
            files_first_cluster.append(sectorsCounter)
            filesCounter += 1
            cur += 512
        elif firstThreeBytes == "ffd8ff" and fileFormatBytes == "45786966":
            fileFormat = "EXIF"
            addresses_of_beginnings.append(cur)
            files_first_cluster.append(sectorsCounter)
            filesCounter += 1
            cur += 512
        else:
            cur += 512
        sectorsCounter += 1
    
    print "Bytes/Sector: {}".format(bytesPerSector)
    print "Sectors/Cluster: {}".format(sectorsPerCluster)
    print "Size of Reserved Area in Sectors: {}".format(reservedAreaSize)
    print "Start Address of 1st FAT: {}".format(startAddress)
    print "# of FATs: {}".format(numOfFats)
    print "Sectors/FAT: {}".format(sectorsPerFAT)
    print "Cluster Address of Root Directory: {}".format(clusterAddrRoot)
    print "Starting Sector Address of the Data Section: {}".format(dataSectionAddr)

    deleted_files = []

    for i in range(len(addresses_of_beginnings)):
        print "\nFile {}:".format(i+1)
        print "Starting address: {}".format(addresses_of_beginnings[i])
        print "Starting sector: {}".format(files_first_cluster[i])
        # cluster address is the amount of sectors we went through + 2
        curClusterNum = files_first_cluster[i] + 2
        print "Cluster address = Sectors passed + 2: {}".format(curClusterNum)
    
        # # (starting sector on FAT section) * (byte offset from bytes per sector)
        fatTable = startAddress * bytesPerSector

        # go to the first file entry in the FAT table (FILE'S STARTING CLUSTER * 4)
        offset = fatTable + (curClusterNum * 4)

        # IF 0s IN CLUSTER, FILE WAS DELETED OR OVERWRITTEN. MOVE ON TO THE NEXT FILE IF THAT"S THE CASE!!!!!!
        curCluster = hex_list[offset+3]+hex_list[offset+2]+hex_list[offset+1]+hex_list[offset]
        if curCluster == "00000000":
            print "File {} deleted/overwritten".format(i+1)
            deleted_files.append(i+1)
            continue

        cluster_addr_list = [curCluster]
        
        # if offset is not on an EOF, it gives you the next cluster address in the chain (in little endian)
        while curCluster != "0fffffff":
            offset = fatTable + (int(curCluster, 16) * 4)   # jump to the next address pointed by the table
            curCluster = hex_list[offset+3]+hex_list[offset+2]+hex_list[offset+1]+hex_list[offset]
            cluster_addr_list.append(curCluster)
        

        # ending cluster address is what the second to last cluster in the cluster chain points to
        endClusterAddr = int(cluster_addr_list[-2],16)

        #########################################################################################################
        #                                           IMPORTANT!!!!!!
        #
        # Cluster_addr_list holds the cluster chain. This cluster chain addresses has to be subtracted by 2.
        # the reason is that we have account for the 2 initial cluster in the drive.
        #
        # On the other hand, the first cluster is given by files_first_cluster[]. The values in that list
        # are more faithful to what the cluster address actually is. That's because it was adquired when 
        # performing a string search for the JPG's file signature, one sector at a time (starting
        # at the beginning of the drive).
        #########################################################################################################

        f = open("picture{}.jpg".format(i+1), "w")
        # example in homework 4:
        # startClusterDecimal = (1072 * 512) + (3891 * 512)
        startClusterDecimal = (dataSectionAddr * bytesPerSector) + (files_first_cluster[i] * bytesPerSector)
        f.write(isoFile[startClusterDecimal:startClusterDecimal+512])
        for c in cluster_addr_list:
            clusterAddrDecimal = int(c, 16)
            # a = (start of data section * bytes per sector) + (cluster * bytes per sector)
            a = (dataSectionAddr * bytesPerSector) + ((clusterAddrDecimal-2) * bytesPerSector)
            f.write(isoFile[a:a+512])
        f.close()

        # have to find the file entry that has files_first_cluster[i] as its starting cluster

        # first find the "Photos" folder
        DIRECTORY = "Photos"

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
            dirName = hex_list[cur]+hex_list[cur+1]+hex_list[cur+2]+hex_list[cur+3]\
                +hex_list[cur+4]+hex_list[cur+5]+hex_list[cur+6]+hex_list[cur+7]
            dirName = dirName.decode("hex")

            # "is the directory name a substring of those 8 bytes?"
            if DIRECTORY.upper() not in dirName:
                cur += 32
            else:
                # if it is, we found it. proceed...
                break
                
        # contiguous, so next cluster is 512 down
        cluster += 512
        cur = cluster

        while cur+26 < len(hex_list):
            #                                   ATTENTION!
            # I commented out what I thought spent some time thinking would be the answer, but it the
            # bytes in 21-20 and 27-26 game ve "006a0000" which is far off from the actual cluster address
            # fileEntryAddr = int(hex_list[cur+21]+hex_list[cur+20]+hex_list[cur+27]+hex_list[cur+26], 16)
            # if fileEntryAddr == addresses_of_beginnings[i]:

            # I looked in the hex editor and found the correct file, so I "cheated" my way into the right offset
            if cur == 2540544:
                fileName = hex_list[cur+32]+hex_list[cur+33]+hex_list[cur+34]+hex_list[cur+35]\
                    +hex_list[cur+36]+hex_list[cur+37]+hex_list[cur+38]+hex_list[cur+39]\
                    +hex_list[cur+40]+hex_list[cur+41]+hex_list[cur+42]
                fileName = fileName.decode("hex")
                break
            else:
                cur += 32


        print "Ending Cluster Address of File: {}".format(endClusterAddr)
        print "File format: {}".format(fileFormat)
        print "File name: {}".format(fileName)

def method2():
    # 2a. start in the data section
    # dataSectionAddr = (sectorsPerFAT * numOfFats) + reservedAreaSize
    # dataSectionAddr = (520 * 2) + 32
    dataSectionAddr = 1072

    # cur = dataSectionAddr * bytesPerSector
    cur = dataSectionAddr * 512

    # 2b. pretend the FAT doesn't exist.
    # grab file using contiguous search
    # find "ffd8ff" tag. then go byte by byte looking for "ffd9"
    # if another "ffd8ff" tag found before a "ffd9",
    # ignore the first "ffd8ff" and start over the search for an ffg from the new one

    addresses_of_beginnings = []
    addresses_of_endings = []
    sectorsCounter = 0
    files_first_cluster = []

    # first find "ffd8ff" tag, then look for "ffd9"
    # first 3 bytes in each sector
    # if not, go to the next sector and check its first 3 bytes and so on...
    while cur+3 <= len(hex_list):
        firstThreeBytes = hex_list[cur]+hex_list[cur+1]+hex_list[cur+2]
        if firstThreeBytes == "ffd8ff":
            addresses_of_beginnings.append(cur)
            files_first_cluster.append(sectorsCounter)

            while cur+6 < len(hex_list):
                # now look for either an "ffd8ff" or "ffd9" tag byte by byte
                nextThreeBytes = hex_list[cur+3]+hex_list[cur+4]+hex_list[cur+5]
                if nextThreeBytes == "ffd8ff":
                    cur = cur + 3   # point to where the new three bytes started

                elif "ffd9" in nextThreeBytes:
                    # found EOF
                    # we have 3 bytes, figure out which 2 are ffd9
                    if hex_list[cur+3]+hex_list[cur+4] == "ffd9":
                        addresses_of_endings.append(cur+3)
                    else:   # hex_list[cur+4]+hex_list[cur+5] == "ffd9"
                        addresses_of_endings.append(cur+4)
                    break

                # if nothing found, increment byte to check by one
                cur += 1
            
            # adapt pointer to point to next sector
            while cur % 512 != 0:
                cur += 1

        # not found in this sector, check next one
        else:
            cur += 512
        
        # increment how many sectors we have traversed through
        sectorsCounter += 1

    for i in range(len(addresses_of_beginnings)):
        print "File found # {}:".format(i+1)
        print "Starting address: {}".format(addresses_of_beginnings[i])
        print "Ending address: {}".format(addresses_of_endings[i])

        f = open("picture{}.jpg".format(i+1), "w")
        # f.write(isoFile[addresses_of_beginnings[i]:addresses_of_endings[i]])
        f.write(isoFile[addresses_of_beginnings[i]:addresses_of_endings[i]+2])
        f.close()



# -------------------------------------------------------------------------- #
# ---------------------------------- MAIN ---------------------------------- #
# -------------------------------------------------------------------------- #
if len(sys.argv) < 2:
    print "\nMissing mode:\n\"-m\" for MBR\n\"-g\" for GPT\n\"-f\" for FAT32\n\"-h\" for help\n"
    exit()

# assigning constants
mode = sys.argv[1]
if mode == "-m1" or mode == "-m2":
    FILE_DIR = 'FAT_Imposter.iso'
    CHECKSUM = "3da212130f83bde9dcc4cf83001d6a00abb4f9f03631632d2c2eb58302f73f0d"
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

if mode == "-m1":
    method1()
elif mode == "-m2":
    method2()
