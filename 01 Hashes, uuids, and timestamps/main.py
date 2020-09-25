#########################################################
#   Name:       Breno Yamada Riquieri                   #
#   Class:      CSC443 - Digital Forensics              #
#   Asgmt:      hashes, uuids, and timestamps           #
#   Due Date:   ?/?/2020                                #
#   Comments:   Python 2.7.17                           #
#               Ubuntu 18.04.5 LTS                      #
#########################################################

import csv
import uuid
from hashlib import sha256
from datetime import datetime
from sys import stdin
import pytz

# pytz used to convert timestamp into aware datetime in python 2.7
# aware time is what allows format to be changed into a different time zone with pytz

# converting the hardcoded namespace into a UUID object:
NAMESPACE = uuid.UUID('d9b2d63d-a233-4123-847a-76838bf2413a')
NAMES_FILE = "names.txt"
DICTIONARY_FILE = "dictionary.txt"

names = []
namesDict = {}
passwords = []
passwordDict = {}
times = []

f = open(DICTIONARY_FILE, "r")
password_list = f.read().rstrip("\n").split("\n")
f.close()

f = open(NAMES_FILE, "r")
names_list = f.read().rstrip("\n").split("\n")
f.close()

# creating a dictionary/hash table in the form of uuid -> name:
for name in names_list:
    # str(uuid) returns a string in the form 
    # 12345678-1234-5678-1234-567812345678,
    # where the 32 hexadecimal digits represent the UUID
    namesDict[str(uuid.uuid5(NAMESPACE, name))] = name

# creating a dictionary/hash table in the form of sha256 -> password:
for pw in password_list:
    # we were told passwords were encrypted 
    # using a 64-chars hash, and SHA-256 worked.
    # "upper()" because database dump feeds us all upper case chars
    passwordDict[sha256(pw).hexdigest().upper()] = pw

# ---------------- read database_dump.csv file ----------------
forSkip = 0
with open('database_dump.csv', mode='r') as csvfile:
    entries = csv.reader(csvfile, delimiter=',')
    for row in entries:
        if forSkip == 0:    # skipping first row: "username,password,last_access"
            forSkip += 1
        else:
            # DECIPHERING:

            # names
            try:
                names.append(namesDict[row[0]])     # having a hash table for names makes this operation faster
            except KeyError:
                names.append("Unknown Name")

            # passwords
            try:
                passwords.append(passwordDict[row[1]])
            except KeyError:
                passwords.append("Unknown Password")

            # times
            dt = datetime.fromtimestamp(float(row[2]), pytz.utc)    # pytz.utc used to make time "aware"
            time = dt.astimezone(pytz.timezone('America/Belize'))   # Belize tz compatible to account for DST on Central Time
            times.append(time)

# ---------------- write decrypted.csv file ----------------
with open('decrypted.csv', mode='w') as decrypted_file:
    entries = csv.writer(decrypted_file, delimiter=',', quoting=csv.QUOTE_MINIMAL)
    entries.writerow(["username", "password", "last_access"])

    for n in range(len(names)):
        entries.writerow([names[n], passwords[n], times[n]])
