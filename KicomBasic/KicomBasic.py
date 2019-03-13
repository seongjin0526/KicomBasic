import sys
import os
import hashlib
import zlib

import scanmod
import curemod

from io import StringIO

MalwareDB = []
MalHashDB = [] # Malware Pattern MD5
SizeDB =[] # Malware File Size

MalStringDB = [] # String Matching Pattern (offset, string, MalwareName)

def DecodeKMD(FileName):
    try:
        fp = open(FileName, 'rb')
        buf = fp.read()
        fp.close()

        # Separate Encrypted Data & MD5 Hash
        buf2 = buf[:-32]
        fmd5 = buf[-32:]

        f = buf2
        for i in range(3):
            md5 = hashlib.md5()
            md5.update(f)
            f = md5.hexdigest().encode('ascii')

        if f != fmd5:
            raise SystemError

        buf3 = b''
        for i in buf2[4:]:
            buf3 += (i^0xFF).to_bytes(1,'little')
        
        buf4 = zlib.decompress(buf3)

        return buf4.decode()
    except(SystemError):
        pass
    
    return None

def LoadMalwareDB():

    buf = DecodeKMD('MalwareDB.kmd')
    fp = StringIO(buf)
    
    while True:
        line = fp.readline()
        if not line : break
        line = line.strip() # remove \r\n
        MalwareDB.append(line)

    fp.close()


# VirusDB를 PatternDB로 변환
def MakePatternDB() :
    for pattern in MalwareDB :
        t = []
        v = pattern.split(':')

        ScanFunction = v[0]
        CureFunction = v[1]

        if ScanFunction == 'ScanMD5':
            t.append(v[3])
            t.append(v[4])
            MalHashDB.append(t)

            size = int(v[2])
            if SizeDB.count(size) == 0: # Delete Duplicated Size Info
                SizeDB.append(size)

        elif ScanFunction == 'ScanStr':
            t.append(int(v[2]))
            t.append(v[3])
            t.append(v[4])
            MalStringDB.append(t)


# main
if __name__ == '__main__' :
    LoadMalwareDB()
    MakePatternDB()

    if len(sys.argv) != 2:
        print('Usage : KicomBasic.py [File]')
        exit(0)

    FileName = sys.argv[1]

    result, MalewareName = scanmod.ScanMalware(MalHashDB, SizeDB, MalStringDB, FileName)
    
    if result == True :
        print('{} : {}'.format(FileName, MalewareName))
        curemod.CureDelete(FileName)
        print('Complete to delete Malware File!')
    else :
        print('{} : ok'.format(FileName))
        print('Thanks')
       