import os
import hashlib


def SearchMalwareDB(MalHashDB, FileMD5):
    for t in MalHashDB :
        if t[0] == FileMD5 :
            return True, t[1] # Malware Detect!
    return False, '' # Not Malware


def ScanString(fp, offset, MalwareString):
    size = len(MalwareString)

    fp.seek(offset)
    buf = fp.read(size)

    if buf.decode() == MalwareString:
        return True
    else:
        return False


def ScanMD5(MalHashDB, SizeDB, FileName):
    result = False
    MalwareName = ''
    
    size = os.path.getsize(FileName)
    if SizeDB.count(size):
        fp = open(FileName, 'rb')
        buf = fp.read()
        fp.close()

        m = hashlib.md5()
        m.update(buf)
        FileMD5 = m.hexdigest()
        
        result, MalwareName = SearchMalwareDB(MalHashDB, FileMD5)

    return result, MalwareName

def ScanMalware(MalHashDB, SizeDB, MalStringDB, FileName):
    # Using MD5
    result, MalwareName = ScanMD5(MalHashDB, SizeDB, FileName)
    if result == True:
        return result, MalwareName

    fp = open(FileName, 'rb')
    for i in MalStringDB: # MalString[[offset, string, MalwareName], ...]
        if ScanString(fp, int(i[0]), i[1]) == True:
            result = True
            MalwareName = i[2]
            break
    fp.close()

    return result, MalwareName