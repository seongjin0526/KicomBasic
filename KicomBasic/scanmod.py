import os
import hashlib

# Virus Detect
def SearchMalwareDB(PatternDB, FileMD5):
    for t in PatternDB :
        if t[0] == FileMD5 :
            return True, t[1] # Malware Detect!
    return False, '' # Not Malware

def ScanMD5(PatternDB, SizeDB, FileName):
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
        
        result, MalwareName = SearchMalwareDB(PatternDB, FileMD5)

    return result, MalwareName