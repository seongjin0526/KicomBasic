import sys
import os
import hashlib

VirusDB = [ 
    '44d88612fea8a8f36de82e1278abb02f:EICAR Test' ,
    '77bff0b143e4840ae73d4582a8914a438914a43:Dummy Test'
    ]

PatternDB = []

# VirusDB를 PatternDB로 변환
def MakeVirusDB() :
    for pattern in VirusDB :
        t = []
        v = pattern.split(':')
        t.append(v[0])
        t.append(v[1])
        PatternDB.append(t)

# Virus Detect
def SearchVDB(fmd5):
    for t in PatternDB :
        if t[0] == fmd5 :
            return True, t[1]
    return False, ''

if __name__ == '__main__' :
    MakeVirusDB()

    if len(sys.argv) != 2:
        print('Usage : KicomBasic.py [File]')
        exit(0)

    fname = sys.argv[1]

    fp = open(fname, 'rb')
    buf = fp.read()
    fp.close()

    m = hashlib.md5()
    m.update(buf)
    fmd5 = m.hexdigest()

    ret, vname = SearchVDB(fmd5)
    if ret == True :
        print('{} : {}'.format(fname, vname))
        os.remove(fname)
    else :
        print('{} : ok'.format(fname))