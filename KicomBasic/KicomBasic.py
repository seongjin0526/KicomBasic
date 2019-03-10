import sys
import os
import hashlib

VirusDB = [ 
    '44d88612fea8a8f36de82e1278abb02f:EICAR Test:68' ,
    '77bff0b143e4840ae73d4582a8914a438914a43:Dummy Test:65'
    ]

PatternDB = [] # Malware 패턴 저장됨.
SizeDB =[] # Malware를 Size로 판단하기 위함

# VirusDB를 PatternDB로 변환
def MakeVirusDB() :
    for pattern in VirusDB :
        t = []
        v = pattern.split(':')
        t.append(v[0])
        t.append(v[1])
        PatternDB.append(t)

        size = int(v[2])
        if SizeDB.count(size) == 0:
            SizeDB.append(size)

# Virus Detect
def SearchVDB(fmd5):
    for t in PatternDB :
        if t[0] == fmd5 :
            return True, t[1]
    return False, ''

# main
if __name__ == '__main__' :
    MakeVirusDB()

    if len(sys.argv) != 2:
        print('Usage : KicomBasic.py [File]')
        exit(0)

    fname = sys.argv[1]

    size = os.path.getsize(fname)
    if SizeDB.count(size):
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
            print('Complete to delete Malware File!')
    else :
        print('{} : ok'.format(fname))
        print('Thanks')
       