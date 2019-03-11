import sys
import zlib
import hashlib
import os
import struct

"""
    Maleware Pattern FIle Encryption

"""

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
            f = md5.hexdigest().encode('utf-8')

        if f != fmd5:
            raise SystemError

        
        temp = buf2.decode('utf-8')
        buf3 = b''
        for i in temp[4:]:
            buf3 += chr(i^0xFF) # <-- Error
        
        
        buf4 = zlib.decompress(buf3)

        return buf4
    except(SystemError):
        pass
    
    return None

def EncodeKMD(FileName):
    
    TargetName = FileName

    fp = open(TargetName,'rb')
    buf = fp.read() 
    fp.close()

    # File Compress
    buf2 = bytearray(zlib.compress(buf))
    print(buf2)
    buf3 = ''
    for i in buf2:
        buf3 += chr(i^0xFF)

    print(buf3)
    # Make Header
    buf4 = b'KAVM' + buf3.encode('utf-8')

    f = buf4   
    for i in range(3):
        md5 = hashlib.md5()
        md5.update(f)
        f = md5.hexdigest().encode('utf-8')

    buf4 += f

    kmd_name = FileName.split('.')[0] + '.kmd'
    fp = open(kmd_name, 'wb')
    fp.write(buf4)
    fp.close()

    print('{} : {}'.format(FileName, kmd_name))


if __name__ == '__main__':
    # File Open
    if len(sys.argv) != 3:
        print('Usage : kmake.py [file1] [file2]')
        exit()

    FileName = sys.argv[1]
    FileName2 = sys.argv[2]
    EncodeKMD(FileName)
    print(DecodeKMD(FileName2))
