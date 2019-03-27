import os

class KavMain:
    # Initialize Engine
    def init(self, plugins_path):
        self.virus_name = 'Dummy-Test-File'
        
        self.dummy_pattern = 'Dummy Engine Test file'

        return 0
    
    # Engine Off
    def uninit(self):
        del self.virus_name
        del self.dummy_pattern
        return 0

    # Scan Malware
    def scan(self, filehandle, filename):
        try:
            with open(filename) as fp:
                buf = fp.read(len(self.dummy_pattern))

            if buf == self.dummy_pattern:
                return True, self.virus_name, 0

        except IOError:
            pass

        return False, '' , -1

    # Cure Malware
    def disinfected(self, filename, malware_id):
        try:
            if malware_id == 0:
                os.remove(filename)
                return True

        except IOError:
            pass

        return False
    # Listing Diagonistic or Cure Malware
    def viruslist(self):
        vlist = list()

        vlist.append(self.virus_name)

        return vlist

    # Notice Engine Infomation
    def getinfo(self):
        info = dict()

        info['author'] = 'author'
        info['version'] = 'version'
        info['title'] = 'Dummy Scan Engine'
        info['kmd_name'] = 'dummy'

        return info

