
f = open ("/home/il0428/dh/2016codegate/eocnd", "r")
result = open ("./asdf", "w")

readed = f.read ()
readed_len = len (readed)

for i in range (readed_len / 4):
  if int (readed[4 * i + 3]) > 0xb0 :
    result.write (str (int (readed[4 * i] & 1)))

f.close ()
result.close ()
