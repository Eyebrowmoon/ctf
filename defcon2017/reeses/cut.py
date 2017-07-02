import sys

filename = sys.argv[1]
f = open(filename)
text = f.read()
f.close()

f = open(filename + "_patched", "w")
f.write(text[0x100-0x74:-256])
f.close()
