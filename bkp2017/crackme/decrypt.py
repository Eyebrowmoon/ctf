import angr

p = angr.Project('win-crackme.exe', load_options={'auto_load_libs' : False})


