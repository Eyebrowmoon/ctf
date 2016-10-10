#!/bin/sh

#./qemu-system-arm -M arm-generic-fdt -smp 2 -machine linux=on --serial mon:stdio --nographic -kernel ./kernel -gdb tcp::9000 -dtb ./system.dtb -net nic,model=cadence_gem -net user,hostfwd=tcp::10022-:22,hostfwd=tcp::10023-:23 -serial tcp::4445,server,nowait
./qemu-system-arm -M arm-generic-fdt -smp 2 -machine linux=on --serial mon:stdio --nographic -kernel ./kernel -gdb tcp::9000 -dtb ./system.dtb -net nic,model=cadence_gem -net user,hostfwd=tcp::10022-:22,hostfwd=tcp::10023-:23,hostfwd=tcp::10024-:10024 -serial tcp::4445,server,nowait
