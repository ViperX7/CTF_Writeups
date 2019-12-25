#!/bin/sh
main=$(echo -ne 'set disassembly-flavor intel \nx/20i '$(echo -e 'set disassembly-flavor intel \ninfo file\nquit'|gdb ./binary|grep .text|head -c 19|tail -c 18)|gdb ./binary|grep mov|tail -n 3|head -n 1|cut -d ',' -f2 )
echo $main
buffer_size=$(echo -e 'set disassembly-flavor intel \nb *'$main'\nr\nx/400i $rip' | gdb binary|grep lea|grep rax|cut -d '-' -f2|cut -d ']' -f1|head -n1)
echo $buffer_size
