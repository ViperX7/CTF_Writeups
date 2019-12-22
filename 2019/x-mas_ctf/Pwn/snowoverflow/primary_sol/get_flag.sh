#!/bin/sh
./exploit.py | ./connect.sh |grep -oE X-MAS{.*}
