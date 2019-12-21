#!/bin/bash
(python3 get_flag.py;cat) |./connect.sh|grep -o inctf{.*}
