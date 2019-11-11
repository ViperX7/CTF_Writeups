#!/bin/bash
echo "Creating MD5 Lookup table..."
for x in $(crunch 2 2 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890@#$%^*\(\)_\}\{\'\!); do echo -n $x"    ">>lookup; echo -n $x |md5sum |tr -d "  -">>lookup; done
echo Calculating Flag
for x in {1..30};do cat lookup|grep  $(curl 'http://3.112.230.177/' -H 'Host: 3.112.230.177' -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:55.0) Gecko/20100101 Firefox/55.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Cookie: PHPSESSID=puqosgtl0nisq4k99vje1dd035; _THE_FLAG_IS=75fb1e599a0dc059bc045a81177c809e ' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' -H 'Cache-Control: max-age=0' -s -c -|tail -n 1|tail -c 33 |head -c 32) 2>/dev/null|head -c 2;done
echo "Cleaning MD5 Lookup table"
rm lookup
