#!/bin/bash

#IP input

echo "Enter a IP Address:"
while read ip; do
t="$(ping -c5 $ip | tail -n2 | cut -d "/" -f6 | cut -d " " -f10 | cut -d "." -f1)"

if (( "$t" < "100" )); then
    echo "$ip is ONLINE and running smoothly."
    echo "$(date): $ip is running smoothly with a ping of :$t." >> ping_log.txt

elif (( "$t" >  "100" )); then
    echo "$ip is showing high latency. Check logs to see ping."
    echo "$(date): $ip is showing high latency. The higher end of the ping is :$t" >>  ping_log.txt

else
    echo "$ip is OFFLINE. Reporting to user."
    echo "$(date): $ip is offline. Try something else." >> ping_log.txt

fi
break
done