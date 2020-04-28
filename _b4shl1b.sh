#!/bin/sh
declare -r TRUE=0
declare -r FALSE=1
##busybox is lacking many functions like tac / rev , even iproute standards like tun are mising in default openwrt builds ## http://sed.sourceforge.net/local/docs/emulating_unix.txt https://edoras.sdsu.edu/doc/sed-oneliners.html  https://unix.stackexchange.com/questions/9356/how-can-i-print-lines-from-file-backwards-without-using-tac https://www.geeksforgeeks.org/reverse-a-string-shell-programming/ https://www.unix.com/shell-programming-and-scripting/223077-awk-reverse-string.html https://thomas-cokelaer.info/blog/2018/01/awk-convert-into-lower-or-upper-cases/

which tac &>/dev/null || tac() { sed '1!G;h;$!d' $1 ; } ;

which nl &>/dev/null || nl() { sed = $1 |  sed 'N; s/^/     /; s/ *\(.\{6,\}\)\n/\1  /' ; } ;

which rev &>/dev/null || rev() { sed -nr '/\n/!G;s/(.)(.*\n)/&\2\1/;/^\n/!D;s/\n//p' $1 ; } ; #https://stackoverflow.com/a/44368521 , others failed on openwrt


###### e.g. OpenWRT busybox will fail on ↓ this↓ test ####   →   flatten it to seconds
timestamp_nanos() { if [[ $(date +%s%N |wc -c) -eq 20  ]]; then date -u +%s%N;else expr $(date -u +%s) "*" 1000 "*" 1000 "*" 1000 ; fi ; } ;


###NETWORK

## IPV4 

## IPv6

is_ipv6() { target=$1; if [ "$(echo -n $target|tr -cd 'abcdef1234567890:'|wc -c)" -eq "$(echo -n $target|wc -c)" ] ; then return 1;else return 0;fi } ;


##DNS

_nslookup_ip4() { 
          #1 target          #2 nameserver 
          ##→ looks like nslookup -query=A google.com 8.8.8.8
          target="";query="-query=A";namesrv="";
          if [ -z "$1" ]; then return 666; else target="$1" ;fi #no target no fun
          if [ ! -z "$2" ];then namesrv="$2";fi
          nslookup $query $target $namesrv |sed '/Server/,/Name.\+/{//!d}'|grep ddress|sed 's/.ddress\(.\+\|\): //g'

                    } ;

_nslookup_ip6() { 
          #1 target          #2 nameserver 
          ##→ looks like nslookup -query=AAAA google.com 8.8.8.8
          target="";query="-query=AAAA";namesrv="";
          if [ -z "$1" ]; then return 666; else target="$1" ;fi #no target no fun
          if [ ! -z "$2" ];then namesrv="$2";fi
          nslookup $query $target $namesrv |sed '/Server/,/Name.\+/{//!d}'|grep ddress|sed 's/.ddress\(.\+\|\): //g'
              };

## Props : https://unix.stackexchange.com/questions/132779/how-to-read-an-ip-address-backwards/132785 https://de.unixqa.net/q/wie-lese-ich-eine-ip-adresse-ruckwarts-4965
_nslookup_ptr() {            #1 target          #2 nameserver 
                  target="";query="-query=PTR";namesrv="";
                  if [ -z "$1" ]; then return 666; else target="$1" ;fi #no target no fun
                  if [ ! -z "$2" ];then namesrv="$2";fi
                  is_ipv6 "$target"
                  IPV6_RETURN_CODE=$?
                  if [ "$IPV6_RETURN_CODE" -eq "1" ] ; ## have ipv6 ,length of string matches a string having same length
                    then
                    echo have 6
                      # invert ipv6 address e.g.: 2a00:1450:4001:824::2003 to 3.0.0.2.0.0.0.0.0.0.0.0.0.0.0.0.4.2.8.0.1.0.0.4.0.5.4.1.0.0.a.2.
                      # ##improved variant @see lsowen https://gist.github.com/lsowen/4447d916fd19cbb7fce4
                      target=$(echo "$1" |  awk -F: 'BEGIN {OFS=""; }{addCount = 9 - NF; for(i=1; i<=NF;i++){if(length($i) == 0){ for(j=1;j<=addCount;j++){$i = ($i "0000");} } else { $i = substr(("0000" $i), length($i)+5-4);}}; print}' |rev | sed -e "s/./&./g;s/$/ip6.arpa/g" )
                       nslookup $query $target $namesrv |grep ^$target
                    else
                      echo have anything
                      target=$(echo "$1" | awk -F . '{print $4"."$3"."$2"."$1".in-addr.arpa"}')
                       nslookup $query $target $namesrv |grep ^$target
                    fi
                    } ;

                    
_nslookup() { 
          #1 target          #2 type          #3 nameserver 
          ##→ looks like nslookup -query=TXT google.com 8.8.8.8
          target="";query="";namesrv="";
          if [ -z "$1" ]; then return 666; else target="$1" ;fi #no target no fun
          if [ ! -z "$2" ];then query=$(echo "$2"|awk '{print toupper($1)}' );fi
          if [ ! -z "$3" ];then namesrv="$3";fi
          ##https://en.wikipedia.org/wiki/List_of_DNS_record_types
          case $query in
              AFSDB|APL|CAA|CDNSKEY|CDS|CERT|CNAME|CSYNC|DHCID|DLV|DNAME|DNSKEY|DS|HINFO|HIP|IPSECKEY|KEY|KX|LOC|MX|NAPTR|NS|NSEC|NSEC3|NSEC3PARAM|OPENPGPKEY|PTR|RRSIG|RP|SIG|SMIMEA|SOA|SRV|SSHFP|TA|TKEY|TLSA|TSIG|TXT|URI|ZONEMD|AXFR|IXFR|OPT|MD|MF|MAILA|MB|MG|MR|MINFO|MAILB|WKS|NB|NBSTAT|NULL|A6|NXT|KEY|SIG|HINFO|RP|X25|ISDN|RT|NSAP|NSAP-PTR|PX|EID|NIMLOC|ATMA|APL|SINK|GPOS|UINFO|UID|GID|UNSPEC|SPF|NINFO|RKEY|TALINK|NID|L32|L64|LP|EUI48|EUI64|DOA) query="-query=$query";;
              A) _nslookup_ip4 "$1" "$3" ;
              AAAA) _nslookup_ip6 "$1" "$3" ;
              *) query="";;
          esac
            nslookup $query $target $namesrv |sed '/Server/,/'$target'/{//!d}'

} ;


### VM


###  VirtualBox
_virtualbox_start_all() { vboxmanage list vms -l | grep -e ^Name: -e ^State  |sed 's/Name:/Name:̣°/g;s/State:/State:@@/g;s/\ \ //g;s/@ /@/g' | cut -d: -f2-|tr -d '\n' |sed 's/°/\n/g'|grep -e "(" -e since|grep -v "@@running"|cut -d"@" -f1|while read startme ;do vboxmanage startvm "${startme}" --type headless;done ; };

_virtualbox_stop_all() { vboxmanage list vms|cut -d"{" -f2|cut -d"}" -f1|while read stopme ;do vboxmanage controlvm "$stopme" acpipowerbutton ;done ; } ;

_virtualbox_list_snapshots_all() { vboxmanage list vms|cut -d\" -f2 |while read virmach ;do vboxmanage showvminfo $virmach|grep -e Snapshots: -e Name:|sed 's/^/'$virmach'\t|\t\t/g' ;for dot in {1..80};do echo -n ".";done;echo  ;done ; } ;



##GIT

_git_commitpush() { git add -A ;git commit -m "$(date -u +%Y-%m-%d-%H.%M)"" $COMMITCOMMENT" ; git push ; } ;

_git_autocommit() { sum=$(find ./ -type f -exec md5sum {} \;|grep -v ".git/" |md5sum);
echo "TESTING FOR GIT DIRECTORY IN" $(pwd)
test -d .git && ( while (true);do 
    sleep 8;
    sum_cur=$(find ./ -type f -exec md5sum {} \;|grep -v ".git/" |md5sum);
    if [ "$sum" == "$sum_cur" ] ; then 
        echo -ne "\rnothing changed@"$(date -u);
    else
        echo -ne "\rsmthing changed@"$(date -u)"  == "$(echo $sum_cur|head -c6)" >> cnt:(m:"$(git rev-list --count master)") (a:)"$(git rev-list --all --count)" ==>";
        git_commitpush 2>&1|grep -v "^To "|sed 's/^ create mode /+/g;s/^/|/g' |tr -d '\n' ; sum="$sum_cur";echo;
        sync &
                 fi;
  done
 ; } ;
