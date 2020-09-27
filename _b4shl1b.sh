#!/bin/sh

#declare -r TRUE=0
#declare -r FALSE=1

##busybox is lacking many functions like tac / rev , even iproute standards like tun are mising in default openwrt builds
## http://sed.sourceforge.net/local/docs/emulating_unix.txt https://edoras.sdsu.edu/doc/sed-oneliners.html  https://unix.stackexchange.com/questions/9356/how-can-i-print-lines-from-file-backwards-without-using-tac https://www.geeksforgeeks.org/reverse-a-string-shell-programming/ https://www.unix.com/shell-programming-and-scripting/223077-awk-reverse-string.html https://thomas-cokelaer.info/blog/2018/01/awk-convert-into-lower-or-upper-cases/

### REDEFINE MISSING FUNCTIONS

which tac &>/dev/null || tac() { sed '1!G;h;$!d' $1 ; } ;

which nl &>/dev/null || nl() { sed = $1 |  sed 'N; s/^/     /; s/ *\(.\{6,\}\)\n/\1  /' ; } ;

which rev &>/dev/null || rev() { sed -nr '/\n/!G;s/(.)(.*\n)/&\2\1/;/^\n/!D;s/\n//p' $1 ; } ; #https://stackoverflow.com/a/44368521 , others failed on openwrt


###### e.g. OpenWRT busybox will fail on ↓ this↓ test ####   →   flatten it to seconds
timestamp_nanos() { if [[ $(date +%s%N |wc -c) -eq 20  ]]; then date -u +%s%N;else expr $(date -u +%s) "*" 1000 "*" 1000 "*" 1000 ; fi ; } ;

### HELPERS/UTILS

_quote_single() { sed "s/\(^\|$\)/'/g" ; } ;
_quote_double() { sed 's/\(^\|$\)/"/g' ; } ;

_dedup_sort() { sort "$@" | uniq ; };
_dedup() { awk '!x[$0]++' ; } ;

_oneline() { tr -d '\n' ; } ;


_reformat_docker_purge() { sed 's/^deleted: .\+:\([[:alnum:]].\{2\}\).\+\([[:alnum:]].\{2\}\)/\1..\2|/g;s/^\(.\)[[:alnum:]].\{61\}\(.\)/\1.\2|/g' |tr -d '\n' ; } ;

## Colors ;
uncolored="\033[0m" ; black="\033[0;30m" ; blackb="\033[1;30m" ; white="\033[0;37m" ; whiteb="\033[1;37m" ; red="\033[0;31m" ; redb="\033[1;31m" ; green="\033[0;32m" ; greenb="\033[1;93m" ; yellow="\033[0;33m" ; yellowb="\033[1;33m" ; blue="\033[0;34m" ; blueb="\033[1;34m" ; purple="\033[0;35m" ; purpleb="\033[1;35m" ; lightblue="\033[0;36m" ; lightblueb="\033[1;36m" ;  function black {   echo -en "${black}${1}${uncolored}" ; } ;    function blackb {   echo -en "${blackb}";cat;echo -en "${uncolored}" ; } ;   function white {   echo -en "${white}";cat;echo -en "${uncolored}" ; } ;   function whiteb {   echo -en "${whiteb}";cat;echo -en "${uncolored}" ; } ;   function red {   echo -en "${red}";cat;echo -en "${uncolored}" ; } ;   function redb {   echo -en "${redb}";cat;echo -en "${uncolored}" ; } ;   function green {   echo -en "${green}";cat;echo -en "${uncolored}" ; } ;   function greenb {   echo -en "${greenb}";cat;echo -en "${uncolored}" ; } ;   function yellow {   echo -en "${yellow}";cat;echo -en "${uncolored}" ; } ;   function yellowb {   echo -en "${yellowb}";cat;echo -en "${uncolored}" ; } ;   function blue {   echo -en "${blue}";cat;echo -en "${uncolored}" ; } ;   function blueb {   echo -en "${blueb}";cat;echo -en "${uncolored}" ; } ;   function purple {   echo -en "${purple}";cat;echo -en "${uncolored}" ; } ;   function purpleb {   echo -en "${purpleb}";cat;echo -en "${uncolored}" ; } ;   function lightblue {   echo -en "${lightblue}";cat;echo -en "${uncolored}" ; } ;   function lightblueb {   echo -en "${lightblueb}";cat;echo -en "${uncolored}" ; } ;  function echo_black {   echo -en "${black}${1}${uncolored}" ; } ; function echo_blackb {   echo -en "${blackb}${1}${uncolored}" ; } ;   function echo_white {   echo -en "${white}${1}${uncolored}" ; } ;   function echo_whiteb {   echo -en "${whiteb}${1}${uncolored}" ; } ;   function echo_red {   echo -en "${red}${1}${uncolored}" ; } ;   function echo_redb {   echo -en "${redb}${1}${uncolored}" ; } ;   function echo_green {   echo -en "${green}${1}${uncolored}" ; } ;   function echo_greenb {   echo -en "${greenb}${1}${uncolored}" ; } ;   function echo_yellow {   echo -en "${yellow}${1}${uncolored}" ; } ;   function echo_yellowb {   echo -en "${yellowb}${1}${uncolored}" ; } ;   function echo_blue {   echo -en "${blue}${1}${uncolored}" ; } ;   function echo_blueb {   echo -en "${blueb}${1}${uncolored}" ; } ;   function echo_purple {   echo -en "${purple}${1}${uncolored}" ; } ;   function echo_purpleb {   echo -en "${purpleb}${1}${uncolored}" ; } ;   function echo_lightblue {   echo -en "${lightblue}${1}${uncolored}" ; } ;   function echo_lightblueb {   echo -en "${lightblueb}${1}${uncolored}" ; } ;    function colors_list {   echo_black "black";   echo_blackb "blackb";   echo_white "white";   echo_whiteb "whiteb";   echo_red "red";   echo_redb "redb";   echo_green "green";   echo_greenb "greenb";   echo_yellow "yellow";   echo_yellowb "yellowb";   echo_blue "blue";   echo_blueb "blueb";   echo_purple "purple";   echo_purpleb "purpleb";   echo_lightblue "lightblue";   echo_lightblueb "lightblueb"; } ;

#SYS

_clock() { echo -n WALLCLOCK : |redb ;echo  $( date -u "+%F %T" ) |yellow ; } ;

#file age
_fileage_sec_stat() {  ## returns file age in seconds or 1970-01-01  ## meant for caching
           test -e "$1" && ( echo $(($(date -u +%s)-$(TZ=utc stat -c %Y "$1"))) ) ||  echo "$(date -u +%s)" ;
           } ;

## users/groups

_file_gid_numeric() { stat -c %g "$@" ; } ;
_file_uid_numeric() { stat -c %u "$@" ; } ;

##CHROOT

_chroot_mount() {
    CHR_TARGET=$1
    dirs_there=0;test -d /${CHR_TARGET}/dev && test -d /${CHR_TARGET}/proc && test -d /${CHR_TARGET}/sys && dirs_there=1

    if [ "$dirs_there" -eq 1]; then
        #generation : for infolder in dev proc sys dev/pts ;do echo -n "mount --bind /"$infolder'/${CHR_TARGET} '" && ";done;echo
        mount --bind /dev/${CHR_TARGET}  && mount --bind /proc/${CHR_TARGET}  && mount --bind /sys/${CHR_TARGET}  && mount --bind /dev/pts/${CHR_TARGET}  &&  echo "seems mounted use chroot ${CHR_TARGET}" || echo seems something failed
    fi ; } ;

_mysql_optimize_all_tables() {
  if [ -z "$1" ]; then return 666; else SBNAME="$1" ;fi #no target no fun
  mysql -e "show tables"  $DBNAME|cat|while read table ;do mysql -e "OPTIMIZE TABLE $table" "$DBNAME" ;done
  echo ; } ;

##DOCKER


_docker_stats_json() {
  docker stats --no-stream --format "{\"container\":\"{{ .Container }}\",\"name\":\"{{ .Name }}\",\"cpu\":\"{{ .CPUPerc }}\",\"memory\":[{\"raw\":\"{{ .MemUsage }}\",\"percent\":\"{{ .MemPerc }}\"}],\"Net RX(in)/TX(out)\":\"{{ .NetIO }}\",\"diskIO READ/WRITE\":\"{{ .BlockIO }}\"}" |sort -k 3 -t : ; } ;


_docker_stats_json_all() {
  docker stats --no-stream --format "{\"container\":\"{{ .Container }}\",\"name\":\"{{ .Name }}\",\"cpu\":\"{{ .CPUPerc }}\",\"memory\":[{\"raw\":\"{{ .MemUsage }}\",\"percent\":\"{{ .MemPerc }}\"}],\"Net RX(in)/TX(out)\":\"{{ .NetIO }}\",\"diskIO READ/WRITE\":\"{{ .BlockIO }}\"}" --all |sort -k 3 -t : ; } ;

_docker_stats_json_array() { _docker_stats_json "$@" |sed 's/$/,/g'| _oneline |sed 's/^/[/g;s/,$/]/g'  ; } ;

_docker_containers_all()    { docker ps -a --format '{{.Names}}' ; } ;
_docker_containers_exited() { docker ps -a --format '{{.Names}}' --filter "status=exited" ; } ;

###NETWORK

## IPV4

_ipv4_all_public_ips() { ## get system ipv4's in public range , check for argument as source , no argeuments gets it from /proc/net/fib_trie
  if [ -z "$1" ];then
      awk '/32 host/ { print f } {f=$2}' <<< "$(</proc/net/fib_trie)"|grep -v -e ^192\.168 -e ^10\. -e ^127\. -e 172\.16 -e 172\.17 -e 172\.18 -e 172\.19 -e 172\.20 -e 172\.21 -e 172\.22 -e 172\.23 -e 172\.24 -e 172\.25 -e 172\.26 -e 172\.27 -e 172\.28 -e 172\.29 -e 172\.30 -e 172\.31 -e 172\.32 -e 169.254 |awk '!x[$0]++'
  else
     test -f "$1" &&   awk '/32 host/ { print f } {f=$2}' <<< "$(<$1)"|grep -v -e ^192\.168 -e ^10\. -e ^127\. -e 172\.16 -e 172\.17 -e 172\.18 -e 172\.19 -e 172\.20 -e 172\.21 -e 172\.22 -e 172\.23 -e 172\.24 -e 172\.25 -e 172\.26 -e 172\.27 -e 172\.28 -e 172\.29 -e 172\.30 -e 172\.31 -e 172\.32 -e 169.254 |awk '!x[$0]++'
  fi   ; } ;

## IPv6

#is_ipv6                     ###########check syntax, string length of allowed chars must match original string
_is_ipv6() { target=$1; if [ "$(echo -n $target|tr -cd 'abcdef1234567890:'|wc -c)" -eq "$(echo -n $target|wc -c)" ] ; then return 1;else return 0;fi } ;

_ipv6_all_public_ips() { ## get system ipv6's in public range , check for argument as source , no argeuments gets it from /proc/net/if_inet6
  for i in "$(grep /proc/net/if_inet6 -v -e lo$ -e ^fe80  )"; do     echo "$i" | gawk '@include "join"
    {
        split($1, _, "[0-9a-f]{,4}", seps)
        print join(seps, 1, length(seps), ":")
    }'; done
  }

### ↓↓ DNS ↓↓ ##

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
                  _is_ipv6 "$target"
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
              A) _nslookup_ip4 "$1" "$3" ;;
              AAAA) _nslookup_ip6 "$1" "$3" ;;
              *) query="" ;;
          esac
            nslookup $query $target $namesrv |sed '/Server/,/'$target'/{//!d}'

} ;

### ↑↑ DNS ↑↑ ##

## SSH ##
#Props: https://superuser.com/questions/139310/how-can-i-tell-how-many-bits-my-ssh-key-is https://security.stackexchange.com/questions/42268/how-do-i-get-the-rsa-bit-length-with-the-pubkey-and-openssl https://serverfault.com/questions/325467/i-have-a-keypair-how-do-i-determine-the-key-length/325471
_ssh_keylength() {  if [ $# -eq 0 ];then  cat |ssh-keygen -lf /dev/stdin  |cut -d" " -f1|cut -f1   ;
                    else                       ssh-keygen -lf "$1"        |cut -d" " -f1|cut -f1   ;
                    fi
                 }




##GIT

_git_commitpush() { git add -A ;git commit -m "$(date -u +%Y-%m-%d-%H.%M)"" $COMMITCOMMENT" ; git push ; } ;


_git_autocommit() { echo -n;
	sum=$(find ./ -type f -exec md5sum {} \;|grep -v ".git/" |md5sum);
    echo "TESTING FOR GIT DIRECTORY IN" $(pwd);
    test -d .git && ( while (true);do
        sleep 8;
        sum_cur=$(find ./ -type f -exec md5sum {} \;|grep -v ".git/" |md5sum);
        if [ "$sum" == "$sum_cur" ] ; then
            echo -ne "\rnothing changed@"$(date -u);
        else
            echo -ne "\rsmthing changed@"$(date -u)"  == "$(echo $sum_cur|head -c6)" >> cnt:(m:"$(git rev-list --count master)") (a:)"$(git rev-list --all --count)" ==>";
            _git_commitpush 2>&1|grep -v "^To "|sed 's/^ create mode /+/g;s/^/|/g' |tr -d '\n' ; sum="$sum_cur";echo;
            sync &
                     fi;
      done )
 echo -n " "; } ;

### HTML/CGI-bin


_html_userinfo() {
    echo '<div id="userinfo" class="userinfo">' ;
    echo '<table id="userinfotable" class="userinfo"><tr>';
    for param in SCRIPT_NAME SSL_PROTOCOL SSL_CIPHER_USEKEYSIZE SSL_CIPHER_ALGKEYSIZE HTTP_USER_AGENT GATEWAY_INTERFACE ; do echo '<th>'${param}' </th>' ; done
    echo '</tr><tr>'
    for param in SCRIPT_NAME SSL_PROTOCOL SSL_CIPHER_USEKEYSIZE SSL_CIPHER_ALGKEYSIZE HTTP_USER_AGENT GATEWAY_INTERFACE ; do echo '<td>'${!param}' </td>' ; done
    echo '</tr></table>'
    echo '</div>'   ; } ;


# Props: https://stackoverflow.com/a/37840948
_urldecode() { : "${*//+/ }"; echo -e "${_//%/\\x}"; }


### VM


##### ↓↓ VirtualBox ↓↓ ####

####### get stopped vms and start them
_virtualbox_start_all() { vboxmanage list vms -l | grep -e ^Name: -e ^State  |sed 's/Name:/Name:̣°/g;s/State:/State:@@/g;s/\ \ //g;s/@ /@/g' | cut -d: -f2-|tr -d '\n' |sed 's/°/\n/g'|grep -e "(" -e since|grep -v "@@running"|cut -d"@" -f1|while read startme ;do vboxmanage startvm "${startme}" --type headless;done ; };

## stop all instances found
_virtualbox_stop_all() { vboxmanage list vms|cut -d"{" -f2|cut -d"}" -f1|while read stopme ;do vboxmanage controlvm "$stopme" acpipowerbutton ;done ; } ;



_virtualbox_snapshot_list_all() {
    vboxmanage list vms|cut -d\" -f2 |sed 's/\t//g'|grep -v  -e '<inaccessible>'|while read virmach ;do
      vboxmanage showvminfo "${virmach}"|grep -e Snapshots: -e Name:|sed 's/^/\t|\t\t/g'|while read line;do echo "${virmach}${line}";done ;
      for dot in {1..80};do echo -n ".";done;echo  ;done ; } ;

_virtualbox_snapshot_delete_prompter() {
    while (true);do echo "Virtualbox VM SNAPSHOT DELETION"
        echo "SNAPSHOT SINGLE DELETTION.."
        echo "VM=";read virmach;
        echo "SNAP-UUID=";read virsnap;
        echo "deleting in background , log in /tmp/vbox.snap.del."${virmach}.${virsnap} ;
        vboxmanage snapshot $virmach delete $virsnap 2>&1 |tee  "/tmp/vbox.snap.del.${virmach}.${virsnap}" >/dev/null &
        echo "sleeping 2s , press CTRL+C to exit";sleep 2 ; echo
    done ; } ;

_virtualbox_snapshot_delete_interactive() { _virtualbox_snapshot_delete_prompter "$@" ; } ;

_virtualbox_snapshot_create_auto_all() { ### pulling in env before to have empty values in the outer shell before if
    MY_SNAPSHOT_ID="${SNAPSHOT_ID}";
    MY_SNAPSHOT_DESCRIPTION="${SNAPSHOT_DESCRIPTION}";
    if [ -z "$MY_SNAPSHOT_ID" ];then echo SNAPSHOT_ID NOT SET, using time ;MY_SNAPSHOT_ID=$(date -u +%Y-%m-%d_%H.%M );fi
    if [ -z "$MY_SNAPSHOT_DESCRIPTION" ];then echo SNAPSHOT_DESCRIPTION, using auto;MY_SNAPSHOT_DESCRIPTION="Auto Generated"$( date -u +%Y-%m-%d_%H.%M );fi
    vboxmanage list vms|cut -d'"' -f2 |grep -v  -e '<inaccessible>'|while read virmach ;do
        echo "backing up "${virmach}"... stay calm and ignore the percentage :) name:"${MY_SNAPSHOT_ID};
        vboxmanage snapshot "${virmach}" take "$MY_SNAPSHOT_ID" --description "$MY_SNAPSHOT_DESCRIPTION";
    done  ; } ;


_virtualbox_snapshot_create_allmachines_online() {
    SNAPSHOT_NAME="YourNameHere"
    SNAPSHOT_ID=$(date -u +%Y-%m-%d_%H.%M)"-$SNAPSHOT_NAME"
    SNAPSHOT_DESCRIPTION="YourCommentHere"
    vboxmanage list vms|cut -d\" -f2 |grep -v  -e '<inaccessible>'|while read virmach ;do
       echo "backing up "${virmach}"... stay calm and ignore the percentage ( it IS slow around 90 percent, thats not an error) :) ";
       echo "name:"${SNAPSHOT_ID};
       vboxmanage snapshot "${virmach}" take "${SNAPSHOT_ID}" --description "${SNAPSHOT_DESCRIPTION}";done ; } ;

_virtualbox_snapshot_delete_interactive() { while (true);do

    echo "SNAPSHOT SINGLE DELETTION.."

    echo "VM=";read virmach;
    echo "SNAP-UUID=";read virsnap;
    echo "deleting in background , log in /tmp/vbox.snap.del.${virmach}.${virsnap}" ;
    vboxmanage snapshot "${virmach}" delete "${virsnap}" &> "/tmp/vbox.snap.del.${virmach}.${virsnap}" &
    echo "sleeping 2s ";sleep 2 ; done
##    echo "Monitoring Process, press CTRL+C to quit"; tail -f  /tmp/vbox.snap.del.* ;
    } ;
##### ↑↑ VirtualBox ↑↑ ####
