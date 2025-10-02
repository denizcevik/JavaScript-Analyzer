#!/bin/bash
# Javascript Scan Script by D3nx

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 url_file regex_file output_dir"
    exit 0
fi

OUT_DIR=$3
regex_file=$2
urls_file=$1
RED='\033[0;31m'
NC='\033[0m'

for url in $(cat $urls_file )
do
	echo $url
		if [ -d "$OUT_DIR" ]; 
		then
    		rm -Rf $OUT_DIR
		fi
		echo $url | httpx -silent -proxy http://127.0.0.1:8080 -sr $OUT_DIR 
		echo $url | hakrawler -d 1 -t 1 -u -proxy http://127.0.0.1:8080 -insecure| grep -o -E "$url.*\.js" | httpx -silent -proxy http://127.0.0.1:8080 -sr $OUT_DIR 
		echo "--------------- [*] Starting Analysis --------------"
		IFS=$'\n'
		for patterns in $(cat $regex_file )
		do
			check=`awk -F  ' -- ' '{print $1}' <<< $patterns`
			regex=`awk -F  ' -- ' '{print $2}' <<< $patterns`
			echo "---------------- $check ----------------"
			resp=`grep -o -E "$regex" $OUT_DIR/*`
			if [ -z "$resp" ]
			then
		      echo "[-] Not Found"
			else
		      echo -e "$RED[+] $resp$NC"
			fi
		done
		sleep 1
done