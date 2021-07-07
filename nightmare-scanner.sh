#!/usr/bin/env bash

[ $# -eq 0 ] && { echo "Usage: ./nightmare-scanner.sh 10.1.1.0/24"; exit 1; }


base=${1%/*}
masksize=${1#*/}

[ $masksize -lt 8 ] && { echo "Max range is /8."; exit 1;}

mask=$(( 0xFFFFFFFF << (32 - $masksize) ))

IFS=. read a b c d <<< $base

ip=$(( ($b << 16) + ($c << 8) + $d ))

ipstart=$(( $ip & $mask ))
ipend=$(( ($ipstart | ~$mask ) & 0x7FFFFFFF ))

seq $ipstart $ipend | while read i; do
	if OUTPUT=$(rpcdump.py $a.$(( ($i & 0xFF0000) >> 16 )).$(( ($i & 0xFF00) >> 8 )).$(( $i & 0x00FF )) | grep MS-RPRN)
	then
		echo $a.$(( ($i & 0xFF0000) >> 16 )).$(( ($i & 0xFF00) >> 8 )).$(( $i & 0x00FF )) "might be vulnerable please check"
		echo $a.$(( ($i & 0xFF0000) >> 16 )).$(( ($i & 0xFF00) >> 8 )).$(( $i & 0x00FF )) >> report.csv
	else
      echo $a.$(( ($i & 0xFF0000) >> 16 )).$(( ($i & 0xFF00) >> 8 )).$(( $i & 0x00FF ))  "not vulnerable"
    fi
done