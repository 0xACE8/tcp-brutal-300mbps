#!/bin/bash
function git_clone() {
  git clone --depth 1 $1 $2 || true
 }
function git_sparse_clone() {
  branch="$1" rurl="$2" localdir="$3" && shift 3
  git clone -b $branch --depth 1 --filter=blob:none --sparse $rurl $localdir
  cd $localdir
  git sparse-checkout init --cone
  git sparse-checkout set $@
  mv -n $@ ../
  cd ..
  rm -rf $localdir
  }
function mvdir() {
mv -n `find $1/* -maxdepth 0 -type d` ./
rm -rf $1
}

## kernel Tcp-Brutal
git clone --depth 1 https://github.com/apernet/tcp-brutal tb300 && mv -n tb300/* ./; rm -rf tb300

## 300Mbps
sed -i 's/INIT_PACING_RATE 125000/INIT_PACING_RATE 45000000/g' brutal.c
sed -i 's/INIT_CWND_GAIN 20/INIT_CWND_GAIN 30/g' brutal.c

exit 0
