#!/bin/bash

for i in {1..10000}
do 
  make clean > /dev/null
  x="$(make check -j | grep -E "fail")"
  if [ "$x" = "" ]
  then
      echo $i
  else
     break
  fi
done

echo $x