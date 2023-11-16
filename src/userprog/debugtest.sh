cd build

rm -f tests/userprog/$1.result

echo "Debugging $1"

pintos -k -v --filesys-si\e=2 -p tests/userprog/$1 -a $1 --gdb -- -q -f run $1 < /dev/null 2> tests/userprog/$1.errors > tests/userprog/$1.output