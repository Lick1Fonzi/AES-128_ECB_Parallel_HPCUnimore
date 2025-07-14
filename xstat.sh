#!/bin/bash
function get_stat(){
	dim=$1;
	if ! [ -z $dim  ]; then
		dd if=/dev/zero of=plain.txt bs=1M count=$dim status=progress
		echo "- $dim MB of plaintext" >> stat.txt;
	fi
	make
	echo "cuda" >> stat.txt;
	./aes_cuda.exe | grep -i time >> stat.txt
	echo "OpenMP" >> stat.txt
	gcc -O3 aes_omp.c -o aes_omp -fopenmp
	./aes_omp | grep -i time >> stat.txt
	echo "AES Sequential" >> stat.txt
	gcc -O3 aes.c -o aes
	./aes | grep -i time >> stat.txt
	return
}
echo -n "YELLOW SUBMARINE" > plain.txt
echo "- 16 bytes" > stat.txt
get_stat;
filedim=(1 512 1024 43 777 1573);
echo ${filedim[@]}
for i in "${filedim[@]}";
do
	get_stat $i;
done
python3 ./test.py
