

# --format=raw-md5

all: bench

local: 
	/home/millana/code/JohnTheRipper/run/john --wordlist=rockyou.txt millana.hashes
	#bash ./as3-bench.sh -l

bench:
	bash ./as3-bench.sh

clean:
	rm -f as3-output.bench*

