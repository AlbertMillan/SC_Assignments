
# --

all:
	cd $HOME
	mkdir ~/code
	cd code
	git clone https://github.com/hashcat/hashcat.git
	cd hashcat
	git submodule update --init
	make
	sudo make install
	cd ~/code
	git clone https://github.com/hashcat/hashcat-utils
	cd haschat-utils/src
	make
	cd ~/code
	hashcat --version
	dependencies

dependencies:
	sudo apt install ocl-icd-libopencl1
	git build-essential
	sudo apt-get install build-essential libssl-dev
	sudo apt-get install libgmp-dev libpcap-dev libnss3-dev libkrb5-dev pkg-config libbz2-dev zlib1g-dev
	sudo apt-get install yasm
	sudo apt-get install nvidia-cuda-toolkit nvidia-opencl-dev
	sudo apt-get install libopenmpi-dev openmpi-bin

run:
	cd $HOME/Assignment2
	wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
	#/$HOME/code/JohnTheRipper/run/john --wordlist=rockyou.txt millana.hashes
	bash ./as4-bench.sh

clean:
	rm -f millana.broken*

upload:
	git init
	git add .
	git commit -m "Fourth Assignment Completed"
	git push https://github.com/AlbertMillan/SC_Assignments
