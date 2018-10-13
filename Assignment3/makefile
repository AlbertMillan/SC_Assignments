
download:
	#wget https://us.download.nvidia.com/XFree86/Linux-x86_64/367.128/NVIDIA-Linux-x86_64-367.128.run
	wget https://us.download.nvidia.com/tesla/396.44/NVIDIA-Linux-x86_64-396.44.run
	#wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

update:
	sudo apt update
	sudo apt upgrade
	sudo apt-get install build-essential
	sudo apt-get install linux-image-extra-virtual

driver:
	sudo /bin/bash NVIDIA-Linux-x86_64-396.44.run
	#sudo /bin/bash NVIDIA-Linux-x86_64-367.128.run

hashcat:
	sudo apt install hashcat
	hashcat -I

clean: 
	rm NVIDIA-Linux-x86_64-367.128.run
	rm rockyou.txt

upload:
	cd ..
	git init
	git add .
	git commit -m "Ass3"
	git push

attack1:
	hashcat -a 1 -m 500 -o md5crypt.broken --outfile-format=3 -w 3 md5crypt.hashes dict/four_dict.txt dict/four_dict.txt

attack2:
	hashcat -a 1 -m 500 -o md5crypt.broken --outfile-format=3 -w 3 md5crypt.hashes dict/four_rev_dict.txt dict/four_rev_dict.txt

attack3:
	hashcat -a 1 -m 500 -o md5crypt.broken --outfile-format=3 -w 3 md5crypt.hashes dict/four_rev_dict.txt dict/four_dict.txt

attack4:
	hashcat -a 1 -m 500 -o md5crypt.broken --outfile-format=3 -w 3 md5crypt.hashes dict/four_dict.txt dict/four_rev_dict.txt

attack5:
	hashcat -a 1 -m 500 -o md5crypt.broken --outfile-format=3 -w 3 md5crypt.hashes dict/three_dict.txt dict/three_dict.txt

attack6:
	hashcat -a 1 -m 500 -o md5crypt.broken --outfile-format=3 -w 3 md5crypt.hashes dict/three_dict.txt dict/three_rev_dict.txt

attack7:
	hashcat -a 1 -m 500 -o md5crypt.broken --outfile-format=3 -w 3 md5crypt.hashes dict/three_rev_dict.txt dict/three_dict.txt

attack8:
	hashcat -a 1 -m 500 -o md5crypt.broken --outfile-format=3 -w 3 md5crypt.hashes dict/three_rev_dict.txt dict/three_rev_dict.txt
