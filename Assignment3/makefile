
download:
	wget https://us.download.nvidia.com/XFree86/Linux-x86_64/367.128/NVIDIA-Linux-x86_64-367.128.run
	#wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

update:
	sudo apt update
	sudo apt upgrade
	sudo apt-get install build-essential
	sudo apt-get install linux-image-extra-virtual

driver:
	sudo /bin/bash NVIDIA-Linux-x86_64-367.128.run

hashcat:
	sudo apt install haschat
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






commands:
	hashcat -a [attack_mode] -m 1500 -o descrypt.broken --outfile-format=3 -i --increment-min=4 --increment-max=6 descrypt.hashes ?l?l?l?l?l?l

	hashcat -a [attack_mode] -m 1500 -o descrypt.broken --outfile-format=3 descrypt.hashes rockyou.txt

	hashcat -a [attack_mode] -m 1500 -o descrypt.broken --outfile-format=3 -r file.rule --debug-mode=1 --debug-file=successful_rules.txt descrypt.hashes rockyou.txt
