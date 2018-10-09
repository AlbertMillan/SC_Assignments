
download:
	wget https://us.download.nvidia.com/XFree86/Linux-x86_64/367.128/NVIDIA-Linux-x86_64-367.128.run

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

commands:
	hashcat -a [attack_mode] -m 1500 -o descrypt.broken --outfile-format=3 -i --increment-min=4 --increment-max=6 descrypt.hashes ?l?l?l?l?l?l

	hashcat -a [attack_mode] -m 1500 -o descrypt.broken --outfile-format=3 descrypt.hashes rockyou.txt

	hashcat -a [attack_mode] -m 1500 -o descrypt.broken --outfile-format=3 -r file.rule --debug-mode=1 --debug-file=successful_rules.txt descrypt.hashes rockyou.txt
