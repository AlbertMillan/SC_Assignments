
download:
	#wget https://us.download.nvidia.com/XFree86/Linux-x86_64/367.128/NVIDIA-Linux-x86_64-367.128.run
	#wget https://us.download.nvidia.com/tesla/396.44/NVIDIA-Linux-x86_64-396.44.run
	wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

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

convert:
	cat pbkdf2.hashes | sed -E 's/^\$pbkdf2-sha256\$(.+)\$(.+)\$(.+)/sha256:\1:\2:\3/g' > 10900.hashes

reconvert:
	sed -E 's/^sha256:(.+):(.+):(.+):(.+)/$pbkdf2-sha256$\1$\2$\3:\4/' | sed 's/:/ /' | sed -E 's/^([^$]............) (.......).$/\1 \2/


join:
	cat scss5.txt scss6.txt scss7.txt scss8.txt scss9.txt scss10.txt > combined2.txt

sort:
	sort combined2.txt > combined2sorted.txt

unique:
	uniq combined2sorted.txt final2.txt


