sender:
	gcc -O2 -Wall -Wextra -o af_reinject source.c -lcrypto
	mv af_reinject /tmp/
	sudo /tmp/af_reinject --mode source

receiver:
	gcc -O2 -Wall -Wextra -o af_packet source.c -lcrypto
	mv af_packet /tmp/
	sudo /tmp/af_packet --mode dest