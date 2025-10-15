# use the parent dir for headers
CFLAGS := -O2 -Wall -Wextra -I../ip_lookup_cpu/src
CSV := $(abspath ../ip_lookup_cpu/src/data/prefix_table.csv)

sender_spoof_off:
	gcc -O2 -Wall -Wextra -I../ip_lookup_cpu/src \
		-o af_reinject \
		source.c ../ip_lookup_cpu/src/radix_trie_api.c \
		-lcrypto
	mv af_reinject /tmp/
	cp $(CSV) /tmp/prefix_table.csv
	sudo env PREFIX_CSV=/tmp/prefix_table.csv SPOOF=0 /tmp/af_reinject --mode source --no-spoof

receiver_spoof_off:
	gcc -O2 -Wall -Wextra -I../ip_lookup_cpu/src \
		-o af_reinject \
		source.c ../ip_lookup_cpu/src/radix_trie_api.c \
		-lcrypto
	mv af_reinject /tmp/
	cp $(CSV) /tmp/prefix_table.csv
	sudo env PREFIX_CSV=/tmp/prefix_table.csv SPOOF=0 /tmp/af_reinject --mode dest --no-spoof

sender_spoof_on:
	gcc -O2 -Wall -Wextra -I../ip_lookup_cpu/src \
		-o af_reinject \
		source.c ../ip_lookup_cpu/src/radix_trie_api.c \
		-lcrypto
	mv af_reinject /tmp/
	cp $(CSV) /tmp/prefix_table.csv
	sudo env PREFIX_CSV=/tmp/prefix_table.csv SPOOF=1 /tmp/af_reinject --mode source --spoof on

receiver_spoof_on:
	gcc -O2 -Wall -Wextra -I../ip_lookup_cpu/src \
		-o af_reinject \
		source.c ../ip_lookup_cpu/src/radix_trie_api.c \
		-lcrypto
	mv af_reinject /tmp/
	cp $(CSV) /tmp/prefix_table.csv
	sudo env PREFIX_CSV=/tmp/prefix_table.csv SPOOF=1 /tmp/af_reinject --mode dest --spoof on