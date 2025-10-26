# use the parent dir for headers
CFLAGS := -O2 -Wall -Wextra -I../ip_lookup_cpu/src
CSV := $(abspath ../ip_lookup_cpu/src/data/prefix_table.csv)

sender:
	gcc -O2 -Wall -Wextra -I../ip_lookup_cpu/src \
		-o af_reinject \
		source.c ../ip_lookup_cpu/src/radix_trie_api.c \
		-lcrypto
	mv af_reinject /tmp/
	cp $(CSV) /tmp/prefix_table.csv
	sudo env PREFIX_CSV=/tmp/prefix_table.csv /tmp/af_reinject --mode source

receiver:
	gcc -O2 -Wall -Wextra -I../ip_lookup_cpu/src \
		-o af_reinject \
		source.c ../ip_lookup_cpu/src/radix_trie_api.c \
		-lcrypto
	mv af_reinject /tmp/
	cp $(CSV) /tmp/prefix_table.csv
	sudo env PREFIX_CSV=/tmp/prefix_table.csv /tmp/af_reinject --mode destip