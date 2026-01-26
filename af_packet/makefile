CFLAGS := -O2 -Wall -Wextra -I../ip_lookup_cpu/src
CSV := $(abspath ../ip_lookup_cpu/src/data/prefix_table.csv)
BIN_DIR := /tmp

SRC := source.c
TRIE := ../ip_lookup_cpu/src/radix_trie_api.c

# Interfaces for our setup
RX_IFACE := ifb0
TX_IFACE := enp175s0f0np0
TUN_IFACE := auth0

# Host IPs
BODHI_IP := 192.168.100.1
BANYAN_IP := 192.168.100.2

.PHONY: build_bodhi build_banyan install_csv run_source_bodhi run_dest_bodhi run_both_bodhi \
        run_source_banyan run_dest_banyan run_both_banyan clean_tmp

install_csv:
	cp $(CSV) $(BIN_DIR)/prefix_table.csv

build_bodhi:
	gcc $(CFLAGS) -DLOCAL_IP="\"$(BODHI_IP)\"" \
		-o $(BIN_DIR)/af_reinject_bodhi \
		$(SRC) $(TRIE) -lcrypto

build_banyan:
	gcc $(CFLAGS) -DLOCAL_IP="\"$(BANYAN_IP)\"" \
		-o $(BIN_DIR)/af_reinject_banyan \
		$(SRC) $(TRIE) -lcrypto

run_source_bodhi: build_bodhi install_csv
	sudo env PREFIX_CSV=$(BIN_DIR)/prefix_table.csv \
		RX_IFACE=$(RX_IFACE) TX_IFACE=$(TX_IFACE) TUN_IFACE=$(TUN_IFACE) \
		$(BIN_DIR)/af_reinject_bodhi --mode source

run_dest_bodhi: build_bodhi install_csv
	sudo env PREFIX_CSV=$(BIN_DIR)/prefix_table.csv \
		RX_IFACE=$(RX_IFACE) TX_IFACE=$(TX_IFACE) TUN_IFACE=$(TUN_IFACE) \
		$(BIN_DIR)/af_reinject_bodhi --mode dest

run_both_bodhi: build_bodhi install_csv
	@echo "Starting bodhi dest + source in background..."
	sudo env PREFIX_CSV=$(BIN_DIR)/prefix_table.csv \
		RX_IFACE=$(RX_IFACE) TX_IFACE=$(TX_IFACE) TUN_IFACE=$(TUN_IFACE) \
		$(BIN_DIR)/af_reinject_bodhi --mode dest >$(BIN_DIR)/dest_bodhi.log 2>&1 &
	sudo env PREFIX_CSV=$(BIN_DIR)/prefix_table.csv \
		RX_IFACE=$(RX_IFACE) TX_IFACE=$(TX_IFACE) TUN_IFACE=$(TUN_IFACE) \
		$(BIN_DIR)/af_reinject_bodhi --mode source >$(BIN_DIR)/source_bodhi.log 2>&1 &
	@echo "Logs: $(BIN_DIR)/dest_bodhi.log and $(BIN_DIR)/source_bodhi.log"

run_source_banyan: build_banyan install_csv
	sudo env PREFIX_CSV=$(BIN_DIR)/prefix_table.csv \
		RX_IFACE=$(RX_IFACE) TX_IFACE=$(TX_IFACE) TUN_IFACE=$(TUN_IFACE) \
		$(BIN_DIR)/af_reinject_banyan --mode source

run_dest_banyan: build_banyan install_csv
	sudo env PREFIX_CSV=$(BIN_DIR)/prefix_table.csv \
		RX_IFACE=$(RX_IFACE) TX_IFACE=$(TX_IFACE) TUN_IFACE=$(TUN_IFACE) \
		$(BIN_DIR)/af_reinject_banyan --mode dest

run_both_banyan: build_banyan install_csv
	@echo "Starting banyan dest + source in background..."
	sudo env PREFIX_CSV=$(BIN_DIR)/prefix_table.csv \
		RX_IFACE=$(RX_IFACE) TX_IFACE=$(TX_IFACE) TUN_IFACE=$(TUN_IFACE) \
		$(BIN_DIR)/af_reinject_banyan --mode dest >$(BIN_DIR)/dest_banyan.log 2>&1 &
	sudo env PREFIX_CSV=$(BIN_DIR)/prefix_table.csv \
		RX_IFACE=$(RX_IFACE) TX_IFACE=$(TX_IFACE) TUN_IFACE=$(TUN_IFACE) \
		$(BIN_DIR)/af_reinject_banyan --mode source >$(BIN_DIR)/source_banyan.log 2>&1 &
	@echo "Logs: $(BIN_DIR)/dest_banyan.log and $(BIN_DIR)/source_banyan.log"

clean_tmp:
	rm -f $(BIN_DIR)/af_reinject_bodhi $(BIN_DIR)/af_reinject_banyan \
	      $(BIN_DIR)/prefix_table.csv \
	      $(BIN_DIR)/dest_bodhi.log $(BIN_DIR)/source_bodhi.log \
	      $(BIN_DIR)/dest_banyan.log $(BIN_DIR)/source_banyan.log
