.PHONY: build

SHELL := /bin/bash
ESPFLASHVERSION = $(shell expr `cargo espflash -V | grep ^cargo-espflash | sed 's/^.* //g' | cut -f1 -d. ` \< 2)

cargo-ver:
ifeq "$(ESPFLASHVERSION)" "1"
		$(error Update espfash to version >2.0. Update with cargo install cargo-espflash@2.0.0-rc.1)
endif

build:
	cargo build --release

upload: cargo-ver
	cargo espflash flash --monitor --partition-table partitions.csv --baud 460800 -f 80M --use-stub --release $(ESPFLASH_FLASH_ARGS)


build-esp32-bin:
	cargo espflash save-image --merge --chip esp32 target/esp32-server.bin --partition-table partitions.csv -s 4M  --release

flash-esp32-bin:
ifneq (,$(wildcard target/esp32-server.bin))
	espflash write-bin 0x0 target/esp32-server.bin -b 460800  && sleep 2 && espflash monitor
else
	$(error esp32-server.bin not found, run build-esp32-bin first)
endif
