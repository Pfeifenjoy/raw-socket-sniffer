NAME := sniffer
BUILD := build
SRC := src
LIBS := $(shell pcap-config --libs)

all: build


create_build_directory:
	mkdir -p $(BUILD)

build: create_build_directory
	$(CC) ./$(SRC)/*.c -o ./$(BUILD)/$(NAME) $(LIBS)

run: build
	sudo ./$(BUILD)/$(NAME)

clean:
	rm -rf $(BUILD)

