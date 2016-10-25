NAME := sniffer
BUILD := build
SRC := src

build:
	mkdir $(BUILD)
	$(CC) ./$(SRC)/*.c -o ./$(BUILD)/$(NAME)

run: build
	sudo ./$(BUILD)/$(NAME)

clean:
	rm -rf $(BUILD)

all: build
