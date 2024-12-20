CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g

TARGET = main

SRCS = main.c hpt.c
BUILD_DIR = build
OBJS = $(BUILD_DIR)/main.o $(BUILD_DIR)/hpt.o

HEADERS = hpt_common.h hpt.h

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: %.c $(HEADERS)
	mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(TARGET)
