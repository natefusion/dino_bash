# https://github.com/clemedon/makefile_tutor
# https://makefiletutorial.com

OBJ_DIR := ./build
SRC_DIR := .

CC := gcc
SRCS := $(wildcard $(SRC_DIR)/*.c)

CFLAGS := -std=gnu11 -pipe -g -Wall -Werror -Wextra -Wmissing-prototypes
CPPFLAGS := -MMD -MP

OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

NAME := dino_bash
EXECUTABLE := $(OBJ_DIR)/$(NAME)

DIR_DUP = mkdir -p $(@D)

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJS)
	$(CC) $^ -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(DIR_DUP)
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

-include $(DEPS)

.PHONY: clean install uninstall

clean:
	rm -f $(EXECUTABLE) $(OBJS) $(DEPS)

install:
	cp $(RELEASE)/$(NAME) /bin/

uninstall:
	rm -f /bin/$(NAME)
