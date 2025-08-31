CC = gcc
WARNINGS= -Wall
DEBUG	= -ggdb -fno-omit-frame-pointer
OPTIMIZE= -O2
CFLAGS = $(WARNINGS) $(DEBUG) $(OPTIMIZE) -Wextra -std=c11 -fPIC
INCLUDES = -Iinclude

SRCDIR = src
OBJDIR = ../obj/data-encryption
INCDIR = include

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

TARGET = ../lib/libaesenc.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS) | ../lib
	ar rcs $@ $^
	ranlib $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR) ../lib:
	mkdir -p $@

clean:
	rm -rf $(OBJDIR) $(TARGET)
