include ../config.mk

PROJECT_ROOT = ..

INCLUDES = -Iinclude

SRCDIR = src
OBJDIR = $(PROJECT_ROOT)/obj/data-encryption
INCDIR = include

SOURCES = $(wildcard $(SRCDIR)/*.c)
# Substitution reference syntax: $(variable:pattern=replacement)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

TARGET = $(PROJECT_ROOT)/lib/libaesenc.a

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS) | $(PROJECT_ROOT)/lib
	ar rcs $@ $^
	ranlib $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(OBJDIR) $(PROJECT_ROOT)/lib:
	mkdir -p $@

clean:
	rm -rf $(OBJDIR) $(TARGET)
