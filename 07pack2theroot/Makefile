CC      ?= gcc
CFLAGS  = -Wall -O2 -static
TARGET  = cve-2026-41651
SRC     = src/cve-2026-41651.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET) /tmp/.skp-dummy-*.deb /tmp/.skp-payload-*.deb /var/tmp/.suid_bash

.PHONY: all clean
