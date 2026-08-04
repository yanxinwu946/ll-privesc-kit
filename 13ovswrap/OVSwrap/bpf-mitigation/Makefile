CLANG ?= clang
CC ?= cc
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr
ARCH ?= x86
MULTIARCH := $(shell $(CC) -print-multiarch 2>/dev/null)
LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf 2>/dev/null)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf 2>/dev/null || \
	echo '-lbpf -lelf -lz')

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -Wall -Wextra \
	-Wno-unused-parameter -I. $(if $(MULTIARCH),-I/usr/include/$(MULTIARCH)) \
	$(LIBBPF_CFLAGS)
LOADER_CFLAGS := -O2 -g -Wall -Wextra $(LIBBPF_CFLAGS)
LOADER_LIBS := $(LIBBPF_LIBS)

.PHONY: all clean install

all: ovswrap_guard.bpf.o ovswrap_guard

ovswrap_guard.bpf.o: ovswrap_guard.bpf.c ovswrap_guard.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

ovswrap_guard: ovswrap_guard.c ovswrap_guard.h
	$(CC) $(LOADER_CFLAGS) $< -o $@ $(LOADER_LIBS)

install: all
	install -D -m 0755 ovswrap_guard $(DESTDIR)$(PREFIX)/sbin/ovswrap_guard
	install -D -m 0644 ovswrap_guard.bpf.o $(DESTDIR)$(PREFIX)/lib/ovswrap-guard/ovswrap_guard.bpf.o

clean:
	rm -f ovswrap_guard ovswrap_guard.bpf.o
