# linux/Makefile — GoodByeDPI-Plus Linux port
#
# Build:    make
# Drift:   make check-sync
# Sync:    make sync
# Clean:   make clean
#
# Dependencies (runtime): libnetfilter_queue, libnfnetlink, libmnl
#   Arch:       pacman -S libnetfilter_queue
#   Debian/Ubuntu: apt install libnetfilter-queue-dev libnfnetlink-dev libmnl-dev
#   Fedora:     dnf install libnetfilter_queue-devel

TARGET  = goodbyedpi
CC     ?= cc
PKGS       = libnetfilter_queue libmnl libnfnetlink
PKG_CFLAGS = $(shell pkg-config --cflags $(PKGS) 2>/dev/null)
PKG_LIBS   = $(shell pkg-config --libs   $(PKGS) 2>/dev/null)
CFLAGS  += -std=gnu99 -O2 -Wall -Wextra -Wpedantic -fPIE \
          -D_DEFAULT_SOURCE -D_FORTIFY_SOURCE=2 -fstack-protector $(PKG_CFLAGS)
LDFLAGS += -pie
LIBS     = $(if $(PKG_LIBS),$(PKG_LIBS),-lnetfilter_queue -lnfnetlink -lmnl) -lpthread -ldl

# Source files — linux/ only, no dependency on windows/
# Phase 0-4: utils + packet_io + checksum + rawsend + proctrack
SRCS    = utils/repl_str.c packet_io_linux.c checksum.c rawsend_linux.c proctrack_linux.c

# Phase 5: bypass sources (COPY+MODIFY) — ported WinDivert -> Linux
BYPASS_SRCS = fakepackets.c dnsredir.c ttltrack.c blackwhitelist.c
BYPASS_OBJS = $(BYPASS_SRCS:.c=.o)

# Phase 5+: bypass + main loop
SRCS += $(BYPASS_SRCS) goodbyedpi.c

OBJS    = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

# Smoke test — NFQUEUE passthrough
smoke_test: smoke_test.o packet_io_linux.o rawsend_linux.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

# Checksum unit test — RFC 1071 + parse_packet
checksum_test: checksum_test.o checksum.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

# Raw socket test — fake packet injection
rawsend_test: rawsend_test.o rawsend_linux.o checksum.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

# Proctrack unit test — /proc/net/tcp parse + inode cache + match_pid
proctrack_test: proctrack_test.o proctrack_linux.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

# Bypass unit test — fakepackets + dnsredir + ttltrack + blackwhitelist logic tests
bypass_test: bypass_test.o $(BYPASS_OBJS) checksum.o packet_io_linux.o rawsend_linux.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# Drift detection (Bolum 4.1)
check-sync:
	@./scripts/check-sync.sh

sync:
	@./scripts/sync-from-src.sh

# Settings persistence + password-dialog-cancel regression suite.
# Needs a built binary and no running daemon; refuses to run otherwise.
settings-test: $(TARGET)
	@./scripts/settings-test.sh

clean:
	rm -f $(OBJS) $(BYPASS_OBJS) $(TARGET) smoke_test.o smoke_test checksum_test.o checksum_test rawsend_test.o rawsend_test proctrack_test.o proctrack_test bypass_test.o bypass_test

.PHONY: check-sync sync settings-test clean smoke_test checksum_test rawsend_test proctrack_test bypass_compile bypass_test
