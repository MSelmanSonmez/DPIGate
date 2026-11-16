# Builds a universal (x86_64 + arm64) ByeDPI SOCKS5 proxy for macOS.
SRCDIR   := byedpi
BUILD    := build
SRC      := packets.c main.c conev.c proxy.c desync.c mpool.c extend.c dns_resolver.c
HEADERS  := $(wildcard $(SRCDIR)/*.h)
ARCHS    := x86_64 arm64
CPPFLAGS := -D_DEFAULT_SOURCE
CFLAGS   := -I$(SRCDIR) -std=c99 -O2 -Wall -Wno-unused -Wextra -Wno-unused-parameter -pedantic -mmacosx-version-min=11.0
TARGET   := $(BUILD)/dpigate-proxy

all: $(TARGET)

define ARCH_RULES
$(BUILD)/$(1)/%.o: $(SRCDIR)/%.c $(HEADERS)
	@mkdir -p $$(dir $$@)
	$$(CC) -arch $(1) $$(CPPFLAGS) $$(CFLAGS) -c $$< -o $$@
$(BUILD)/dpigate-proxy-$(1): $(patsubst %.c,$(BUILD)/$(1)/%.o,$(SRC))
	$$(CC) -arch $(1) -mmacosx-version-min=11.0 -o $$@ $$^
endef
$(foreach a,$(ARCHS),$(eval $(call ARCH_RULES,$(a))))

$(TARGET): $(foreach a,$(ARCHS),$(BUILD)/dpigate-proxy-$(a))
	lipo -create -output $@ $^
	codesign --force -s - $@

clean:
	rm -f $(BUILD)/test_dns $(TARGET) $(foreach a,$(ARCHS),$(BUILD)/dpigate-proxy-$(a) $(patsubst %.c,$(BUILD)/$(a)/%.o,$(SRC)))
	-rmdir $(foreach a,$(ARCHS),$(BUILD)/$(a)) $(BUILD) 2>/dev/null

test: $(BUILD)/test_dns
	@$(BUILD)/test_dns
	@/bin/bash tests/test_dpigate.sh

$(BUILD)/test_dns: tests/test_dns.c $(SRCDIR)/dns_resolver.c $(SRCDIR)/dns_resolver.h
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_dns.c $(SRCDIR)/dns_resolver.c

.PHONY: all clean test
