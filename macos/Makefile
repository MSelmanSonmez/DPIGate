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
	rm -rf $(BUILD)/DPIGate.app $(BUILD)/app
	rm -f $(BUILD)/test_dns $(TARGET) $(foreach a,$(ARCHS),$(BUILD)/dpigate-proxy-$(a) $(patsubst %.c,$(BUILD)/$(a)/%.o,$(SRC)))
	-rmdir $(foreach a,$(ARCHS),$(BUILD)/$(a)) $(BUILD) 2>/dev/null

$(BUILD)/test_dns: tests/test_dns.c $(SRCDIR)/dns_resolver.c $(SRCDIR)/dns_resolver.h
	@mkdir -p $(BUILD)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ tests/test_dns.c $(SRCDIR)/dns_resolver.c

# Menu bar app: build/DPIGate.app (universal Swift binary + script + proxy, ad-hoc signed).
# Separate from "all" because it needs swiftc (Command Line Tools are enough).
APP      := $(BUILD)/DPIGate.app
SWIFTSRC := app/main.swift

app: $(APP)/Contents/MacOS/DPIGate

$(APP)/Contents/MacOS/DPIGate: $(SWIFTSRC) app/Info.plist dpigate $(TARGET)
	@rm -rf $(APP)
	@mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources $(BUILD)/app
	swiftc -O -target x86_64-apple-macos11 -o $(BUILD)/app/DPIGate-x86_64 $(SWIFTSRC)
	swiftc -O -target arm64-apple-macos11 -o $(BUILD)/app/DPIGate-arm64 $(SWIFTSRC)
	lipo -create -output $@ $(BUILD)/app/DPIGate-x86_64 $(BUILD)/app/DPIGate-arm64
	cp app/Info.plist $(APP)/Contents/Info.plist
	cp dpigate $(APP)/Contents/Resources/dpigate
	cp $(TARGET) $(APP)/Contents/Resources/dpigate-proxy
	codesign --force --deep -s - $(APP)

test: $(BUILD)/test_dns app
	@$(BUILD)/test_dns
	@/bin/bash tests/test_dpigate.sh
	@/bin/bash tests/test_app.sh

.PHONY: all clean test app
