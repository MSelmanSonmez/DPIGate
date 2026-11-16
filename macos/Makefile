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
	rm -rf $(BUILD)/DPIGate.app $(BUILD)/app $(BUILD)/dist $(BUILD)/DPIGate-macos.zip
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

ICON     := ../docs/icon.png

$(APP)/Contents/MacOS/DPIGate: $(SWIFTSRC) app/Info.plist dpigate $(TARGET) $(ICON)
	@rm -rf $(APP)
	@mkdir -p $(APP)/Contents/MacOS $(APP)/Contents/Resources $(BUILD)/app
	swiftc -O -target x86_64-apple-macos11 -o $(BUILD)/app/DPIGate-x86_64 $(SWIFTSRC)
	swiftc -O -target arm64-apple-macos11 -o $(BUILD)/app/DPIGate-arm64 $(SWIFTSRC)
	lipo -create -output $@ $(BUILD)/app/DPIGate-x86_64 $(BUILD)/app/DPIGate-arm64
	cp app/Info.plist $(APP)/Contents/Info.plist
	cp dpigate $(APP)/Contents/Resources/dpigate
	cp $(TARGET) $(APP)/Contents/Resources/dpigate-proxy
	sips -z 18 18 $(ICON) --out $(APP)/Contents/Resources/menubar.png >/dev/null
	sips -z 36 36 $(ICON) --out $(APP)/Contents/Resources/menubar@2x.png >/dev/null
	@mkdir -p $(BUILD)/app/AppIcon.iconset
	@for spec in 16:16x16 32:16x16@2x 32:32x32 64:32x32@2x 128:128x128 256:128x128@2x 256:256x256; do \
	  sips -z $${spec%%:*} $${spec%%:*} $(ICON) --out $(BUILD)/app/AppIcon.iconset/icon_$${spec#*:}.png >/dev/null || exit 1; done
	iconutil -c icns -o $(APP)/Contents/Resources/AppIcon.icns $(BUILD)/app/AppIcon.iconset
	codesign --force --deep -s - $(APP)

# Release zip: DPIGate-macos/{DPIGate.app,install.sh,uninstall.sh}.
DIST     := $(BUILD)/DPIGate-macos.zip

dist: app
	@rm -rf $(BUILD)/dist $(DIST)
	@mkdir -p $(BUILD)/dist/DPIGate-macos
	ditto $(APP) $(BUILD)/dist/DPIGate-macos/DPIGate.app
	cp install.sh uninstall.sh $(BUILD)/dist/DPIGate-macos/
	chmod +x $(BUILD)/dist/DPIGate-macos/install.sh $(BUILD)/dist/DPIGate-macos/uninstall.sh
	cd $(BUILD)/dist && ditto -c -k --norsrc --noextattr --keepParent DPIGate-macos ../DPIGate-macos.zip
	@rm -rf $(BUILD)/dist

test: $(BUILD)/test_dns app
	@$(BUILD)/test_dns
	@/bin/bash tests/test_dpigate.sh
	@/bin/bash tests/test_app.sh
	@/bin/bash tests/test_app_menu.sh
	@/bin/bash tests/test_install.sh

.PHONY: all clean test app dist
