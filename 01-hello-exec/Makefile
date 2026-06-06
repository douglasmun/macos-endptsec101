CC      = clang
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lEndpointSecurity -lbsm -framework Foundation

# Your signing identity from: security find-identity -v -p codesigning
SIGN_ID = Apple Development: Douglas Mun (PABRCU3Y4G)

TARGET  = hello-exec

.PHONY: all clean sign sign-adhoc run

all: $(TARGET)

$(TARGET): hello-exec.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Sign with entitlements (requires active provisioning profile with ES entitlement)
sign: $(TARGET)
	codesign --force --sign "$(SIGN_ID)" \
	         --entitlements hello-exec.entitlements \
	         --timestamp \
	         $(TARGET)

# Ad-hoc sign (no entitlement enforcement — only works with SIP disabled)
sign-adhoc: $(TARGET)
	codesign --force --sign - \
	         --entitlements hello-exec.entitlements \
	         $(TARGET)

run: sign
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
