CC      = clang
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lEndpointSecurity -lbsm -framework Foundation

SIGN_ID = Apple Development: Douglas Mun (PABRCU3Y4G)

TARGET  = dynamic-policy

.PHONY: all clean sign sign-adhoc run

all: $(TARGET)

$(TARGET): dynamic-policy.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

sign: $(TARGET)
	codesign --force --sign "$(SIGN_ID)" \
	         --entitlements dynamic-policy.entitlements \
	         --timestamp \
	         $(TARGET)

sign-adhoc: $(TARGET)
	codesign --force --sign - \
	         --entitlements dynamic-policy.entitlements \
	         $(TARGET)

run: sign
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
