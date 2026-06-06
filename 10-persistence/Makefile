CC      = clang
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lEndpointSecurity -lbsm -framework Foundation

SIGN_ID = Apple Development: Douglas Mun (PABRCU3Y4G)

TARGET  = persistence

.PHONY: all clean sign sign-adhoc run

all: $(TARGET)

$(TARGET): persistence.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

sign: $(TARGET)
	codesign --force --sign "$(SIGN_ID)" \
	         --entitlements persistence.entitlements \
	         --timestamp \
	         $(TARGET)

sign-adhoc: $(TARGET)
	codesign --force --sign - \
	         --entitlements persistence.entitlements \
	         $(TARGET)

run: sign
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
