CC      = clang
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lEndpointSecurity -lbsm -framework Foundation

SIGN_ID = Apple Development: Douglas Mun (PABRCU3Y4G)

TARGET  = file-monitor

.PHONY: all clean sign sign-adhoc run

all: $(TARGET)

$(TARGET): file-monitor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

sign: $(TARGET)
	codesign --force --sign "$(SIGN_ID)" \
	         --entitlements file-monitor.entitlements \
	         --timestamp \
	         $(TARGET)

sign-adhoc: $(TARGET)
	codesign --force --sign - \
	         --entitlements file-monitor.entitlements \
	         $(TARGET)

run: sign
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
