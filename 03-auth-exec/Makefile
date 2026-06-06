CC      = clang
CFLAGS  = -Wall -Wextra -O2
LDFLAGS = -lEndpointSecurity -lbsm -framework Foundation

SIGN_ID = Apple Development: Douglas Mun (PABRCU3Y4G)

TARGET  = auth-exec

.PHONY: all clean sign sign-adhoc run

all: $(TARGET)

$(TARGET): auth-exec.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

sign: $(TARGET)
	codesign --force --sign "$(SIGN_ID)" \
	         --entitlements auth-exec.entitlements \
	         --timestamp \
	         $(TARGET)

sign-adhoc: $(TARGET)
	codesign --force --sign - \
	         --entitlements auth-exec.entitlements \
	         $(TARGET)

run: sign
	sudo ./$(TARGET)

clean:
	rm -f $(TARGET)
