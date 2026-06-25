/*
 * ids-poc.c — triggers ch07 IDS RULE 2 (unsigned-then-connect).
 *
 * ES only delivers NOTIFY_UIPC_CONNECT for AF_UNIX (Unix-domain) sockets, NOT
 * for AF_INET — so the POC writes /tmp, then connects to a Unix-domain socket
 * (mDNSResponder, always present). Build UNSIGNED and run while 07-ids monitors.
 * Harmless: one marker file + one local Unix-socket connect.
 */
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(void) {
    FILE *f = fopen("/tmp/ids-marker", "w");
    if (f) { fputs("x", f); fclose(f); }

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s >= 0) {
        struct sockaddr_un a;
        memset(&a, 0, sizeof(a));
        a.sun_family = AF_UNIX;
        strncpy(a.sun_path, "/var/run/mDNSResponder", sizeof(a.sun_path) - 1);
        connect(s, (struct sockaddr *)&a, sizeof(a));
        close(s);
    }
    printf("ids-poc: wrote /tmp/ids-marker and connected to a Unix socket\n");
    return 0;
}
