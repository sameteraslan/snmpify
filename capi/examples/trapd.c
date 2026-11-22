/* snmpify_trapd [ADDRESS] [COMMUNITY]   (prints traps and informs) */
#include <stdio.h>

#include "snmpify.h"

int main(int argc, char **argv) {
    const char *address = argc > 1 ? argv[1] : "0.0.0.0:162";
    const char *community = argc > 2 ? argv[2] : "public";
    snmpify_receiver *rx = snmpify_receiver_new(address, &community, 1, NULL, 0);
    if (!rx) {
        fprintf(stderr, "%s\n", snmpify_last_error());
        return 1;
    }
    printf("listening on %s\n", snmpify_receiver_address(rx));
    for (;;) {
        snmpify_notification *n;
        if (snmpify_receiver_recv(rx, 0, &n) != SNMPIFY_OK) {
            fprintf(stderr, "%s\n", snmpify_last_error());
            break;
        }
        const snmpify_result *vbs = snmpify_notification_varbinds(n);
        printf("%s v%d from %s: %s\n", snmpify_notification_kind(n), snmpify_notification_version(n),
               snmpify_notification_source(n), snmpify_notification_trap_oid(n));
        for (size_t i = 0; i < snmpify_result_len(vbs); i++) {
            printf("  %s = %s\n", snmpify_result_oid(vbs, i), snmpify_result_text(vbs, i));
        }
        snmpify_notification_free(n);
    }
    snmpify_receiver_free(rx);
    return 0;
}
