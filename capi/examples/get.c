/* snmpify_get HOST[:PORT] COMMUNITY OID...   (SNMPv2c GetRequest)
 * With the standard MIBs, names work too: snmpify_get host public sysName.0 */
#include <stdio.h>

#include "snmpify.h"

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s HOST[:PORT] COMMUNITY OID...\n", argv[0]);
        return 2;
    }
    snmpify_mib *mib = snmpify_mib_standard();
    char oids[64][256];
    const char *ptrs[64];
    size_t n = 0;
    for (int i = 3; i < argc && n < 64; i++, n++) {
        if (snmpify_mib_resolve(mib, argv[i], oids[n], sizeof oids[n]) == 0) {
            fprintf(stderr, "%s: %s\n", argv[i], snmpify_last_error());
            return 1;
        }
        ptrs[n] = oids[n];
    }
    snmpify_client *c = snmpify_client_new(argv[1], argv[2], 2);
    if (!c) {
        fprintf(stderr, "%s\n", snmpify_last_error());
        return 1;
    }
    snmpify_result *r;
    if (snmpify_get(c, ptrs, n, &r) != SNMPIFY_OK) {
        fprintf(stderr, "%s\n", snmpify_last_error());
        return 1;
    }
    char line[1024];
    for (size_t i = 0; i < snmpify_result_len(r); i++) {
        snmpify_mib_format(mib, r, i, line, sizeof line);
        printf("%s\n", line);
    }
    snmpify_result_free(r);
    snmpify_client_free(c);
    snmpify_mib_free(mib);
    return 0;
}
