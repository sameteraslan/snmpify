/* The C API against an agent made with the C API (and net-snmp's snmpd
 * when SNMPIFY_AGENT is set). Exits non-zero on the first failure. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "snmpify.h"

static int failures = 0;
#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            fprintf(stderr, "%s:%d: CHECK(%s) failed: %s\n", __FILE__, __LINE__, \
                    #cond, snmpify_last_error());                                \
            failures++;                                                          \
        }                                                                        \
    } while (0)

static int reads = 0;
static int counter_cb(void *ctx, snmpify_value *out) {
    (void)ctx;
    out->type = SNMPIFY_GAUGE32;
    out->uinteger = (uint64_t)++reads;
    return 0;
}

static snmpify_varbind vb_str(const char *oid, const char *s) {
    snmpify_varbind vb;
    memset(&vb, 0, sizeof vb);
    vb.oid = oid;
    vb.value.type = SNMPIFY_OCTET_STRING;
    vb.value.bytes = (const uint8_t *)s;
    vb.value.len = strlen(s);
    return vb;
}

int main(void) {
    printf("snmpify %s\n", snmpify_version());
    snmpify_user *alice = snmpify_user_new("alice", "SHA-256", "alice-auth", "AES", "alice-priv");
    CHECK(alice != NULL);
    CHECK(snmpify_user_new("x", "SHA-999", "password", NULL, NULL) == NULL);
    CHECK(strstr(snmpify_last_error(), "SHA-999") != NULL);

    /* An agent. */
    snmpify_agent *a = snmpify_agent_new("127.0.0.1:0");
    CHECK(a != NULL);
    CHECK(snmpify_agent_add_community(a, "public", 0) == SNMPIFY_OK);
    CHECK(snmpify_agent_add_community(a, "private", 1) == SNMPIFY_OK);
    CHECK(snmpify_agent_add_user(a, alice, 1) == SNMPIFY_OK);
    snmpify_varbind name = vb_str("1.3.6.1.2.1.1.5.0", "c-agent");
    CHECK(snmpify_agent_set(a, &name, 0) == SNMPIFY_OK);
    snmpify_varbind w = vb_str("1.3.6.1.4.1.99999.1.0", "before");
    CHECK(snmpify_agent_set(a, &w, 1) == SNMPIFY_OK);
    char oid[64];
    for (int i = 1; i <= 20; i++) {
        snmpify_varbind row;
        memset(&row, 0, sizeof row);
        snprintf(oid, sizeof oid, "1.3.6.1.4.1.99999.2.%d", i);
        row.oid = oid;
        row.value.type = SNMPIFY_COUNTER64;
        row.value.uinteger = (uint64_t)i << 40;
        CHECK(snmpify_agent_set(a, &row, 0) == SNMPIFY_OK);
    }
    CHECK(snmpify_agent_set_callback(a, "1.3.6.1.4.1.99999.3.0", counter_cb, NULL) == SNMPIFY_OK);
    CHECK(snmpify_agent_start(a) == SNMPIFY_OK);
    CHECK(snmpify_agent_start(a) == SNMPIFY_ERR_INVALID_ARGUMENT);
    const char *addr = snmpify_agent_address(a);

    /* v2c client. */
    snmpify_client *c = snmpify_client_new(addr, "public", 2);
    CHECK(c != NULL);
    CHECK(snmpify_client_set_options(c, 300, 1, 7) == SNMPIFY_OK);
    const char *oids[] = {"1.3.6.1.2.1.1.5.0", "1.3.6.1.4.1.99999.2.3", "1.3.6.1.4.1.99999.9.0"};
    snmpify_result *r = NULL;
    CHECK(snmpify_get(c, oids, 3, &r) == SNMPIFY_OK);
    CHECK(snmpify_result_len(r) == 3);
    size_t len = 0;
    const uint8_t *b = snmpify_result_bytes(r, 0, &len);
    CHECK(len == 7 && memcmp(b, "c-agent", 7) == 0);
    CHECK(strcmp(snmpify_result_text(r, 0), "c-agent") == 0);
    CHECK(snmpify_result_type(r, 1) == SNMPIFY_COUNTER64);
    CHECK(snmpify_result_uint(r, 1) == (3ull << 40));
    CHECK(snmpify_result_type(r, 2) == SNMPIFY_NO_SUCH_OBJECT);
    CHECK(strcmp(snmpify_result_oid(r, 2), "1.3.6.1.4.1.99999.9.0") == 0);
    CHECK(snmpify_result_oid(r, 3) == NULL);
    snmpify_result_free(r);

    CHECK(snmpify_walk_all(c, "1.3.6.1.4.1.99999.2", &r) == SNMPIFY_OK);
    CHECK(snmpify_result_len(r) == 20);
    snmpify_result_free(r);
    snmpify_walk *wk = snmpify_walk_new(c, "1.3.6.1.4.1.99999.2");
    int n = 0;
    while (snmpify_walk_next(wk, &r) == SNMPIFY_OK) {
        n++;
        snmpify_result_free(r);
    }
    CHECK(n == 20);
    snmpify_walk_free(wk);
    const char *start[] = {"1.3.6.1.4.1.99999.2.18"};
    CHECK(snmpify_get_bulk(c, start, 1, 0, 5, &r) == SNMPIFY_OK);
    CHECK(snmpify_result_len(r) == 4); /* .19, .20, .3.0, endOfMibView */
    CHECK(snmpify_result_type(r, 3) == SNMPIFY_END_OF_MIB_VIEW);
    snmpify_result_free(r);
    const char *g[] = {"1.3.6.1.4.1.99999.3.0"};
    CHECK(snmpify_get(c, g, 1, &r) == SNMPIFY_OK);
    CHECK(snmpify_result_type(r, 0) == SNMPIFY_GAUGE32 && snmpify_result_uint(r, 0) >= 1);
    snmpify_result_free(r);
    CHECK(snmpify_get_next(c, g, 1, &r) == SNMPIFY_OK);
    snmpify_result_free(r);

    /* Errors. */
    snmpify_varbind nw = vb_str("1.3.6.1.4.1.99999.1.0", "nope");
    CHECK(snmpify_set(c, &nw, 1, NULL) == SNMPIFY_ERR_AGENT);
    CHECK(strcmp(snmpify_error_status_name(snmpify_last_error_status()), "noAccess") == 0);
    CHECK(snmpify_last_error_index() == 1);
    const char *bad[] = {"1.x"};
    CHECK(snmpify_get(c, bad, 1, &r) == SNMPIFY_ERR_INVALID_ARGUMENT);
    CHECK(snmpify_get(NULL, oids, 1, &r) == SNMPIFY_ERR_INVALID_ARGUMENT);
    snmpify_client *wrong = snmpify_client_new(addr, "nope", 2);
    snmpify_client_set_options(wrong, 100, 0, 10);
    CHECK(snmpify_get(wrong, oids, 1, &r) == SNMPIFY_ERR_TIMEOUT);
    snmpify_client_free(wrong);
    CHECK(snmpify_client_new(addr, "public", 3) == NULL);

    /* Sets with the write community and with SNMPv3. */
    snmpify_client *rw = snmpify_client_new(addr, "private", 2);
    snmpify_varbind after = vb_str("1.3.6.1.4.1.99999.1.0", "after");
    CHECK(snmpify_set(rw, &after, 1, NULL) == SNMPIFY_OK);
    CHECK(snmpify_agent_get(a, "1.3.6.1.4.1.99999.1.0", &r) == SNMPIFY_OK);
    CHECK(strcmp(snmpify_result_text(r, 0), "after") == 0);
    snmpify_result_free(r);
    snmpify_client *v3 = snmpify_client_new_v3(addr, alice, NULL);
    snmpify_varbind byv3 = vb_str("1.3.6.1.4.1.99999.1.0", "v3");
    CHECK(snmpify_set(v3, &byv3, 1, &r) == SNMPIFY_OK);
    snmpify_result_free(r);
    snmpify_user *wrongpw = snmpify_user_new("alice", "SHA-256", "not-alice", NULL, NULL);
    snmpify_client *bad3 = snmpify_client_new_v3(addr, wrongpw, NULL);
    CHECK(snmpify_get(bad3, oids, 1, &r) == SNMPIFY_ERR_REPORT);
    CHECK(strstr(snmpify_last_error(), "wrong digest") != NULL);

    /* MIBs. */
    snmpify_mib *m = snmpify_mib_standard();
    char buf[128];
    CHECK(snmpify_mib_resolve(m, "IF-MIB::ifDescr.3", buf, sizeof buf) > 0);
    CHECK(strcmp(buf, "1.3.6.1.2.1.2.2.1.2.3") == 0);
    CHECK(snmpify_mib_resolve(m, "nothing", buf, sizeof buf) == 0);
    CHECK(snmpify_mib_name(m, "1.3.6.1.2.1.1.5.0", buf, sizeof buf) == strlen("SNMPv2-MIB::sysName.0") + 1);
    CHECK(strcmp(buf, "SNMPv2-MIB::sysName.0") == 0);
    CHECK(snmpify_mib_name(m, "1.3.6.1.2.1.1.5.0", buf, 6) > 6 && strlen(buf) == 5);
    CHECK(snmpify_get(c, oids, 1, &r) == SNMPIFY_OK);
    CHECK(snmpify_mib_format(m, r, 0, buf, sizeof buf) > 0);
    CHECK(strcmp(buf, "SNMPv2-MIB::sysName.0 = c-agent") == 0);
    snmpify_result_free(r);

    /* Traps and informs. */
    const char *comms[] = {"public"};
    const snmpify_user *users[] = {alice};
    snmpify_receiver *rx = snmpify_receiver_new("127.0.0.1:0", comms, 1, users, 1);
    CHECK(rx != NULL);
    snmpify_client *tc = snmpify_client_new(snmpify_receiver_address(rx), "public", 2);
    snmpify_varbind tv = vb_str("1.3.6.1.2.1.1.5.0", "alarm");
    CHECK(snmpify_trap(tc, "1.3.6.1.6.3.1.1.5.3", &tv, 1) == SNMPIFY_OK);
    snmpify_notification *note = NULL;
    CHECK(snmpify_receiver_recv(rx, 2000, &note) == SNMPIFY_OK);
    CHECK(strcmp(snmpify_notification_kind(note), "trap") == 0);
    CHECK(strcmp(snmpify_notification_trap_oid(note), "1.3.6.1.6.3.1.1.5.3") == 0);
    CHECK(strcmp(snmpify_notification_sender(note), "public") == 0);
    CHECK(snmpify_notification_version(note) == 2);
    CHECK(snmpify_result_len(snmpify_notification_varbinds(note)) == 1);
    snmpify_notification_free(note);
    CHECK(snmpify_receiver_recv(rx, 50, &note) == SNMPIFY_ERR_TIMEOUT);
    snmpify_client *t3 = snmpify_client_new_v3(snmpify_receiver_address(rx), alice, NULL);
    CHECK(snmpify_trap(t3, "1.3.6.1.6.3.1.1.5.4", NULL, 0) == SNMPIFY_OK);
    CHECK(snmpify_receiver_recv(rx, 2000, &note) == SNMPIFY_OK);
    CHECK(snmpify_notification_version(note) == 3);
    CHECK(strcmp(snmpify_notification_sender(note), "alice") == 0);
    snmpify_notification_free(note);

    /* net-snmp, when available. */
    const char *netsnmp = getenv("SNMPIFY_AGENT");
    if (netsnmp) {
        snmpify_client *ns = snmpify_client_new(netsnmp, "public", 2);
        CHECK(snmpify_get(ns, oids, 1, &r) == SNMPIFY_OK);
        CHECK(strcmp(snmpify_result_text(r, 0), "snmpify-agent") == 0);
        snmpify_result_free(r);
        CHECK(snmpify_walk_all(ns, "1.3.6.1.2.1.2.2", &r) == SNMPIFY_OK);
        CHECK(snmpify_result_len(r) > 10);
        snmpify_result_free(r);
        snmpify_user *u = snmpify_user_new("sha_des", "SHA", "auth-sha_des", "DES", "priv-sha_des");
        snmpify_client *ns3 = snmpify_client_new_v3(netsnmp, u, NULL);
        CHECK(snmpify_get(ns3, oids, 1, &r) == SNMPIFY_OK);
        snmpify_result_free(r);
        snmpify_client_free(ns3);
        snmpify_user_free(u);
        snmpify_client_free(ns);
        printf("net-snmp: ok\n");
    }

    snmpify_client_free(t3);
    snmpify_client_free(tc);
    snmpify_receiver_free(rx);
    snmpify_mib_free(m);
    snmpify_client_free(bad3);
    snmpify_user_free(wrongpw);
    snmpify_client_free(v3);
    snmpify_client_free(rw);
    snmpify_client_free(c);
    snmpify_agent_free(a);
    snmpify_user_free(alice);
    /* NULL is fine everywhere. */
    snmpify_client_free(NULL);
    snmpify_result_free(NULL);
    snmpify_agent_free(NULL);
    if (failures) {
        fprintf(stderr, "%d failure(s)\n", failures);
        return 1;
    }
    printf("C API: all checks passed\n");
    return 0;
}
