/* net-snmp's C library (libnetsnmp): the reference implementation.
 *   bench_netsnmp walk|walk3|get|getnext|bulk|set|trap|inform|poll HOST PORT N
 * Walks: GetBulk loops (max-repetitions 25) with the synchronous API;
 * polling: the asynchronous API (one session per agent, select loop). */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static double now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + t.tv_nsec / 1e6;
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static void report(int items, double ms, double *lat, int n) {
    double p50 = 0, p99 = 0;
    if (n > 0) {
        qsort(lat, n, sizeof(double), cmp);
        p50 = lat[(int)((n - 1) * 0.50 + 0.5)];
        p99 = lat[(int)((n - 1) * 0.99 + 0.5)];
    }
    printf("{\"items\": %d, \"ms\": %.3f, \"p50_us\": %.1f, \"p99_us\": %.1f}\n", items, ms, p50, p99);
}

static netsnmp_session *open_session(const char *peer, int v3) {
    netsnmp_session s;
    snmp_sess_init(&s);
    s.peername = strdup(peer);
    s.timeout = 1000000;
    s.retries = 2;
    if (!v3) {
        s.version = SNMP_VERSION_2c;
        s.community = (u_char *)"public";
        s.community_len = 6;
    } else {
        s.version = SNMP_VERSION_3;
        s.securityName = strdup("bench");
        s.securityNameLen = 5;
        s.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
        s.securityAuthProto = usmHMACSHA1AuthProtocol;
        s.securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
        s.securityAuthKeyLen = USM_AUTH_KU_LEN;
        generate_Ku(s.securityAuthProto, s.securityAuthProtoLen, (u_char *)"bench-auth-pass", 15,
                    s.securityAuthKey, &s.securityAuthKeyLen);
        s.securityPrivProto = usmAESPrivProtocol;
        s.securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
        s.securityPrivKeyLen = USM_PRIV_KU_LEN;
        generate_Ku(s.securityAuthProto, s.securityAuthProtoLen, (u_char *)"bench-priv-pass", 15,
                    s.securityPrivKey, &s.securityPrivKeyLen);
    }
    netsnmp_session *ss = snmp_open(&s);
    if (!ss) {
        snmp_perror("snmp_open");
        exit(1);
    }
    return ss;
}

static int walk(netsnmp_session *ss) {
    oid root[MAX_OID_LEN], cur[MAX_OID_LEN];
    size_t root_len = MAX_OID_LEN;
    read_objid("1.3.6.1.4.1.99999.1", root, &root_len);
    memcpy(cur, root, root_len * sizeof(oid));
    size_t cur_len = root_len;
    int n = 0;
    for (;;) {
        netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GETBULK), *resp = NULL;
        pdu->non_repeaters = 0;
        pdu->max_repetitions = 25;
        snmp_add_null_var(pdu, cur, cur_len);
        if (snmp_synch_response(ss, pdu, &resp) != STAT_SUCCESS || !resp || resp->errstat) {
            fprintf(stderr, "walk failed\n");
            exit(1);
        }
        int done = 0, got = 0;
        for (netsnmp_variable_list *v = resp->variables; v; v = v->next_variable) {
            if (v->type == SNMP_ENDOFMIBVIEW || v->name_length < root_len ||
                memcmp(v->name, root, root_len * sizeof(oid)) != 0) {
                done = 1;
                break;
            }
            memcpy(cur, v->name, v->name_length * sizeof(oid));
            cur_len = v->name_length;
            n++;
            got = 1;
        }
        snmp_free_pdu(resp);
        if (done || !got) return n;
    }
}

static int pending = 0, ok = 0;
static int on_response(int op, netsnmp_session *s, int reqid, netsnmp_pdu *pdu, void *magic) {
    (void)s, (void)reqid, (void)magic;
    if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE && pdu->errstat == SNMP_ERR_NOERROR) ok++;
    pending--;
    return 1;
}

int main(int argc, char **argv) {
    if (argc < 5) {
        fprintf(stderr, "usage: %s walk|walk3|get|poll HOST PORT N\n", argv[0]);
        return 2;
    }
    const char *scenario = argv[1], *host = argv[2];
    int port = atoi(argv[3]), n = atoi(argv[4]);
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DONT_PERSIST_STATE, 1);
    netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DISABLE_PERSISTENT_LOAD, 1);
    init_snmp("bench");
    char peer[256];
    snprintf(peer, sizeof peer, "udp:%s:%d", host, port);
    double t0 = now_ms();
    if (!strcmp(scenario, "walk") || !strcmp(scenario, "walk3")) {
        netsnmp_session *ss = open_session(peer, !strcmp(scenario, "walk3"));
        int items = 0;
        for (int i = 0; i < n; i++) items += walk(ss);
        report(items, now_ms() - t0, NULL, 0);
    } else if (!strcmp(scenario, "get")) {
        netsnmp_session *ss = open_session(peer, 0);
        oid name[MAX_OID_LEN];
        size_t len = MAX_OID_LEN;
        read_objid("1.3.6.1.2.1.1.5.0", name, &len);
        double *lat = malloc(sizeof(double) * n);
        for (int i = 0; i < n; i++) {
            double s = now_ms();
            netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET), *resp = NULL;
            snmp_add_null_var(pdu, name, len);
            if (snmp_synch_response(ss, pdu, &resp) != STAT_SUCCESS || !resp) {
                fprintf(stderr, "get failed\n");
                return 1;
            }
            snmp_free_pdu(resp);
            lat[i] = (now_ms() - s) * 1e3;
        }
        report(n, now_ms() - t0, lat, n);
    } else if (!strcmp(scenario, "getnext") || !strcmp(scenario, "bulk") || !strcmp(scenario, "set") ||
               !strcmp(scenario, "trap") || !strcmp(scenario, "inform")) {
        int notify = !strcmp(scenario, "trap") || !strcmp(scenario, "inform");
        if (notify) snprintf(peer, sizeof peer, "udp:%s:%d", host, port - 1);
        netsnmp_session s;
        snmp_sess_init(&s);
        s.peername = peer;
        s.version = SNMP_VERSION_2c;
        s.community = (u_char *)(!strcmp(scenario, "set") ? "private" : "public");
        s.community_len = strlen((char *)s.community);
        s.timeout = 1000000;
        s.retries = 2;
        netsnmp_session *ss = snmp_open(&s);
        if (!ss) {
            snmp_perror("snmp_open");
            return 1;
        }
        oid a[MAX_OID_LEN], uptime[MAX_OID_LEN], trapoid[MAX_OID_LEN];
        size_t alen = MAX_OID_LEN, ulen = MAX_OID_LEN, tlen = MAX_OID_LEN;
        const char *which = !strcmp(scenario, "getnext") ? "1.3.6.1.2.1.1.5.0"
                            : !strcmp(scenario, "bulk")  ? "1.3.6.1.4.1.99999.1"
                            : !strcmp(scenario, "set")   ? "1.3.6.1.4.1.99999.3.0"
                                                         : "1.3.6.1.2.1.2.2.1.1.7";
        read_objid(which, a, &alen);
        read_objid("1.3.6.1.2.1.1.3.0", uptime, &ulen);
        read_objid("1.3.6.1.6.3.1.1.4.1.0", trapoid, &tlen);
        double *lat = malloc(sizeof(double) * n);
        int items = 0;
        for (int i = 0; i < n; i++) {
            double st = now_ms();
            int type = !strcmp(scenario, "getnext") ? SNMP_MSG_GETNEXT
                       : !strcmp(scenario, "bulk")  ? SNMP_MSG_GETBULK
                       : !strcmp(scenario, "set")   ? SNMP_MSG_SET
                       : !strcmp(scenario, "trap")  ? SNMP_MSG_TRAP2
                                                    : SNMP_MSG_INFORM;
            netsnmp_pdu *pdu = snmp_pdu_create(type), *resp = NULL;
            char buf[32];
            if (type == SNMP_MSG_GETBULK) {
                pdu->non_repeaters = 0;
                pdu->max_repetitions = 50;
            }
            if (notify) {
                snmp_add_var(pdu, uptime, ulen, 't', "0");
                snmp_add_var(pdu, trapoid, tlen, 'o', "1.3.6.1.6.3.1.1.5.3");
                snmp_add_var(pdu, a, alen, 'i', "7");
            } else if (type == SNMP_MSG_SET) {
                snprintf(buf, sizeof buf, "value %d", i);
                snmp_add_var(pdu, a, alen, 's', buf);
            } else {
                snmp_add_null_var(pdu, a, alen);
            }
            if (type == SNMP_MSG_TRAP2) {
                if (!snmp_send(ss, pdu)) {
                    snmp_free_pdu(pdu);
                    fprintf(stderr, "send failed\n");
                    return 1;
                }
                items++;
            } else {
                if (snmp_synch_response(ss, pdu, &resp) != STAT_SUCCESS || !resp ||
                    resp->errstat != SNMP_ERR_NOERROR) {
                    fprintf(stderr, "%s failed\n", scenario);
                    return 1;
                }
                for (netsnmp_variable_list *v = resp->variables; v; v = v->next_variable) items++;
                snmp_free_pdu(resp);
            }
            lat[i] = (now_ms() - st) * 1e3;
        }
        report(!strcmp(scenario, "inform") ? n : items, now_ms() - t0, lat, n);
    } else if (!strcmp(scenario, "poll")) {
        oid name[MAX_OID_LEN];
        size_t len = MAX_OID_LEN;
        read_objid("1.3.6.1.2.1.1.5.0", name, &len);
        for (int k = 1; k <= n; k++) {
            netsnmp_session s;
            snmp_sess_init(&s);
            snprintf(peer, sizeof peer, "udp:%s:%d", host, port + k);
            s.peername = peer;
            s.version = SNMP_VERSION_2c;
            s.community = (u_char *)"public";
            s.community_len = 6;
            s.timeout = 1000000;
            s.retries = 2;
            s.callback = on_response;
            netsnmp_session *ss = snmp_open(&s);
            if (!ss) continue;
            netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_GET);
            snmp_add_null_var(pdu, name, len);
            if (snmp_send(ss, pdu)) pending++;
            else snmp_free_pdu(pdu);
        }
        while (pending > 0) {
            int fds = 0, block = 1;
            fd_set fdset;
            struct timeval tv;
            FD_ZERO(&fdset);
            snmp_select_info(&fds, &fdset, &tv, &block);
            fds = select(fds, &fdset, NULL, NULL, block ? NULL : &tv);
            if (fds > 0) snmp_read(&fdset);
            else snmp_timeout();
        }
        report(ok, now_ms() - t0, NULL, 0);
    } else if (!strcmp(scenario, "idle")) {
        report(0, 0, NULL, 0);
    } else {
        printf("{\"unsupported\": true}\n");
    }
    return 0;
}
