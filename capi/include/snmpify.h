/*
 * snmpify: fast, safe SNMP (v1, v2c, v3) for C, with a Rust core.
 *
 *   snmpify_client *c = snmpify_client_new("192.0.2.1", "public", 2);
 *   const char *oids[] = {"1.3.6.1.2.1.1.5.0"};
 *   snmpify_result *r;
 *   if (snmpify_get(c, oids, 1, &r) == SNMPIFY_OK) {
 *       printf("%s = %s\n", snmpify_result_oid(r, 0), snmpify_result_text(r, 0));
 *       snmpify_result_free(r);
 *   } else {
 *       fprintf(stderr, "%s\n", snmpify_last_error());
 *   }
 *   snmpify_client_free(c);
 *
 * Conventions:
 * - Calls block; handles may be used from several threads (except a
 *   walk, a receiver and an agent being configured).
 * - Functions return a status; on failure snmpify_last_error() describes
 *   it (thread-local, valid until the next call on the thread).
 *   Constructors return NULL on failure.
 * - Every handle is freed with its _free function (NULL is accepted).
 *   Strings returned as `const char *` belong to the handle they came
 *   from and live as long as it does.
 * - OIDs are dotted strings ("1.3.6.1.2.1.1.5.0").
 */
#ifndef SNMPIFY_H
#define SNMPIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Status codes and errors                                            */
/* ------------------------------------------------------------------ */

typedef int snmpify_status;
#define SNMPIFY_OK 0
#define SNMPIFY_ERR_TIMEOUT 1          /* no answer after all retries */
#define SNMPIFY_ERR_AGENT 2            /* error-status in the response */
#define SNMPIFY_ERR_REPORT 3           /* SNMPv3 report (wrong password …) */
#define SNMPIFY_ERR_INVALID_ARGUMENT 4 /* bad OID, NULL pointer, … */
#define SNMPIFY_ERR_IO 5               /* socket error */
#define SNMPIFY_ERR_PROTOCOL 6         /* malformed or unexpected answer */
#define SNMPIFY_END 7                  /* snmpify_walk_next: no more */
#define SNMPIFY_ERR_PANIC 8            /* internal error */

/* The last error's message on this thread ("" if none). */
const char *snmpify_last_error(void);
/* After SNMPIFY_ERR_AGENT: the error-status code and the 1-based index of
 * the failing binding. */
int snmpify_last_error_status(void);
uint32_t snmpify_last_error_index(void);
/* "noSuchName", "noAccess" … for an error-status code. */
const char *snmpify_error_status_name(int code);
/* "0.1.0". */
const char *snmpify_version(void);

/* ------------------------------------------------------------------ */
/* Values                                                             */
/* ------------------------------------------------------------------ */

/* Value types (their BER tags). */
typedef int snmpify_type;
#define SNMPIFY_INTEGER 0x02
#define SNMPIFY_OCTET_STRING 0x04
#define SNMPIFY_NULL 0x05
#define SNMPIFY_OBJECT_ID 0x06
#define SNMPIFY_IP_ADDRESS 0x40
#define SNMPIFY_COUNTER32 0x41
#define SNMPIFY_GAUGE32 0x42
#define SNMPIFY_TIMETICKS 0x43
#define SNMPIFY_OPAQUE 0x44
#define SNMPIFY_COUNTER64 0x46
#define SNMPIFY_NO_SUCH_OBJECT 0x80
#define SNMPIFY_NO_SUCH_INSTANCE 0x81
#define SNMPIFY_END_OF_MIB_VIEW 0x82

/* A value to send. Set `type` and the matching field:
 *   INTEGER: integer; COUNTER32/GAUGE32/TIMETICKS/COUNTER64: uinteger;
 *   OCTET_STRING/OPAQUE: bytes + len; OBJECT_ID/IP_ADDRESS: text (dotted). */
typedef struct snmpify_value {
    snmpify_type type;
    int64_t integer;
    uint64_t uinteger;
    const uint8_t *bytes;
    size_t len;
    const char *text;
} snmpify_value;

/* A binding to send. */
typedef struct snmpify_varbind {
    const char *oid;
    snmpify_value value;
} snmpify_varbind;

/* Received bindings. */
typedef struct snmpify_result snmpify_result;
size_t snmpify_result_len(const snmpify_result *r);
const char *snmpify_result_oid(const snmpify_result *r, size_t i);
snmpify_type snmpify_result_type(const snmpify_result *r, size_t i);
/* Numbers: INTEGER and the unsigned types. */
int64_t snmpify_result_int(const snmpify_result *r, size_t i);
uint64_t snmpify_result_uint(const snmpify_result *r, size_t i);
/* OCTET STRING / Opaque bytes (not NUL-terminated); NULL for other types. */
const uint8_t *snmpify_result_bytes(const snmpify_result *r, size_t i, size_t *len);
/* Any value as text. */
const char *snmpify_result_text(const snmpify_result *r, size_t i);
void snmpify_result_free(snmpify_result *r);

/* ------------------------------------------------------------------ */
/* Clients                                                            */
/* ------------------------------------------------------------------ */

typedef struct snmpify_user snmpify_user;
/* An SNMPv3 user. Protocols (NULL for none): "MD5", "SHA", "SHA-224",
 * "SHA-256", "SHA-384", "SHA-512"; "DES", "AES", "AES-192", "AES-256",
 * and Cisco's AES key extension "AES-192-C", "AES-256-C".
 * Passwords need 8 characters or more. */
snmpify_user *snmpify_user_new(const char *name, const char *auth_protocol,
                               const char *auth_password, const char *priv_protocol,
                               const char *priv_password);
void snmpify_user_free(snmpify_user *u);

typedef struct snmpify_client snmpify_client;
/* version: 1 or 2 (v2c). target: "host" or "host:port" (default 161). */
snmpify_client *snmpify_client_new(const char *target, const char *community, int version);
/* SNMPv3; context may be NULL. */
snmpify_client *snmpify_client_new_v3(const char *target, const snmpify_user *user,
                                      const char *context);
/* The same over TCP (RFC 3430): no retransmissions; a request waits as
 * long as all attempts would. */
snmpify_client *snmpify_client_new_tcp(const char *target, const char *community, int version);
snmpify_client *snmpify_client_new_v3_tcp(const char *target, const snmpify_user *user,
                                          const char *context);
/* Defaults: 1000 ms per attempt, 2 retries, 25 bindings per GetBulk in walks. */
snmpify_status snmpify_client_set_options(snmpify_client *c, uint32_t timeout_ms,
                                          uint32_t retries, uint32_t max_repetitions);
void snmpify_client_free(snmpify_client *c);

snmpify_status snmpify_get(const snmpify_client *c, const char *const *oids, size_t n,
                           snmpify_result **out);
snmpify_status snmpify_get_next(const snmpify_client *c, const char *const *oids, size_t n,
                                snmpify_result **out);
snmpify_status snmpify_get_bulk(const snmpify_client *c, const char *const *oids, size_t n,
                                uint32_t non_repeaters, uint32_t max_repetitions,
                                snmpify_result **out);
/* out may be NULL. */
snmpify_status snmpify_set(const snmpify_client *c, const snmpify_varbind *vbs, size_t n,
                           snmpify_result **out);
/* The whole subtree under root. */
snmpify_status snmpify_walk_all(const snmpify_client *c, const char *root,
                                snmpify_result **out);

/* A walk read one binding at a time. */
typedef struct snmpify_walk snmpify_walk;
snmpify_walk *snmpify_walk_new(const snmpify_client *c, const char *root);
/* SNMPIFY_OK with a one-binding result, SNMPIFY_END at the end. */
snmpify_status snmpify_walk_next(snmpify_walk *w, snmpify_result **out);
void snmpify_walk_free(snmpify_walk *w);

/* Notifications (v2c, v3): sysUpTime.0 and snmpTrapOID.0 are added. */
snmpify_status snmpify_trap(const snmpify_client *c, const char *trap_oid,
                            const snmpify_varbind *vbs, size_t n);
/* Waits for the receiver's acknowledgement. */
snmpify_status snmpify_inform(const snmpify_client *c, const char *trap_oid,
                              const snmpify_varbind *vbs, size_t n);

/* ------------------------------------------------------------------ */
/* Receiving traps and informs                                        */
/* ------------------------------------------------------------------ */

typedef struct snmpify_receiver snmpify_receiver;
typedef struct snmpify_notification snmpify_notification;
/* n_communities 0: any community. users: SNMPv3 users (may be 0). */
snmpify_receiver *snmpify_receiver_new(const char *address, const char *const *communities,
                                       size_t n_communities, const snmpify_user *const *users,
                                       size_t n_users);
const char *snmpify_receiver_address(const snmpify_receiver *r);
/* timeout_ms 0: wait forever. SNMPIFY_ERR_TIMEOUT if nothing came. */
snmpify_status snmpify_receiver_recv(snmpify_receiver *r, uint32_t timeout_ms,
                                     snmpify_notification **out);
void snmpify_receiver_free(snmpify_receiver *r);

const char *snmpify_notification_kind(const snmpify_notification *n); /* "trap"/"inform" */
int snmpify_notification_version(const snmpify_notification *n);      /* 1, 2, 3 */
const char *snmpify_notification_source(const snmpify_notification *n);
const char *snmpify_notification_sender(const snmpify_notification *n); /* community/user */
const char *snmpify_notification_trap_oid(const snmpify_notification *n);
uint32_t snmpify_notification_uptime(const snmpify_notification *n);
const snmpify_result *snmpify_notification_varbinds(const snmpify_notification *n);
void snmpify_notification_free(snmpify_notification *n);

/* ------------------------------------------------------------------ */
/* Agent                                                              */
/* ------------------------------------------------------------------ */

typedef struct snmpify_agent snmpify_agent;
/* Bound to address ("0.0.0.0:161"); configure, then start. */
snmpify_agent *snmpify_agent_new(const char *address);
snmpify_status snmpify_agent_add_community(snmpify_agent *a, const char *community, int writable);
snmpify_status snmpify_agent_add_user(snmpify_agent *a, const snmpify_user *user, int writable);
/* A value at an instance OID ("….0"); writable: managers may set it. */
snmpify_status snmpify_agent_set(snmpify_agent *a, const snmpify_varbind *vb, int writable);
/* Fills *out on every read and returns 0 (else the read gets
 * noSuchInstance). Called on an snmpify thread: ctx must be usable there;
 * bytes/text it points to must stay valid until the next call. */
typedef int (*snmpify_value_fn)(void *ctx, snmpify_value *out);
snmpify_status snmpify_agent_set_callback(snmpify_agent *a, const char *oid,
                                          snmpify_value_fn callback, void *ctx);
/* The current value (after managers' sets). */
snmpify_status snmpify_agent_get(const snmpify_agent *a, const char *oid, snmpify_result **out);
snmpify_status snmpify_agent_start(snmpify_agent *a);
const char *snmpify_agent_address(const snmpify_agent *a);
/* Stops and frees. */
void snmpify_agent_free(snmpify_agent *a);

/* ------------------------------------------------------------------ */
/* MIBs                                                               */
/* ------------------------------------------------------------------ */

typedef struct snmpify_mib snmpify_mib;
/* The built-in standard modules (SNMPv2-MIB, IF-MIB, …). */
snmpify_mib *snmpify_mib_standard(void);
snmpify_status snmpify_mib_load_file(snmpify_mib *m, const char *path);
/* These write a NUL-terminated string into buf (truncated to len) and
 * return the length needed including the NUL; 0 on error. */
size_t snmpify_mib_resolve(const snmpify_mib *m, const char *name, char *buf, size_t len);
size_t snmpify_mib_name(const snmpify_mib *m, const char *oid, char *buf, size_t len);
/* Binding i of r as "IF-MIB::ifOperStatus.1 = up(1)". */
size_t snmpify_mib_format(const snmpify_mib *m, const snmpify_result *r, size_t i, char *buf,
                          size_t len);
void snmpify_mib_free(snmpify_mib *m);

#ifdef __cplusplus
}
#endif

#endif /* SNMPIFY_H */
