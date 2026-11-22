// snmpify for C++17: a header-only wrapper of snmpify.h with RAII
// handles and exceptions.
//
//   snmpify::Client c("192.0.2.1", "public");
//   std::cout << c.get("1.3.6.1.2.1.1.5.0").text << "\n";
//   for (const auto& vb : c.walk("1.3.6.1.2.1.2.2.1.2")) std::cout << vb.oid << " " << vb.text << "\n";
#ifndef SNMPIFY_HPP
#define SNMPIFY_HPP

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "snmpify.h"

namespace snmpify {

// An snmpify failure: the status, and for agent errors the error-status
// and failing binding.
class Error : public std::runtime_error {
public:
    Error(snmpify_status status, const std::string& message, int agent_status = 0, uint32_t index = 0)
        : std::runtime_error(message), status_(status), agent_status_(agent_status), index_(index) {}
    snmpify_status status() const noexcept { return status_; }
    bool timeout() const noexcept { return status_ == SNMPIFY_ERR_TIMEOUT; }
    // After an agent error: "noSuchName" …
    std::string agent_status_name() const { return snmpify_error_status_name(agent_status_); }
    int agent_status() const noexcept { return agent_status_; }
    uint32_t index() const noexcept { return index_; }

private:
    snmpify_status status_;
    int agent_status_;
    uint32_t index_;
};

namespace detail {
inline void check(snmpify_status s) {
    if (s != SNMPIFY_OK) {
        throw Error(s, snmpify_last_error(), snmpify_last_error_status(), snmpify_last_error_index());
    }
}
template <class T>
T* not_null(T* p) {
    if (!p) throw Error(snmpify_status(SNMPIFY_ERR_INVALID_ARGUMENT), snmpify_last_error());
    return p;
}
struct ResultFree {
    void operator()(snmpify_result* r) const { snmpify_result_free(r); }
};
using ResultPtr = std::unique_ptr<snmpify_result, ResultFree>;
}  // namespace detail

// A received binding.
struct VarBind {
    std::string oid;
    snmpify_type type = SNMPIFY_NULL;
    int64_t integer = 0;    // INTEGER and the unsigned types
    uint64_t uinteger = 0;  // Counter32/64, Gauge32, TimeTicks
    std::string bytes;      // OCTET STRING / Opaque (binary)
    std::string text;       // any value as text

    bool exception() const {
        return type == SNMPIFY_NO_SUCH_OBJECT || type == SNMPIFY_NO_SUCH_INSTANCE ||
               type == SNMPIFY_END_OF_MIB_VIEW;
    }
};

inline std::vector<VarBind> to_vector(const snmpify_result* r) {
    std::vector<VarBind> v;
    size_t n = snmpify_result_len(r);
    v.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        VarBind vb;
        vb.oid = snmpify_result_oid(r, i);
        vb.type = snmpify_result_type(r, i);
        vb.integer = snmpify_result_int(r, i);
        vb.uinteger = snmpify_result_uint(r, i);
        size_t len = 0;
        const uint8_t* b = snmpify_result_bytes(r, i, &len);
        if (b) vb.bytes.assign(reinterpret_cast<const char*>(b), len);
        vb.text = snmpify_result_text(r, i);
        v.push_back(std::move(vb));
    }
    return v;
}

// A value to send. Keeps its own copy of strings.
class Value {
public:
    static Value integer(int32_t v) { Value x(SNMPIFY_INTEGER); x.v_.integer = v; return x; }
    static Value string(std::string s) { Value x(SNMPIFY_OCTET_STRING); x.data_ = std::move(s); return x; }
    static Value oid(std::string s) { Value x(SNMPIFY_OBJECT_ID); x.data_ = std::move(s); return x; }
    static Value ip(std::string s) { Value x(SNMPIFY_IP_ADDRESS); x.data_ = std::move(s); return x; }
    static Value counter32(uint32_t v) { return unsigned_(SNMPIFY_COUNTER32, v); }
    static Value gauge32(uint32_t v) { return unsigned_(SNMPIFY_GAUGE32, v); }
    static Value timeticks(uint32_t v) { return unsigned_(SNMPIFY_TIMETICKS, v); }
    static Value counter64(uint64_t v) { return unsigned_(SNMPIFY_COUNTER64, v); }
    static Value null() { return Value(SNMPIFY_NULL); }

    // The C view (valid while this Value lives).
    snmpify_value c() const {
        snmpify_value v = v_;
        if (v.type == SNMPIFY_OCTET_STRING || v.type == SNMPIFY_OPAQUE) {
            v.bytes = reinterpret_cast<const uint8_t*>(data_.data());
            v.len = data_.size();
        } else if (v.type == SNMPIFY_OBJECT_ID || v.type == SNMPIFY_IP_ADDRESS) {
            v.text = data_.c_str();
        }
        return v;
    }

private:
    explicit Value(snmpify_type t) : v_{t, 0, 0, nullptr, 0, nullptr} {}
    static Value unsigned_(snmpify_type t, uint64_t u) { Value x(t); x.v_.uinteger = u; return x; }
    snmpify_value v_;
    std::string data_;
};

using Binding = std::pair<std::string, Value>;

namespace detail {
struct CBindings {
    explicit CBindings(const std::vector<Binding>& b) {
        values.reserve(b.size());
        for (const auto& [oid, v] : b) values.push_back({oid.c_str(), v.c()});
    }
    std::vector<snmpify_varbind> values;
};
inline std::vector<const char*> c_strs(const std::vector<std::string>& v) {
    std::vector<const char*> out;
    for (const auto& s : v) out.push_back(s.c_str());
    return out;
}
}  // namespace detail

// An SNMPv3 user.
class User {
public:
    explicit User(const std::string& name, const char* auth_protocol = nullptr,
                  const std::string& auth_password = "", const char* priv_protocol = nullptr,
                  const std::string& priv_password = "")
        : u_(detail::not_null(snmpify_user_new(name.c_str(), auth_protocol, auth_password.c_str(),
                                               priv_protocol, priv_password.c_str())),
             snmpify_user_free) {}
    const snmpify_user* get() const { return u_.get(); }

private:
    std::shared_ptr<snmpify_user> u_;
};

// A blocking client for one agent.
class Client {
public:
    // v1 (version 1) or v2c (2).
    explicit Client(const std::string& target, const std::string& community = "public", int version = 2)
        : c_(detail::not_null(snmpify_client_new(target.c_str(), community.c_str(), version)),
             snmpify_client_free) {}
    Client(const std::string& target, const User& user, const char* context = nullptr)
        : c_(detail::not_null(snmpify_client_new_v3(target.c_str(), user.get(), context)),
             snmpify_client_free) {}

    // Over TCP (RFC 3430).
    static Client tcp(const std::string& target, const std::string& community = "public", int version = 2) {
        return Client(detail::not_null(snmpify_client_new_tcp(target.c_str(), community.c_str(), version)));
    }
    static Client tcp(const std::string& target, const User& user, const char* context = nullptr) {
        return Client(detail::not_null(snmpify_client_new_v3_tcp(target.c_str(), user.get(), context)));
    }

    Client& options(uint32_t timeout_ms, uint32_t retries, uint32_t max_repetitions = 25) {
        detail::check(snmpify_client_set_options(c_.get(), timeout_ms, retries, max_repetitions));
        return *this;
    }

    VarBind get(const std::string& oid) const { return get(std::vector<std::string>{oid}).at(0); }
    std::vector<VarBind> get(const std::vector<std::string>& oids) const {
        return call(snmpify_get, oids);
    }
    std::vector<VarBind> get_next(const std::vector<std::string>& oids) const {
        return call(snmpify_get_next, oids);
    }
    std::vector<VarBind> get_bulk(const std::vector<std::string>& oids, uint32_t non_repeaters,
                                  uint32_t max_repetitions) const {
        auto c = detail::c_strs(oids);
        snmpify_result* r = nullptr;
        detail::check(snmpify_get_bulk(c_.get(), c.data(), c.size(), non_repeaters, max_repetitions, &r));
        detail::ResultPtr p(r);
        return to_vector(r);
    }
    std::vector<VarBind> set(const std::vector<Binding>& vbs) const {
        detail::CBindings b(vbs);
        snmpify_result* r = nullptr;
        detail::check(snmpify_set(c_.get(), b.values.data(), b.values.size(), &r));
        detail::ResultPtr p(r);
        return to_vector(r);
    }
    std::vector<VarBind> walk(const std::string& root) const {
        snmpify_result* r = nullptr;
        detail::check(snmpify_walk_all(c_.get(), root.c_str(), &r));
        detail::ResultPtr p(r);
        return to_vector(r);
    }
    // Calls f for each binding as it arrives; f returns false to stop.
    void walk(const std::string& root, const std::function<bool(const VarBind&)>& f) const {
        std::unique_ptr<snmpify_walk, void (*)(snmpify_walk*)> w(
            detail::not_null(snmpify_walk_new(c_.get(), root.c_str())), snmpify_walk_free);
        for (;;) {
            snmpify_result* r = nullptr;
            snmpify_status s = snmpify_walk_next(w.get(), &r);
            if (s == SNMPIFY_END) return;
            detail::check(s);
            detail::ResultPtr p(r);
            if (!f(to_vector(r).at(0))) return;
        }
    }
    void trap(const std::string& trap_oid, const std::vector<Binding>& vbs = {}) const {
        detail::CBindings b(vbs);
        detail::check(snmpify_trap(c_.get(), trap_oid.c_str(), b.values.data(), b.values.size()));
    }
    void inform(const std::string& trap_oid, const std::vector<Binding>& vbs = {}) const {
        detail::CBindings b(vbs);
        detail::check(snmpify_inform(c_.get(), trap_oid.c_str(), b.values.data(), b.values.size()));
    }

private:
    explicit Client(snmpify_client* c) : c_(c, snmpify_client_free) {}
    using Fn = snmpify_status (*)(const snmpify_client*, const char* const*, size_t, snmpify_result**);
    std::vector<VarBind> call(Fn f, const std::vector<std::string>& oids) const {
        auto c = detail::c_strs(oids);
        snmpify_result* r = nullptr;
        detail::check(f(c_.get(), c.data(), c.size(), &r));
        detail::ResultPtr p(r);
        return to_vector(r);
    }
    std::shared_ptr<snmpify_client> c_;
};

// A received trap or inform.
struct Notification {
    std::string kind;  // "trap" / "inform"
    int version = 0;
    std::string source;
    std::string sender;  // community or user
    std::string trap_oid;
    uint32_t uptime = 0;
    std::vector<VarBind> varbinds;
};

// Receives traps and informs.
class Receiver {
public:
    Receiver(const std::string& address, const std::vector<std::string>& communities,
             const std::vector<User>& users = {}) {
        auto c = detail::c_strs(communities);
        std::vector<const snmpify_user*> u;
        for (const auto& x : users) u.push_back(x.get());
        r_.reset(detail::not_null(
            snmpify_receiver_new(address.c_str(), c.data(), c.size(), u.data(), u.size())));
    }
    std::string address() const { return snmpify_receiver_address(r_.get()); }
    // std::nullopt after timeout_ms (0: wait forever).
    std::optional<Notification> recv(uint32_t timeout_ms = 0) {
        snmpify_notification* n = nullptr;
        snmpify_status s = snmpify_receiver_recv(r_.get(), timeout_ms, &n);
        if (s == SNMPIFY_ERR_TIMEOUT) return std::nullopt;
        detail::check(s);
        std::unique_ptr<snmpify_notification, void (*)(snmpify_notification*)> p(n, snmpify_notification_free);
        Notification out;
        out.kind = snmpify_notification_kind(n);
        out.version = snmpify_notification_version(n);
        out.source = snmpify_notification_source(n);
        out.sender = snmpify_notification_sender(n);
        out.trap_oid = snmpify_notification_trap_oid(n);
        out.uptime = snmpify_notification_uptime(n);
        out.varbinds = to_vector(snmpify_notification_varbinds(n));
        return out;
    }

private:
    std::unique_ptr<snmpify_receiver, void (*)(snmpify_receiver*)> r_{nullptr, snmpify_receiver_free};
};

// An agent: configure, then start(); stops when destroyed.
class Agent {
public:
    explicit Agent(const std::string& address = "0.0.0.0:161")
        : a_(detail::not_null(snmpify_agent_new(address.c_str())), snmpify_agent_free) {}
    Agent& community(const std::string& c, bool writable = false) {
        detail::check(snmpify_agent_add_community(a_.get(), c.c_str(), writable));
        return *this;
    }
    Agent& user(const User& u, bool writable = false) {
        detail::check(snmpify_agent_add_user(a_.get(), u.get(), writable));
        return *this;
    }
    Agent& set(const std::string& oid, const Value& v, bool writable = false) {
        snmpify_varbind vb{oid.c_str(), v.c()};
        detail::check(snmpify_agent_set(a_.get(), &vb, writable));
        return *this;
    }
    // The current value (after managers' sets).
    VarBind get(const std::string& oid) const {
        snmpify_result* r = nullptr;
        detail::check(snmpify_agent_get(a_.get(), oid.c_str(), &r));
        detail::ResultPtr p(r);
        return to_vector(r).at(0);
    }
    void start() { detail::check(snmpify_agent_start(a_.get())); }
    std::string address() const { return snmpify_agent_address(a_.get()); }
    snmpify_agent* raw() { return a_.get(); }

private:
    std::unique_ptr<snmpify_agent, void (*)(snmpify_agent*)> a_;
};

// MIBs: names and readable values.
class Mib {
public:
    Mib() : m_(detail::not_null(snmpify_mib_standard()), snmpify_mib_free) {}
    void load_file(const std::string& path) { detail::check(snmpify_mib_load_file(m_.get(), path.c_str())); }
    std::string resolve(const std::string& name) const {
        return out([&](char* b, size_t n) { return snmpify_mib_resolve(m_.get(), name.c_str(), b, n); });
    }
    std::string name(const std::string& oid) const {
        return out([&](char* b, size_t n) { return snmpify_mib_name(m_.get(), oid.c_str(), b, n); });
    }

private:
    template <class F>
    static std::string out(F f) {
        size_t n = f(nullptr, 0);
        if (n == 0) throw Error(SNMPIFY_ERR_INVALID_ARGUMENT, snmpify_last_error());
        std::string s(n, '\0');
        f(s.data(), n);
        s.resize(n - 1);
        return s;
    }
    std::unique_ptr<snmpify_mib, void (*)(snmpify_mib*)> m_;
};

}  // namespace snmpify

#endif  // SNMPIFY_HPP
