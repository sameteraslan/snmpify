// The C++ wrapper against an agent made with it.
#include <cassert>
#include <iostream>

#include "snmpify.hpp"

#define CHECK(c)                                                              \
    do {                                                                      \
        if (!(c)) {                                                           \
            std::cerr << __FILE__ << ":" << __LINE__ << ": " #c "\n";         \
            return 1;                                                         \
        }                                                                     \
    } while (0)

int main() {
    using snmpify::Value;
    snmpify::User alice("alice", "SHA-512", "alice-auth", "AES-256", "alice-priv");
    snmpify::Agent agent("127.0.0.1:0");
    agent.community("public").community("private", true).user(alice, true);
    agent.set("1.3.6.1.2.1.1.5.0", Value::string("cpp-agent"));
    agent.set("1.3.6.1.4.1.99999.1.0", Value::integer(5), true);
    agent.set("1.3.6.1.4.1.99999.2.0", Value::oid("1.3.6.1.4.1.8072"));
    agent.set("1.3.6.1.4.1.99999.3.0", Value::ip("192.0.2.1"));
    agent.set("1.3.6.1.4.1.99999.4.0", Value::timeticks(100));
    agent.set("1.3.6.1.4.1.99999.5.0", Value::gauge32(3));
    agent.set("1.3.6.1.4.1.99999.6.0", Value::counter32(4));
    agent.start();

    snmpify::Client c(agent.address(), "public");
    c.options(300, 1);
    CHECK(c.get("1.3.6.1.2.1.1.5.0").text == "cpp-agent");
    auto vbs = c.get({"1.3.6.1.4.1.99999.1.0", "1.3.6.1.4.1.99999.2.0", "1.3.6.1.4.1.99999.3.0"});
    CHECK(vbs.at(0).integer == 5);
    CHECK(vbs.at(1).type == SNMPIFY_OBJECT_ID && vbs.at(1).text == "1.3.6.1.4.1.8072");
    CHECK(vbs.at(2).text == "192.0.2.1");
    CHECK(c.walk("1.3.6.1.4.1.99999").size() == 6);
    int n = 0;
    c.walk("1.3.6.1.4.1.99999", [&](const snmpify::VarBind&) { return ++n < 3; });
    CHECK(n == 3);
    CHECK(c.get_next({"1.3.6.1.4.1.99999.1.0"}).at(0).oid == "1.3.6.1.4.1.99999.2.0");
    CHECK(c.get_bulk({"1.3.6.1.4.1.99999"}, 0, 4).size() == 4);
    CHECK(c.get("1.3.6.1.4.1.99999.9.0").exception());

    try {
        c.set({{"1.3.6.1.4.1.99999.1.0", Value::integer(6)}});
        CHECK(false);
    } catch (const snmpify::Error& e) {
        CHECK(e.status() == SNMPIFY_ERR_AGENT && e.agent_status_name() == "noAccess" && e.index() == 1);
    }
    snmpify::Client v3(agent.address(), alice);
    v3.set({{"1.3.6.1.4.1.99999.1.0", Value::integer(6)}});
    CHECK(agent.get("1.3.6.1.4.1.99999.1.0").integer == 6);
    try {
        snmpify::Client(agent.address(), "nope").options(100, 0).get("1.3.6.1.2.1.1.5.0");
        CHECK(false);
    } catch (const snmpify::Error& e) {
        CHECK(e.timeout());
    }

    snmpify::Receiver rx("127.0.0.1:0", {"public"}, {alice});
    snmpify::Client(rx.address(), "public").trap("1.3.6.1.6.3.1.1.5.3", {{"1.3.6.1.2.1.1.5.0", Value::string("x")}});
    auto note = rx.recv(2000);
    CHECK(note && note->kind == "trap" && note->varbinds.size() == 1 && note->sender == "public");
    CHECK(!rx.recv(50));

    snmpify::Mib mib;
    CHECK(mib.resolve("sysName.0") == "1.3.6.1.2.1.1.5.0");
    CHECK(mib.name("1.3.6.1.2.1.2.2.1.2.4") == "IF-MIB::ifDescr.4");
    try {
        mib.resolve("nothing");
        CHECK(false);
    } catch (const snmpify::Error&) {
    }
    try {
        snmpify::User bad("x", "SHA", "short");
        CHECK(false);
    } catch (const snmpify::Error& e) {
        CHECK(e.status() == SNMPIFY_ERR_INVALID_ARGUMENT);
    }
    std::cout << "C++ API: all checks passed\n";
    return 0;
}
