// snmpify_walk HOST[:PORT] COMMUNITY [OID]   (GetBulk walk, names from the MIBs)
#include <iostream>

#include "snmpify.hpp"

int main(int argc, char** argv) {
    if (argc < 3) {
        std::cerr << "usage: " << argv[0] << " HOST[:PORT] COMMUNITY [OID]\n";
        return 2;
    }
    try {
        snmpify::Mib mib;
        snmpify::Client client(argv[1], argv[2]);
        std::string root = argc > 3 ? mib.resolve(argv[3]) : "1.3.6.1.2.1";
        client.walk(root, [&](const snmpify::VarBind& vb) {
            std::cout << mib.name(vb.oid) << " = " << vb.text << "\n";
            return true;
        });
    } catch (const snmpify::Error& e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
    return 0;
}
