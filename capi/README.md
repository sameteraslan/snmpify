# snmpify for C and C++

The C API (`include/snmpify.h`) and a header-only C++17 wrapper
(`include/snmpify.hpp`) of snmpify: an SNMP v1/v2c/v3 client (every
standard authentication and privacy protocol), traps and informs, an
agent, and MIBs with the standard modules built in. One library, no
other dependency; Linux, macOS and Windows.

## Get it

- **Prebuilt**: archives for Linux (x86_64, aarch64), macOS (arm64,
  x86_64) and Windows (x64) on the `c-v*` GitHub releases: `include/`,
  `lib/` (shared and static library, CMake package, pkg-config file).
- **From source** (stable Rust + CMake 3.16):

  ```sh
  cmake -S capi -B build -DCMAKE_INSTALL_PREFIX=/usr/local
  cmake --build build --config Release && cmake --install build
  ```

## Use it

CMake (installed or prebuilt):

```cmake
find_package(snmpify 0.1 REQUIRED)
target_link_libraries(app PRIVATE snmpify::snmpify)   # or snmpify::static
```

or in your source tree: `add_subdirectory(snmpify/capi snmpify)`.
pkg-config: `cc app.c $(pkg-config --cflags --libs snmpify)` (static:
`--static`).

## C

```c
#include <snmpify.h>

snmpify_client *c = snmpify_client_new("192.0.2.1", "public", 2);
const char *oids[] = {"1.3.6.1.2.1.1.5.0"};
snmpify_result *r;
if (snmpify_get(c, oids, 1, &r) == SNMPIFY_OK) {
    printf("%s = %s\n", snmpify_result_oid(r, 0), snmpify_result_text(r, 0));
    snmpify_result_free(r);
} else {
    fprintf(stderr, "%s\n", snmpify_last_error());
}
snmpify_client_free(c);
```

SNMPv3: `snmpify_user_new("monitor", "SHA-256", "auth-pass", "AES",
"priv-pass")` and `snmpify_client_new_v3(target, user, NULL)`. Walks:
`snmpify_walk_all`, or `snmpify_walk_new` / `snmpify_walk_next` one
binding at a time. Errors: a status code, `snmpify_last_error()`, and for
agent errors `snmpify_last_error_status()` / `_index()`.

## C++

```cpp
#include <snmpify.hpp>

snmpify::Client c("192.0.2.1", "public");
std::cout << c.get("1.3.6.1.2.1.1.5.0").text << "\n";
snmpify::Mib mib;
for (const auto& vb : c.walk(mib.resolve("IF-MIB::ifDescr")))
    std::cout << mib.name(vb.oid) << " = " << vb.text << "\n";
```

Errors throw `snmpify::Error`. Also `snmpify::Receiver` (traps and
informs), `snmpify::Agent` and `snmpify::User`.

## Examples

`examples/get.c` (a tiny `snmpget`, names through the MIBs),
`examples/walk.cpp` and `examples/trapd.c`; built with
`-DSNMPIFY_EXAMPLES=ON`.

## Tests

`cargo test -p snmpify-c` builds `tests/test.c` and `tests/test.cpp`
against the static library and runs them (an agent made with the C API
answers them; with `SNMPIFY_AGENT` set they also query net-snmp's snmpd).
`-DSNMPIFY_TESTS=ON` runs them under CTest with the shared and static
libraries. Both pass AddressSanitizer, UndefinedBehaviorSanitizer and
LeakSanitizer.
