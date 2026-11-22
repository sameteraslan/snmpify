//! MIB parsing, resolution and formatting.

use super::*;

const TEST_MIB: &str = r#"
-- A vendor MIB in SMIv2, exercising most constructs.
ACME-MIB DEFINITIONS ::= BEGIN

IMPORTS
    MODULE-IDENTITY, OBJECT-TYPE, NOTIFICATION-TYPE, Integer32,
    Counter64, enterprises                      FROM SNMPv2-SMI
    TEXTUAL-CONVENTION, DisplayString, MacAddress FROM SNMPv2-TC
    MODULE-COMPLIANCE, OBJECT-GROUP             FROM SNMPv2-CONF;

acme MODULE-IDENTITY
    LAST-UPDATED "202611220000Z"
    ORGANIZATION "Acme"
    CONTACT-INFO "nobody -- not a comment inside a string"
    DESCRIPTION  "Test module."
    REVISION     "202611220000Z"
    DESCRIPTION  "First."
    ::= { enterprises 99999 }

AcmeTemp ::= TEXTUAL-CONVENTION
    DISPLAY-HINT "d-1"
    STATUS       current
    DESCRIPTION  "Tenths of a degree."
    SYNTAX       Integer32 (-1000..1000)

AcmeColour ::= TEXTUAL-CONVENTION
    STATUS       current
    DESCRIPTION  "Colours."
    SYNTAX       INTEGER { red(1), green(2), blue(3) }

acmeObjects OBJECT IDENTIFIER ::= { acme 1 }

acmeTemp OBJECT-TYPE
    SYNTAX      AcmeTemp
    UNITS       "0.1 degrees C"
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Temperature."
    ::= { acmeObjects 1 }

acmePortTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF AcmePortEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Ports."
    ::= { acmeObjects 2 }

acmePortEntry OBJECT-TYPE
    SYNTAX      AcmePortEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "A port."
    INDEX       { acmePortIndex }
    ::= { acmePortTable 1 }

AcmePortEntry ::= SEQUENCE {
    acmePortIndex  Integer32,
    acmePortMac    MacAddress,
    acmePortColour AcmeColour,
    acmePortState  INTEGER,
    acmePortOctets Counter64,
    acmePortFlags  BITS
}

acmePortIndex OBJECT-TYPE
    SYNTAX      Integer32 (1..65535)
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "Index."
    ::= { acmePortEntry 1 }

acmePortMac OBJECT-TYPE
    SYNTAX      MacAddress
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "MAC."
    ::= { acmePortEntry 2 }

acmePortColour OBJECT-TYPE
    SYNTAX      AcmeColour
    MAX-ACCESS  read-write
    STATUS      current
    DESCRIPTION "Colour."
    DEFVAL      { red }
    ::= { acmePortEntry 3 }

acmePortState OBJECT-TYPE
    SYNTAX      INTEGER { up(1), down(2), testing(-1) }
    MAX-ACCESS  read-only
    STATUS      deprecated
    DESCRIPTION "State."
    ::= { acmePortEntry 4 }

acmePortOctets OBJECT-TYPE
    SYNTAX      Counter64
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Octets."
    ::= { acmePortEntry 5 }

acmePortFlags OBJECT-TYPE
    SYNTAX      BITS { up(0), promisc(1), lldp(9) }
    MAX-ACCESS  read-only
    STATUS      current
    DESCRIPTION "Flags."
    ::= { acmePortEntry 6 }

acmePortExtTable OBJECT-TYPE
    SYNTAX      SEQUENCE OF AcmePortExtEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "More."
    ::= { acmeObjects 3 }

acmePortExtEntry OBJECT-TYPE
    SYNTAX      AcmePortExtEntry
    MAX-ACCESS  not-accessible
    STATUS      current
    DESCRIPTION "More."
    AUGMENTS    { acmePortEntry }
    ::= { acmePortExtTable 1 }

acmeAlarm NOTIFICATION-TYPE
    OBJECTS     { acmeTemp }
    STATUS      current
    DESCRIPTION "Hot."
    ::= { acme 0 1 }

acmeGroup OBJECT-GROUP
    OBJECTS { acmeTemp, acmePortMac }
    STATUS  current
    DESCRIPTION "Objects."
    ::= { acme 2 1 }

acmeCompliance MODULE-COMPLIANCE
    STATUS current
    DESCRIPTION "Compliance."
    MODULE -- this module
        MANDATORY-GROUPS { acmeGroup }
        OBJECT acmePortColour
            SYNTAX INTEGER { red(1) }
            MIN-ACCESS read-only
            DESCRIPTION "Read-only is fine."
    ::= { acme 2 2 }

END

-- An SMIv1 module in the same file.
ACME-V1-MIB DEFINITIONS ::= BEGIN
IMPORTS enterprises FROM RFC1155-SMI
        OBJECT-TYPE FROM RFC-1212
        TRAP-TYPE FROM RFC-1215;

acmeOld OBJECT IDENTIFIER ::= { enterprises 99998 }

acmeOldName OBJECT-TYPE
    SYNTAX  DisplayString (SIZE (0..32))
    ACCESS  read-write
    STATUS  mandatory
    DESCRIPTION "Name."
    ::= { acmeOld 1 }

acmeOldTrap TRAP-TYPE
    ENTERPRISE acmeOld
    VARIABLES  { acmeOldName }
    DESCRIPTION "Old trap."
    ::= 7
END
"#;

fn mib() -> Mib {
    let mut m = Mib::standard();
    let mods = m.load_str(TEST_MIB).unwrap();
    assert_eq!(mods, ["ACME-MIB", "ACME-V1-MIB"]);
    assert!(m.unresolved().is_empty(), "{:?}", m.unresolved());
    m
}

fn oid(s: &str) -> Oid {
    s.parse().unwrap()
}

#[test]
fn standard_objects() {
    let m = Mib::standard();
    for (name, num) in [
        ("SNMPv2-MIB::sysDescr", "1.3.6.1.2.1.1.1"),
        ("sysUpTime.0", "1.3.6.1.2.1.1.3.0"),
        ("IF-MIB::ifTable", "1.3.6.1.2.1.2.2"),
        ("ifHCInOctets.5", "1.3.6.1.2.1.31.1.1.1.6.5"),
        ("ifName", "1.3.6.1.2.1.31.1.1.1.1"),
        (
            "HOST-RESOURCES-MIB::hrStorageSize",
            "1.3.6.1.2.1.25.2.3.1.5",
        ),
        ("IP-MIB::ipAdEntAddr", "1.3.6.1.2.1.4.20.1.1"),
        ("TCP-MIB::tcpConnectionState", "1.3.6.1.2.1.6.19.1.7"),
        ("UDP-MIB::udpInDatagrams", "1.3.6.1.2.1.7.1"),
        ("ENTITY-MIB::entPhysicalDescr", "1.3.6.1.2.1.47.1.1.1.1.2"),
        (
            "SNMP-USER-BASED-SM-MIB::usmStatsWrongDigests",
            "1.3.6.1.6.3.15.1.1.5",
        ),
        ("SNMP-FRAMEWORK-MIB::snmpEngineID", "1.3.6.1.6.3.10.2.1.1"),
        ("SNMPv2-MIB::coldStart", "1.3.6.1.6.3.1.1.5.1"),
        ("IF-MIB::linkDown", "1.3.6.1.6.3.1.1.5.3"),
        ("UCD-SNMP-MIB::memTotalReal", "1.3.6.1.4.1.2021.4.5"),
        ("UCD-SNMP-MIB::laLoad", "1.3.6.1.4.1.2021.10.1.3"),
        ("NET-SNMP-MIB::netSnmpAgentOIDs", "1.3.6.1.4.1.8072.3.2"),
        ("BRIDGE-MIB::dot1dTpFdbAddress", "1.3.6.1.2.1.17.4.3.1.1"),
        (
            "IP-FORWARD-MIB::inetCidrRouteNextHop",
            "1.3.6.1.2.1.4.24.7.1.6",
        ),
        ("BGP4-MIB::bgpPeerState", "1.3.6.1.2.1.15.3.1.2"),
        ("enterprises", "1.3.6.1.4.1"),
        ("mib-2", "1.3.6.1.2.1"),
    ] {
        assert_eq!(m.resolve(name).unwrap().to_string(), num, "{name}");
    }
    assert!(STANDARD_MODULES.len() >= 40);
    for (module, name) in [("IF-MIB", "ifIndex"), ("SNMPv2-MIB", "sysName")] {
        assert!(m.object(&format!("{module}::{name}")).is_some());
    }
    // SMIv2 names win over RFC1213-MIB's.
    assert_eq!(m.name(&oid("1.3.6.1.2.1.1.3.0")), "SNMPv2-MIB::sysUpTime.0");
    assert_eq!(m.name(&oid("1.3.6.1.2.1.2.2.1.2.7")), "IF-MIB::ifDescr.7");
    let t = m.object("IF-MIB::ifTable").unwrap();
    assert_eq!(t.kind, Kind::Table);
    let e = m.object("IF-MIB::ifEntry").unwrap();
    assert_eq!(
        (e.kind, e.index.as_slice()),
        (Kind::Row, &["ifIndex".to_string()][..])
    );
    let x = m.object("IF-MIB::ifXEntry").unwrap();
    assert_eq!(x.index, ["ifIndex"], "AUGMENTS ifEntry");
    let c = m.object("IF-MIB::ifOperStatus").unwrap();
    assert_eq!(
        (c.kind, c.base, c.access),
        (
            Kind::Column,
            Some(BaseType::Integer),
            Some(Access::ReadOnly)
        )
    );
    assert_eq!(c.enum_label(2), Some("down"));
    let s = m.object("SNMPv2-MIB::sysContact").unwrap();
    assert_eq!(
        (s.kind, s.access, s.display_hint.as_deref()),
        (Kind::Scalar, Some(Access::ReadWrite), Some("255a"))
    );
    assert_eq!(
        m.object("SNMPv2-MIB::coldStart").unwrap().kind,
        Kind::Notification
    );
    assert_eq!(
        m.object("IF-MIB::ifMIB").unwrap().kind,
        Kind::ModuleIdentity
    );
    let tc = m
        .textual_conventions()
        .find(|t| t.name == "PhysAddress" && t.module == "SNMPv2-TC")
        .unwrap();
    assert_eq!(tc.display_hint.as_deref(), Some("1x:"));
}

#[test]
fn loads_vendor_mibs_against_the_standard_ones() {
    let m = mib();
    let o = m.object("ACME-MIB::acmeTemp").unwrap();
    assert_eq!(o.oid, oid("1.3.6.1.4.1.99999.1.1"));
    assert_eq!((o.kind, o.base), (Kind::Scalar, Some(BaseType::Integer)));
    assert_eq!(o.units.as_deref(), Some("0.1 degrees C"));
    assert_eq!(o.display_hint.as_deref(), Some("d-1"));
    assert_eq!(m.object("acmePortTable").unwrap().kind, Kind::Table);
    assert_eq!(m.object("acmePortEntry").unwrap().kind, Kind::Row);
    assert_eq!(
        m.object("acmePortExtEntry").unwrap().index,
        ["acmePortIndex"]
    );
    let mac = m.object("acmePortMac").unwrap();
    assert_eq!(
        (mac.kind, mac.base, mac.display_hint.as_deref()),
        (Kind::Column, Some(BaseType::OctetString), Some("1x:"))
    );
    let col = m.object("acmePortColour").unwrap();
    assert_eq!(
        col.enums,
        [(1, "red".into()), (2, "green".into()), (3, "blue".into())]
    );
    assert_eq!(
        col.access,
        Some(Access::ReadWrite),
        "not the compliance's MIN-ACCESS"
    );
    let st = m.object("acmePortState").unwrap();
    assert_eq!(st.enum_label(-1), Some("testing"));
    assert_eq!(st.status, Some(Status::Deprecated));
    assert_eq!(
        m.object("acmePortFlags").unwrap().base,
        Some(BaseType::Bits)
    );
    assert_eq!(
        m.object("acmeAlarm").unwrap().oid,
        oid("1.3.6.1.4.1.99999.0.1")
    );
    assert_eq!(m.object("acmeGroup").unwrap().kind, Kind::Group);
    assert_eq!(m.object("acmeCompliance").unwrap().kind, Kind::Compliance);
    // SMIv1.
    let old = m.object("ACME-V1-MIB::acmeOldName").unwrap();
    assert_eq!(
        (old.access, old.status, old.base),
        (
            Some(Access::ReadWrite),
            Some(Status::Mandatory),
            Some(BaseType::OctetString)
        )
    );
    let trap = m.object("acmeOldTrap").unwrap();
    assert_eq!(
        (trap.kind, trap.oid.to_string().as_str()),
        (Kind::Notification, "1.3.6.1.4.1.99998.0.7")
    );
    assert!(format!("{m:?}").contains("objects"));
    assert!(m.modules().contains(&"ACME-MIB".to_string()));
}

#[test]
fn names_and_values() {
    let m = mib();
    let row = |col: u32| oid(&format!("1.3.6.1.4.1.99999.1.2.1.{col}.17"));
    assert_eq!(m.name(&row(2)), "ACME-MIB::acmePortMac.17");
    assert_eq!(m.resolve("ACME-MIB::acmePortMac.17").unwrap(), row(2));
    assert_eq!(m.resolve(".1.3.6.1").unwrap(), oid("1.3.6.1"));
    let fmt = |o: Oid, v: Value| m.format(&VarBind::new(o, v));
    assert_eq!(
        fmt(
            row(2),
            Value::OctetString(vec![0, 0x1b, 0x21, 0x3a, 0xc6, 8])
        ),
        "ACME-MIB::acmePortMac.17 = 00:1b:21:3a:c6:08"
    );
    assert_eq!(
        fmt(row(3), Value::Integer(2)),
        "ACME-MIB::acmePortColour.17 = green(2)"
    );
    assert_eq!(
        fmt(row(3), Value::Integer(9)),
        "ACME-MIB::acmePortColour.17 = 9"
    );
    assert_eq!(
        fmt(oid("1.3.6.1.4.1.99999.1.1.0"), Value::Integer(215)),
        "ACME-MIB::acmeTemp.0 = 21.5"
    );
    // Bits: up(0) and lldp(9) set.
    assert_eq!(
        m.format_value(&row(6), &Value::OctetString(vec![0x80, 0x40])),
        "up(0) lldp(9)"
    );
    assert_eq!(
        m.format_value(
            &oid("1.3.6.1.2.1.1.2.0"),
            &Value::ObjectId(oid("1.3.6.1.4.1.8072.3.2.10"))
        ),
        "NET-SNMP-TC::linux"
    );
    assert_eq!(
        m.format_value(&oid("1.3.6.1.2.1.1.5.0"), &Value::from("router")),
        "router"
    );
    assert_eq!(m.format_value(&row(5), &Value::Counter64(5)), "5");
    // Unknown names and OIDs.
    assert_eq!(m.name(&oid("2.999.1")), "2.999.1");
    assert!(matches!(
        m.resolve("noSuchThing"),
        Err(MibError::UnknownName(_))
    ));
    assert!(m.resolve("ifDescr.x").is_err());
    assert!(m.resolve("1.x").is_err());
    assert!(m.object("NOPE::ifDescr").is_none());
    assert_eq!(m.name(&Oid::from([1u32])), "1");
}

#[test]
fn modules_in_any_order_and_errors() {
    // The child module first: pending until its parent arrives.
    let mut m = Mib::new();
    m.load_str("CHILD DEFINITIONS ::= BEGIN IMPORTS base FROM BASE; leaf OBJECT IDENTIFIER ::= { base 5 } END")
        .unwrap();
    assert_eq!(m.unresolved(), ["CHILD::leaf"]);
    m.load_str(
        "BASE DEFINITIONS ::= BEGIN base OBJECT IDENTIFIER ::= { iso org(3) dod(6) 1 4 1 7 } END",
    )
    .unwrap();
    assert!(m.unresolved().is_empty());
    assert_eq!(m.resolve("CHILD::leaf").unwrap(), oid("1.3.6.1.4.1.7.5"));
    assert_eq!(m.resolve("dod").unwrap(), oid("1.3.6"));
    for bad in [
        "",
        "X DEFINITIONS ::= BEGIN",
        "X DEFINITIONS ::= BEGIN a OBJECT IDENTIFIER ::= { iso x(y) } END",
        "X DEFINITIONS ::= BEGIN a OBJECT-TYPE SYNTAX INTEGER { a(x) } ::= { iso 1 } END",
        "X DEFINITIONS ::= BEGIN t TRAP-TYPE VARIABLES { a } ::= 1 END",
        "X DEFINITIONS BEGIN END",
        "X DEFINITIONS ::= START END",
        "X DEFINITIONS ::= BEGIN s \"unterminated END",
    ] {
        assert!(Mib::new().load_str(bad).is_err(), "{bad}");
    }
    let e = Mib::new().load_str("X DEFINITIONS ::= BEGIN").unwrap_err();
    assert!(e.to_string().contains("line"), "{e}");
    assert!(Mib::new()
        .load_file("/no/such/file")
        .unwrap_err()
        .to_string()
        .contains("/no/such/file"));
    assert!(Mib::new().load_dir("/no/such/dir").is_err());
    assert_eq!(
        MibError::UnknownName("x".into()).to_string(),
        "unknown MIB name \"x\""
    );
}

#[test]
fn load_dir_reports_failures() {
    let dir = std::env::temp_dir().join(format!("snmpify-mibs-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("ACME-MIB.txt"), TEST_MIB).unwrap();
    std::fs::write(dir.join("README"), "not a MIB").unwrap();
    let mut m = Mib::standard();
    let r = m.load_dir(&dir).unwrap();
    assert_eq!(r.loaded, ["ACME-MIB", "ACME-V1-MIB"]);
    assert_eq!(r.failed.len(), 1);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn mutated_mib_text_never_panics() {
    // xorshift: deterministic.
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let mut rnd = move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    };
    let base = TEST_MIB.as_bytes();
    for _ in 0..3000 {
        let mut t = base.to_vec();
        for _ in 0..1 + rnd() % 6 {
            let i = (rnd() as usize) % t.len();
            match rnd() % 4 {
                0 => t[i] = b"{}()-\":=.;,a1 \n"[(rnd() % 15) as usize],
                1 => {
                    t.remove(i);
                }
                2 => t.truncate(i.max(1)),
                _ => t.insert(i, b"{}-\""[(rnd() % 4) as usize]),
            }
        }
        let mut m = Mib::new();
        let _ = m.load_str(&String::from_utf8_lossy(&t));
    }
}
