//! Unit tests of the USM: known-answer vectors, every combination, tampering.

use super::*;
use crate::v3::UsmParams;
use crate::{Pdu, Value, VarBind};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

const RFC_ENGINE: &str = "00 00 00 00 00 00 00 00 00 00 00 02";

#[test]
fn rfc3414_a3_md5() {
    let ku = AuthProtocol::Md5.password_to_key(b"maplesyrup").unwrap();
    assert_eq!(ku, hex("9f af 32 83 88 4e 92 83 4e bc 98 47 d8 ed d9 63"));
    let kul = AuthProtocol::Md5.localize(&ku, &hex(RFC_ENGINE));
    assert_eq!(kul, hex("52 6f 5e ed 9f cc e2 6f 89 64 c2 93 07 87 d8 2b"));
}

#[test]
fn rfc3414_a3_sha1() {
    let ku = AuthProtocol::Sha1.password_to_key(b"maplesyrup").unwrap();
    assert_eq!(
        ku,
        hex("9f b5 cc 03 81 49 7b 37 93 52 89 39 ff 78 8d 5d 79 14 52 11")
    );
    let kul = AuthProtocol::Sha1.localize(&ku, &hex(RFC_ENGINE));
    assert_eq!(
        kul,
        hex("66 95 fe bc 92 88 e3 62 82 23 5f c7 15 1f 12 84 97 b3 8f 3f")
    );
}

#[test]
fn key_lengths_and_extension() {
    let e = hex(RFC_ENGINE);
    for a in AuthProtocol::ALL {
        let ku = a.password_to_key(b"maplesyrup").unwrap();
        assert_eq!(ku.len(), a.key_len());
        assert_eq!(a.localize(&ku, &e).len(), a.key_len());
        for p in PrivProtocol::ALL {
            let k = p.localize(a, &ku, &e);
            assert_eq!(k.len(), p.key_len());
            // The extension starts with the plain localized key.
            let kul = a.localize(&ku, &e);
            let n = kul.len().min(p.key_len());
            assert_eq!(k[..n], kul[..n]);
            if kul.len() < p.key_len() {
                assert_eq!(k[kul.len()..], a.digest(&kul)[..p.key_len() - kul.len()]);
            }
        }
    }
    assert_eq!(
        AuthProtocol::Md5.password_to_key(b"short"),
        Err(UsmError::PasswordTooShort)
    );
}

#[test]
fn hmac_sha256_rfc4231_case2() {
    // RFC 4231 test case 2, truncated to RFC 7860's 24 octets.
    let mac = AuthProtocol::Sha256.mac(b"Jefe", b"what do ya want for nothing?");
    assert_eq!(mac, hex("5bdcc146bf60754e6a042426089575c75a003f089d273983"));
    let mac = AuthProtocol::Md5.mac(b"Jefe", b"what do ya want for nothing?");
    // RFC 2104 / 2202 HMAC-MD5 test case 2, first 12 octets.
    assert_eq!(mac, hex("750c783e6ab0b503eaa86e31"));
}

#[test]
fn aes128_cfb_nist_vector() {
    // NIST SP 800-38A F.3.13 (CFB128-AES128.Encrypt), first two blocks.
    let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
    let iv: [u8; 16] = hex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let plain = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51");
    let mut data = plain.clone();
    aes_cfb(PrivProtocol::Aes128, &key, &iv, &mut data, false);
    assert_eq!(
        data,
        hex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b")
    );
    aes_cfb(PrivProtocol::Aes128, &key, &iv, &mut data, true);
    assert_eq!(data, plain);
    // A partial last block.
    let mut d = plain[..21].to_vec();
    aes_cfb(PrivProtocol::Aes128, &key, &iv, &mut d, false);
    assert_eq!(
        d[..],
        hex("3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b")[..21]
    );
}

#[test]
fn des_cbc_known_vector() {
    // FIPS 81 CBC example: key 0123456789abcdef, IV 1234567890abcdef
    // ("Now is the time for all ").
    let mut key = hex("0123456789abcdef");
    key.extend(hex("1234567890abcdef")); // pre-IV; salt 0 → IV = pre-IV
    let mut data = b"Now is the time for all ".to_vec();
    des_cbc(PrivProtocol::Des, &key, &[0; 8], &mut data, false);
    assert_eq!(
        data,
        hex("e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6")
    );
    des_cbc(PrivProtocol::Des, &key, &[0; 8], &mut data, true);
    assert_eq!(data, b"Now is the time for all ");
}

fn request(engine: &[u8]) -> V3Message {
    V3Message {
        msg_id: 99,
        max_size: 65507,
        flags: flags::REPORTABLE,
        usm: UsmParams {
            engine_boots: 3,
            engine_time: 4567,
            ..UsmParams::default()
        },
        data: ScopedPduData::Plaintext(ScopedPdu::new(
            engine.to_vec(),
            Vec::new(),
            Pdu::set(
                5,
                vec![VarBind::new(
                    [1, 3, 6, 1, 2, 1, 1, 4, 0],
                    Value::from("an odd-length value: 37 octets long!!"),
                )],
            ),
        )),
    }
}

fn users() -> Vec<UsmUser> {
    let mut v = vec![UsmUser::new("none")];
    for a in AuthProtocol::ALL {
        let u = UsmUser::new(format!("{a}"))
            .with_auth(a, "auth-pass")
            .unwrap();
        v.push(u.clone());
        for p in PrivProtocol::ALL {
            v.push(u.clone().with_privacy(p, "priv-pass").unwrap());
        }
    }
    v
}

#[test]
fn seal_open_every_combination() {
    let engine = hex("80001f8880 0102030405");
    for (i, u) in users().iter().enumerate() {
        let k = u.localize(&engine);
        let bytes = k.seal(request(&engine), i as u64).unwrap();
        let m = k.open(&bytes).unwrap();
        assert_eq!(SecurityLevel::from_flags(m.flags), u.level(), "{u:?}");
        assert_eq!(m.flags & flags::REPORTABLE, flags::REPORTABLE);
        assert_eq!(m.usm.user_name, u.name());
        assert_eq!(m.usm.engine_id, engine);
        assert_eq!(m.data, request(&engine).data, "{u:?}");
        if u.level() == SecurityLevel::AuthPriv {
            // The plaintext is not in the message.
            assert!(!bytes.windows(10).any(|w| w == b"an odd-len"), "{u:?}");
        }
    }
}

#[test]
fn tampering_is_detected() {
    let engine = hex("80001f8880 0102030405");
    for u in users()
        .iter()
        .filter(|u| u.level() != SecurityLevel::NoAuthNoPriv)
    {
        let k = u.localize(&engine);
        let bytes = k.seal(request(&engine), 1).unwrap();
        // Flip each bit of the message in turn (sampled to keep it quick).
        for i in (0..bytes.len()).step_by(7) {
            let mut b = bytes.clone();
            b[i] ^= 0x10;
            assert!(k.open(&b).is_err(), "{u:?} byte {i}");
        }
        // Another engine's keys, another password.
        let other = u.localize(&hex("80001f8880 0102030406"));
        assert!(other.open(&bytes).is_err());
        let wrong = UsmUser::new(u.name())
            .with_auth(u.auth_protocol().unwrap(), "auth-pas5")
            .unwrap()
            .localize(&engine);
        assert_eq!(wrong.open(&bytes).unwrap_err(), UsmError::WrongDigest);
        // A user without auth cannot open it.
        let none = UsmUser::new(u.name()).localize(&engine);
        assert_eq!(
            none.open(&bytes).unwrap_err(),
            UsmError::UnsupportedSecurityLevel
        );
    }
}

#[test]
fn wrong_privacy_key_is_a_decryption_error() {
    let engine = hex("80001f8880 0102030405");
    for p in PrivProtocol::ALL {
        let u = UsmUser::new("u")
            .with_auth(AuthProtocol::Sha1, "auth-pass")
            .unwrap();
        let right = u.clone().with_privacy(p, "priv-pass").unwrap();
        let wrong = u.with_privacy(p, "priv-pas5").unwrap();
        let bytes = right.localize(&engine).seal(request(&engine), 9).unwrap();
        // Same auth key, so the HMAC passes; the PDU decrypts to garbage.
        assert_eq!(
            wrong.localize(&engine).open(&bytes).unwrap_err(),
            UsmError::DecryptionError,
            "{p}"
        );
    }
}

#[test]
fn open_checks_names_engines_and_flags() {
    let engine = hex("80001f8880 0102030405");
    let u = UsmUser::new("alice")
        .with_auth(AuthProtocol::Sha256, "auth-pass")
        .unwrap();
    let k = u.localize(&engine);
    let bytes = k.seal(request(&engine), 1).unwrap();
    let bob = UsmUser::new("bob")
        .with_auth(AuthProtocol::Sha256, "auth-pass")
        .unwrap()
        .localize(&engine);
    assert_eq!(bob.open(&bytes).unwrap_err(), UsmError::UnknownUserName);
    let other = u.localize(&hex("01"));
    assert_eq!(other.open(&bytes).unwrap_err(), UsmError::UnknownEngineId);
    // A truncated MAC.
    let mut m = V3Message::decode(&bytes).unwrap();
    m.usm.auth_params.truncate(12);
    assert_eq!(k.open(&m.encode()).unwrap_err(), UsmError::WrongDigest);
    // Privacy flag on a plaintext PDU, and an encrypted PDU without it.
    let mut m = V3Message::decode(&bytes).unwrap();
    m.flags |= flags::PRIV;
    assert_eq!(
        UsmUser::new("x").localize(&engine).open(&{
            m.flags = flags::REPORTABLE;
            m.data = ScopedPduData::Encrypted(vec![0; 16]);
            m.usm.auth_params.clear();
            m.encode()
        }),
        Err(UsmError::UnsupportedSecurityLevel)
    );
    // Sealing an already encrypted message, and long names.
    let mut r = request(&engine);
    r.data = ScopedPduData::Encrypted(vec![1]);
    assert_eq!(k.seal(r, 0), Err(UsmError::UnsupportedSecurityLevel));
    let long = UsmUser::new([b'a'; 33]).localize(&engine);
    assert_eq!(
        long.seal(request(&engine), 0),
        Err(UsmError::UserNameTooLong)
    );
    // Privacy without auth; privacy params of the wrong size.
    assert_eq!(
        UsmUser::new("x")
            .with_privacy(PrivProtocol::Des, "priv-pass")
            .unwrap_err(),
        UsmError::PrivacyWithoutAuth
    );
    let p = u
        .clone()
        .with_privacy(PrivProtocol::Des, "priv-pass")
        .unwrap();
    let pk = p.localize(&engine);
    let mut m = V3Message::decode(&pk.seal(request(&engine), 1).unwrap()).unwrap();
    m.usm.priv_params.pop();
    assert_eq!(
        PrivProtocol::Des.decrypt(&[0; 16], 0, 0, &m.usm.priv_params, &[0; 8]),
        Err(UsmError::DecryptionError)
    );
    assert_eq!(
        PrivProtocol::Des.decrypt(&[0; 16], 0, 0, &[0; 8], &[0; 7]),
        Err(UsmError::DecryptionError)
    );
}

#[test]
fn debug_never_shows_keys_and_accessors() {
    let u = UsmUser::new("alice")
        .with_auth(AuthProtocol::Md5, "auth-pass")
        .unwrap()
        .with_privacy(PrivProtocol::Aes256, "priv-pass")
        .unwrap();
    let k = u.localize(b"e");
    let s = format!("{u:?} {k:?}");
    assert!(
        s.contains("alice") && s.contains("Md5") && s.contains("Aes256"),
        "{s}"
    );
    // No run of key bytes, as Debug would print a Vec.
    let ku = AuthProtocol::Md5.password_to_key(b"auth-pass").unwrap();
    let key = AuthProtocol::Md5.localize(&ku, b"e");
    let run = format!("{:?}", &key[..3]);
    assert!(
        !s.contains(run.trim_matches(|c| c == '[' || c == ']')),
        "{s}"
    );
    assert_eq!(k.name(), b"alice");
    assert_eq!(k.engine_id(), b"e");
    assert_eq!(k.level(), SecurityLevel::AuthPriv);
    assert_eq!(u.priv_protocol(), Some(PrivProtocol::Aes256));
    // with_auth again drops the privacy key (it used the other hash).
    let u2 = u.with_auth(AuthProtocol::Sha1, "auth-pass").unwrap();
    assert_eq!(u2.level(), SecurityLevel::AuthNoPriv);
    for a in AuthProtocol::ALL {
        assert!(!a.to_string().is_empty());
    }
    for p in PrivProtocol::ALL {
        assert!(!p.to_string().is_empty());
    }
    for l in [
        SecurityLevel::NoAuthNoPriv,
        SecurityLevel::AuthNoPriv,
        SecurityLevel::AuthPriv,
    ] {
        assert_eq!(SecurityLevel::from_flags(l.flags() | flags::REPORTABLE), l);
    }
    assert!(UsmError::Decode(crate::DecodeError::new(
        crate::DecodeErrorKind::UnexpectedEnd,
        0
    ))
    .to_string()
    .contains("unexpected end"));
}

#[test]
fn error_messages() {
    let all = [
        UsmError::PasswordTooShort,
        UsmError::UserNameTooLong,
        UsmError::PrivacyWithoutAuth,
        UsmError::UnsupportedSecurityLevel,
        UsmError::UnknownUserName,
        UsmError::UnknownEngineId,
        UsmError::WrongDigest,
        UsmError::DecryptionError,
    ];
    let mut seen = std::collections::HashSet::new();
    for e in all {
        assert!(std::error::Error::source(&e).is_none());
        assert!(seen.insert(e.to_string()), "{e:?}");
    }
    let d: UsmError = crate::DecodeError::new(crate::DecodeErrorKind::TrailingData, 3).into();
    assert!(std::error::Error::source(&d).is_some());
}

#[test]
fn privacy_flag_without_privacy_keys() {
    // An authPriv message opened by the authNoPriv user with the same
    // auth key: the HMAC passes, decryption is impossible.
    let engine = hex("80001f8880 0102030405");
    let u = UsmUser::new("u")
        .with_auth(AuthProtocol::Sha1, "auth-pass")
        .unwrap();
    let p = u
        .clone()
        .with_privacy(PrivProtocol::Aes128, "priv-pass")
        .unwrap();
    let bytes = p.localize(&engine).seal(request(&engine), 1).unwrap();
    assert_eq!(
        u.localize(&engine).open(&bytes).unwrap_err(),
        UsmError::UnsupportedSecurityLevel
    );
}

#[test]
fn aes_key_extensions_match_pysnmp() {
    // pysnmp 7.1 (eso/priv/aesbase.py), password "maplesyrup", engine id
    // 00…02 (RFC 3414 A.3): Blumenthal and Reeder (Cisco) extensions.
    let e = hex(RFC_ENGINE);
    let cases = [
        (
            AuthProtocol::Md5,
            PrivProtocol::Aes192Cisco,
            "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0",
        ),
        (
            AuthProtocol::Md5,
            PrivProtocol::Aes256Cisco,
            "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0a3a40abfac5acc12",
        ),
        (
            AuthProtocol::Md5,
            PrivProtocol::Aes192,
            "526f5eed9fcce26f8964c2930787d82bfa24a92467426c2f",
        ),
        (
            AuthProtocol::Md5,
            PrivProtocol::Aes256,
            "526f5eed9fcce26f8964c2930787d82bfa24a92467426c2f4b09192be10dfaec",
        ),
        (
            AuthProtocol::Sha1,
            PrivProtocol::Aes192Cisco,
            "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78",
        ),
        (
            AuthProtocol::Sha1,
            PrivProtocol::Aes256Cisco,
            "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78936ba6e7d19dfd9c",
        ),
        (
            AuthProtocol::Sha1,
            PrivProtocol::Aes192,
            "6695febc9288e36282235fc7151f128497b38f3f505e07eb",
        ),
        (
            AuthProtocol::Sha1,
            PrivProtocol::Aes256,
            "6695febc9288e36282235fc7151f128497b38f3f505e07eb9af25568fa1f5dbe",
        ),
        (
            AuthProtocol::Sha256,
            PrivProtocol::Aes256Cisco,
            "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b",
        ),
        (
            AuthProtocol::Sha256,
            PrivProtocol::Aes256,
            "8982e0e549e866db361a6b625d84cccc11162d453ee8ce3a6445c2d6776f0f8b",
        ),
    ];
    for (a, p, want) in cases {
        let ku = a.password_to_key(b"maplesyrup").unwrap();
        assert_eq!(p.localize(a, &ku, &e), hex(want), "{a} {p}");
    }
    // Sealed and opened like the others.
    let engine = hex("80001f8880 0102030405");
    for p in [PrivProtocol::Aes192Cisco, PrivProtocol::Aes256Cisco] {
        let u = UsmUser::new("cisco")
            .with_auth(AuthProtocol::Sha1, "auth-pass")
            .unwrap()
            .with_privacy(p, "priv-pass")
            .unwrap();
        let k = u.localize(&engine);
        let b = k.seal(request(&engine), 5).unwrap();
        assert_eq!(k.open(&b).unwrap().data, request(&engine).data);
        // Not interchangeable with the standard extension.
        let std = UsmUser::new("cisco")
            .with_auth(AuthProtocol::Sha1, "auth-pass")
            .unwrap()
            .with_privacy(
                if p == PrivProtocol::Aes192Cisco {
                    PrivProtocol::Aes192
                } else {
                    PrivProtocol::Aes256
                },
                "priv-pass",
            )
            .unwrap()
            .localize(&engine);
        assert_eq!(std.open(&b).unwrap_err(), UsmError::DecryptionError);
        assert!(p.to_string().ends_with("-C"));
    }
}

#[test]
fn des3_matches_pysnmp() {
    // pysnmp 7.1 (eso/priv/des3.py) localized keys for "maplesyrup",
    // engine 00…02: the Reeder extension to 32 octets (3DES key ‖ pre-IV).
    let e = hex(RFC_ENGINE);
    for (a, want) in [
        (
            AuthProtocol::Md5,
            "526f5eed9fcce26f8964c2930787d82b79eff44a90650ee0a3a40abfac5acc12",
        ),
        (
            AuthProtocol::Sha1,
            "6695febc9288e36282235fc7151f128497b38f3f9b8b6d78936ba6e7d19dfd9c",
        ),
    ] {
        let ku = a.password_to_key(b"maplesyrup").unwrap();
        assert_eq!(PrivProtocol::Des3.localize(a, &ku, &e), hex(want), "{a}");
    }
    let engine = hex("80001f8880 0102030405");
    let u = UsmUser::new("d3")
        .with_auth(AuthProtocol::Sha256, "auth-pass")
        .unwrap()
        .with_privacy(PrivProtocol::Des3, "priv-pass")
        .unwrap();
    let k = u.localize(&engine);
    let b = k.seal(request(&engine), 3).unwrap();
    assert_eq!(k.open(&b).unwrap().data, request(&engine).data);
    assert!(!b.windows(10).any(|w| w == b"an odd-len"));
    assert_eq!(PrivProtocol::Des3.to_string(), "3DES");
    assert_eq!(PrivProtocol::Des3.key_len(), 32);
}
