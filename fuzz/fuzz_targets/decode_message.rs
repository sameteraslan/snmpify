//! Any input: decoding never panics, and whatever decodes re-encodes to a
//! message that decodes to the same value. SNMPv3 input also goes through
//! USM verification and decryption.
//!
//!     cargo +nightly fuzz run decode_message
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use snmpify::usm::{AuthProtocol, LocalizedUser, PrivProtocol, UsmUser};
use snmpify::v3::Message;
use snmpify::CommunityMessage;

fn users() -> &'static [LocalizedUser] {
    static USERS: OnceLock<Vec<LocalizedUser>> = OnceLock::new();
    USERS.get_or_init(|| {
        let e = [0x80, 0, 0x1f, 0x88, 0x80, 1, 2, 3, 4];
        let u = UsmUser::new("u")
            .with_auth(AuthProtocol::Sha1, "auth-pass")
            .unwrap();
        let mut v = vec![UsmUser::new("u").localize(&e), u.localize(&e)];
        for p in PrivProtocol::ALL {
            v.push(u.clone().with_privacy(p, "priv-pass").unwrap().localize(&e));
        }
        v
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = snmpify::peek_version(data);
    if let Ok(msg) = CommunityMessage::decode(data) {
        let again = CommunityMessage::decode(&msg.encode()).expect("re-encoded message decodes");
        assert_eq!(again, msg);
    }
    if let Ok(msg) = Message::decode(data) {
        let again = Message::decode(&msg.encode()).expect("re-encoded message decodes");
        assert_eq!(again, msg);
        if matches!(msg, Message::V3(_)) {
            for u in users() {
                let _ = u.open(data);
            }
        }
    }
});
