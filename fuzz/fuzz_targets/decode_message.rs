//! Any input: decoding never panics, and whatever decodes re-encodes to a
//! message that decodes to the same value.
//!
//!     cargo +nightly fuzz run decode_message
#![no_main]

use libfuzzer_sys::fuzz_target;
use snmpify::CommunityMessage;

fuzz_target!(|data: &[u8]| {
    let _ = snmpify::peek_version(data);
    if let Ok(msg) = CommunityMessage::decode(data) {
        let again = CommunityMessage::decode(&msg.encode()).expect("re-encoded message decodes");
        assert_eq!(again, msg);
    }
});
