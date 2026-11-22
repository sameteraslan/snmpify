//! The User-based Security Model (RFC 3414): keys, authentication and
//! privacy for SNMPv3 messages. Feature `v3`.
//!
//! - Authentication: HMAC-MD5-96 and HMAC-SHA-96 (RFC 3414),
//!   HMAC-SHA-2 with SHA-224/256/384/512 (RFC 7860).
//! - Privacy: DES-CBC (RFC 3414), AES-128-CFB (RFC 3826), and AES-192/256
//!   with the key extension of draft-blumenthal-aes-usm-04 (what net-snmp
//!   calls `AES-192` and `AES-256`).
//!
//! A [`UsmUser`] holds the master keys, made from the passwords once
//! (hashing a megabyte per password, the slow step); [`UsmUser::localize`]
//! derives the keys for one engine cheaply, so a manager polling thousands
//! of agents with the same user hashes each password only once.
//!
//! ```
//! use snmpify::usm::{AuthProtocol, PrivProtocol, UsmUser};
//! use snmpify::v3::{flags, ScopedPdu, ScopedPduData, UsmParams, V3Message};
//! use snmpify::Pdu;
//!
//! let user = UsmUser::new("admin")
//!     .with_auth(AuthProtocol::Sha256, "auth-password")?
//!     .with_privacy(PrivProtocol::Aes128, "priv-password")?;
//! let engine_id = [0x80, 0x00, 0x1f, 0x88, 0x80, 1, 2, 3, 4];
//! let keys = user.localize(&engine_id);
//!
//! let request = V3Message {
//!     msg_id: 7,
//!     max_size: 65507,
//!     flags: flags::REPORTABLE,
//!     usm: UsmParams { engine_boots: 1, engine_time: 100, ..UsmParams::default() },
//!     data: ScopedPduData::Plaintext(ScopedPdu::new(engine_id, Vec::new(), Pdu::get(7, [[1u32, 3, 6, 1, 2, 1, 1, 5, 0]]))),
//! };
//! let bytes = keys.seal(request, 1)?; // authenticated and encrypted
//! let opened = keys.open(&bytes)?;    // verified and decrypted
//! assert!(matches!(opened.data, ScopedPduData::Plaintext(_)));
//! # Ok::<(), snmpify::usm::UsmError>(())
//! ```

use std::fmt;
use std::sync::Arc;

use aes::cipher::{Block, BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hmac::{Hmac, Mac};
use sha2::Digest;

use crate::error::DecodeError;
use crate::v3::{flags, ScopedPdu, ScopedPduData, V3Message};

/// USM errors: bad credentials or a message that fails the checks.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UsmError {
    /// A password shorter than 8 octets (RFC 3414 §11.2; net-snmp
    /// refuses them too).
    PasswordTooShort,
    /// A user name longer than 32 octets.
    UserNameTooLong,
    /// Privacy needs authentication.
    PrivacyWithoutAuth,
    /// The message could not be decoded.
    Decode(DecodeError),
    /// The message needs a security level the user does not have, or is
    /// encrypted without the privacy flag.
    UnsupportedSecurityLevel,
    /// The message is for another user.
    UnknownUserName,
    /// The message is for another engine.
    UnknownEngineId,
    /// The HMAC does not match: wrong key or protocol, or a forged or
    /// altered message.
    WrongDigest,
    /// The encrypted PDU does not decrypt to a scoped PDU.
    DecryptionError,
}

impl fmt::Display for UsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UsmError::PasswordTooShort => f.write_str("password shorter than 8 octets"),
            UsmError::UserNameTooLong => f.write_str("user name longer than 32 octets"),
            UsmError::PrivacyWithoutAuth => f.write_str("privacy needs authentication"),
            UsmError::Decode(e) => write!(f, "invalid message: {e}"),
            UsmError::UnsupportedSecurityLevel => f.write_str("unsupported security level"),
            UsmError::UnknownUserName => f.write_str("unknown user name"),
            UsmError::UnknownEngineId => f.write_str("unknown engine id"),
            UsmError::WrongDigest => f.write_str("wrong digest"),
            UsmError::DecryptionError => f.write_str("decryption error"),
        }
    }
}

impl std::error::Error for UsmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            UsmError::Decode(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DecodeError> for UsmError {
    fn from(e: DecodeError) -> Self {
        UsmError::Decode(e)
    }
}

/// noAuthNoPriv, authNoPriv or authPriv.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    /// Neither authentication nor privacy.
    NoAuthNoPriv,
    /// Authentication only.
    AuthNoPriv,
    /// Authentication and privacy.
    AuthPriv,
}

impl SecurityLevel {
    /// The level that `msgFlags` ask for.
    pub fn from_flags(f: u8) -> SecurityLevel {
        match (f & flags::AUTH != 0, f & flags::PRIV != 0) {
            (true, true) => SecurityLevel::AuthPriv,
            (true, false) => SecurityLevel::AuthNoPriv,
            _ => SecurityLevel::NoAuthNoPriv,
        }
    }

    /// The `msgFlags` bits for this level.
    pub fn flags(self) -> u8 {
        match self {
            SecurityLevel::NoAuthNoPriv => 0,
            SecurityLevel::AuthNoPriv => flags::AUTH,
            SecurityLevel::AuthPriv => flags::AUTH | flags::PRIV,
        }
    }
}

/// Authentication protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AuthProtocol {
    /// HMAC-MD5-96 (RFC 3414).
    Md5,
    /// HMAC-SHA-96 (RFC 3414), net-snmp's `SHA`.
    Sha1,
    /// HMAC-SHA-224 with a 128-bit MAC (RFC 7860).
    Sha224,
    /// HMAC-SHA-256 with a 192-bit MAC (RFC 7860).
    Sha256,
    /// HMAC-SHA-384 with a 256-bit MAC (RFC 7860).
    Sha384,
    /// HMAC-SHA-512 with a 384-bit MAC (RFC 7860).
    Sha512,
}

macro_rules! with_hash {
    ($p:expr, $f:ident($($a:expr),*)) => {
        match $p {
            AuthProtocol::Md5 => $f::<md5::Md5>($($a),*),
            AuthProtocol::Sha1 => $f::<sha1::Sha1>($($a),*),
            AuthProtocol::Sha224 => $f::<sha2::Sha224>($($a),*),
            AuthProtocol::Sha256 => $f::<sha2::Sha256>($($a),*),
            AuthProtocol::Sha384 => $f::<sha2::Sha384>($($a),*),
            AuthProtocol::Sha512 => $f::<sha2::Sha512>($($a),*),
        }
    };
}

fn hash<D: Digest>(parts: &[&[u8]]) -> Vec<u8> {
    let mut d = D::new();
    for p in parts {
        d.update(p);
    }
    d.finalize().to_vec()
}

/// RFC 3414 §A.2: hash the password repeated to one megabyte.
fn password_to_key<D: Digest>(password: &[u8]) -> Vec<u8> {
    let mut d = D::new();
    let mut block = [0u8; 64];
    let mut i = 0;
    for _ in 0..(1_048_576 / 64) {
        for b in block.iter_mut() {
            *b = password[i];
            i += 1;
            if i == password.len() {
                i = 0;
            }
        }
        d.update(block);
    }
    d.finalize().to_vec()
}

fn hmac<D>(key: &[u8], data: &[u8]) -> Vec<u8>
where
    D: hmac::EagerHash,
    Hmac<D>: Mac + KeyInit,
{
    let mut m = <Hmac<D> as KeyInit>::new_from_slice(key).expect("HMAC takes keys of any length");
    m.update(data);
    m.finalize().into_bytes().to_vec()
}

impl AuthProtocol {
    /// Every protocol, weakest first.
    pub const ALL: [AuthProtocol; 6] = [
        AuthProtocol::Md5,
        AuthProtocol::Sha1,
        AuthProtocol::Sha224,
        AuthProtocol::Sha256,
        AuthProtocol::Sha384,
        AuthProtocol::Sha512,
    ];

    /// Length of `msgAuthenticationParameters` (the truncated HMAC).
    pub fn mac_len(self) -> usize {
        match self {
            AuthProtocol::Md5 | AuthProtocol::Sha1 => 12,
            AuthProtocol::Sha224 => 16,
            AuthProtocol::Sha256 => 24,
            AuthProtocol::Sha384 => 32,
            AuthProtocol::Sha512 => 48,
        }
    }

    /// Length of the keys (the hash output).
    pub fn key_len(self) -> usize {
        match self {
            AuthProtocol::Md5 => 16,
            AuthProtocol::Sha1 => 20,
            AuthProtocol::Sha224 => 28,
            AuthProtocol::Sha256 => 32,
            AuthProtocol::Sha384 => 48,
            AuthProtocol::Sha512 => 64,
        }
    }

    /// The master key Ku for a password (RFC 3414 §A.2).
    pub fn password_to_key(self, password: &[u8]) -> Result<Vec<u8>, UsmError> {
        if password.len() < 8 {
            return Err(UsmError::PasswordTooShort);
        }
        Ok(with_hash!(self, password_to_key(password)))
    }

    /// The localized key Kul = H(Ku ‖ engineID ‖ Ku) (RFC 3414 §2.6).
    pub fn localize(self, master_key: &[u8], engine_id: &[u8]) -> Vec<u8> {
        with_hash!(self, hash(&[master_key, engine_id, master_key]))
    }

    /// The truncated HMAC of `data`.
    fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut m = with_hash!(self, hmac(key, data));
        m.truncate(self.mac_len());
        m
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        with_hash!(self, hash(&[data]))
    }
}

impl fmt::Display for AuthProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            AuthProtocol::Md5 => "MD5",
            AuthProtocol::Sha1 => "SHA",
            AuthProtocol::Sha224 => "SHA-224",
            AuthProtocol::Sha256 => "SHA-256",
            AuthProtocol::Sha384 => "SHA-384",
            AuthProtocol::Sha512 => "SHA-512",
        })
    }
}

/// Privacy (encryption) protocols.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrivProtocol {
    /// CBC-DES (RFC 3414). Weak; for old agents only.
    Des,
    /// CFB128-AES-128 (RFC 3826).
    Aes128,
    /// CFB128-AES-192, key extension of draft-blumenthal-aes-usm-04
    /// (net-snmp's `AES-192`).
    Aes192,
    /// CFB128-AES-256, key extension of draft-blumenthal-aes-usm-04
    /// (net-snmp's `AES-256`).
    Aes256,
}

impl PrivProtocol {
    /// Every protocol.
    pub const ALL: [PrivProtocol; 4] = [
        PrivProtocol::Des,
        PrivProtocol::Aes128,
        PrivProtocol::Aes192,
        PrivProtocol::Aes256,
    ];

    /// Length of the localized privacy key the cipher uses (for DES: the
    /// key and the pre-IV).
    pub fn key_len(self) -> usize {
        match self {
            PrivProtocol::Des | PrivProtocol::Aes128 => 16,
            PrivProtocol::Aes192 => 24,
            PrivProtocol::Aes256 => 32,
        }
    }

    /// The localized privacy key: the localized key of the privacy
    /// password, extended when the hash is shorter than the cipher key
    /// (Kul ‖ H(Kul) ‖ H(Kul ‖ H(Kul)) …), then truncated.
    pub fn localize(self, auth: AuthProtocol, master_key: &[u8], engine_id: &[u8]) -> Vec<u8> {
        let mut k = auth.localize(master_key, engine_id);
        while k.len() < self.key_len() {
            let more = auth.digest(&k);
            k.extend_from_slice(&more);
        }
        k.truncate(self.key_len());
        k
    }

    /// Encrypts `plain` for a message with these engine boots and time;
    /// returns the ciphertext and `msgPrivacyParameters`.
    fn encrypt(
        self,
        key: &[u8],
        boots: u32,
        time: u32,
        salt: u64,
        plain: &[u8],
    ) -> (Vec<u8>, Vec<u8>) {
        match self {
            PrivProtocol::Des => {
                // RFC 3414 §8.1.1.1: salt = boots ‖ counter, IV = pre-IV ⊕ salt.
                let mut s = [0u8; 8];
                s[..4].copy_from_slice(&boots.to_be_bytes());
                s[4..].copy_from_slice(&(salt as u32).to_be_bytes());
                let mut data = plain.to_vec();
                data.resize(plain.len().div_ceil(8) * 8, 0);
                des_cbc(key, &s, &mut data, false);
                (data, s.to_vec())
            }
            _ => {
                let s = salt.to_be_bytes();
                let mut data = plain.to_vec();
                aes_cfb(self, key, &aes_iv(boots, time, &s), &mut data, false);
                (data, s.to_vec())
            }
        }
    }

    fn decrypt(
        self,
        key: &[u8],
        boots: u32,
        time: u32,
        params: &[u8],
        cipher: &[u8],
    ) -> Result<Vec<u8>, UsmError> {
        let salt: [u8; 8] = params.try_into().map_err(|_| UsmError::DecryptionError)?;
        let mut data = cipher.to_vec();
        match self {
            PrivProtocol::Des => {
                if data.len() % 8 != 0 {
                    return Err(UsmError::DecryptionError);
                }
                des_cbc(key, &salt, &mut data, true);
            }
            _ => aes_cfb(self, key, &aes_iv(boots, time, &salt), &mut data, true),
        }
        Ok(data)
    }
}

impl fmt::Display for PrivProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PrivProtocol::Des => "DES",
            PrivProtocol::Aes128 => "AES",
            PrivProtocol::Aes192 => "AES-192",
            PrivProtocol::Aes256 => "AES-256",
        })
    }
}

fn des_cbc(key: &[u8], salt: &[u8; 8], data: &mut [u8], decrypt: bool) {
    let cipher = des::Des::new_from_slice(&key[..8]).expect("DES key is 8 bytes");
    let mut prev = [0u8; 8];
    for (p, (k, s)) in prev.iter_mut().zip(key[8..16].iter().zip(salt)) {
        *p = k ^ s;
    }
    for chunk in data.chunks_exact_mut(8) {
        let mut b = Block::<des::Des>::default();
        if decrypt {
            b.copy_from_slice(chunk);
            let c: [u8; 8] = b.into();
            cipher.decrypt_block(&mut b);
            for (o, (x, p)) in chunk.iter_mut().zip(b.iter().zip(&prev)) {
                *o = x ^ p;
            }
            prev = c;
        } else {
            for (o, (x, p)) in b.iter_mut().zip(chunk.iter().zip(&prev)) {
                *o = x ^ p;
            }
            cipher.encrypt_block(&mut b);
            chunk.copy_from_slice(&b);
            prev.copy_from_slice(&b);
        }
    }
}

fn aes_iv(boots: u32, time: u32, salt: &[u8; 8]) -> [u8; 16] {
    // RFC 3826 §3.1.2.1: IV = boots ‖ time ‖ salt.
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&boots.to_be_bytes());
    iv[4..8].copy_from_slice(&time.to_be_bytes());
    iv[8..].copy_from_slice(salt);
    iv
}

fn aes_cfb(p: PrivProtocol, key: &[u8], iv: &[u8; 16], data: &mut [u8], decrypt: bool) {
    fn run<C: BlockCipherEncrypt + KeyInit>(
        key: &[u8],
        iv: &[u8; 16],
        data: &mut [u8],
        decrypt: bool,
    ) {
        let cipher = C::new_from_slice(key).expect("AES key length matches the protocol");
        let mut feedback = Block::<C>::default();
        feedback.copy_from_slice(iv);
        for chunk in data.chunks_mut(16) {
            let mut ks = feedback.clone();
            cipher.encrypt_block(&mut ks);
            if decrypt {
                feedback[..chunk.len()].copy_from_slice(chunk);
                for (c, k) in chunk.iter_mut().zip(ks.iter()) {
                    *c ^= k;
                }
            } else {
                for (c, k) in chunk.iter_mut().zip(ks.iter()) {
                    *c ^= k;
                }
                feedback[..chunk.len()].copy_from_slice(chunk);
            }
        }
    }
    match p {
        PrivProtocol::Aes128 => run::<aes::Aes128>(key, iv, data, decrypt),
        PrivProtocol::Aes192 => run::<aes::Aes192>(key, iv, data, decrypt),
        PrivProtocol::Aes256 => run::<aes::Aes256>(key, iv, data, decrypt),
        PrivProtocol::Des => unreachable!("DES is CBC"),
    }
}

/// Compares in constant time (the HMAC must not leak through timing).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[derive(Clone)]
struct MasterKeys {
    auth: Option<(AuthProtocol, Arc<[u8]>)>,
    privacy: Option<(PrivProtocol, Arc<[u8]>)>,
}

/// An SNMPv3 user: name, protocols and master keys (from passwords).
///
/// Cloning is cheap. The keys are never printed by `Debug`.
#[derive(Clone)]
pub struct UsmUser {
    name: Arc<[u8]>,
    keys: MasterKeys,
}

impl fmt::Debug for UsmUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UsmUser")
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("auth", &self.keys.auth.as_ref().map(|a| a.0))
            .field("privacy", &self.keys.privacy.as_ref().map(|p| p.0))
            .finish()
    }
}

impl UsmUser {
    /// A user without authentication or privacy (noAuthNoPriv). Names
    /// longer than 32 octets are rejected when used.
    pub fn new(name: impl AsRef<[u8]>) -> Self {
        Self {
            name: name.as_ref().into(),
            keys: MasterKeys {
                auth: None,
                privacy: None,
            },
        }
    }

    /// Adds authentication with a password (at least 8 octets).
    pub fn with_auth(
        mut self,
        protocol: AuthProtocol,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, UsmError> {
        let key = protocol.password_to_key(password.as_ref())?;
        self.keys.auth = Some((protocol, key.into()));
        // A privacy key made with another hash would no longer match.
        self.keys.privacy = None;
        Ok(self)
    }

    /// Adds privacy with a password (at least 8 octets); call
    /// [`with_auth`](Self::with_auth) first.
    pub fn with_privacy(
        mut self,
        protocol: PrivProtocol,
        password: impl AsRef<[u8]>,
    ) -> Result<Self, UsmError> {
        let Some((auth, _)) = self.keys.auth else {
            return Err(UsmError::PrivacyWithoutAuth);
        };
        let key = auth.password_to_key(password.as_ref())?;
        self.keys.privacy = Some((protocol, key.into()));
        Ok(self)
    }

    /// The user name.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// The authentication protocol.
    pub fn auth_protocol(&self) -> Option<AuthProtocol> {
        self.keys.auth.as_ref().map(|a| a.0)
    }

    /// The privacy protocol.
    pub fn priv_protocol(&self) -> Option<PrivProtocol> {
        self.keys.privacy.as_ref().map(|p| p.0)
    }

    /// The user's security level.
    pub fn level(&self) -> SecurityLevel {
        match (&self.keys.auth, &self.keys.privacy) {
            (Some(_), Some(_)) => SecurityLevel::AuthPriv,
            (Some(_), None) => SecurityLevel::AuthNoPriv,
            _ => SecurityLevel::NoAuthNoPriv,
        }
    }

    /// The keys for one engine (cheap: two hashes per key).
    pub fn localize(&self, engine_id: &[u8]) -> LocalizedUser {
        let auth = self
            .keys
            .auth
            .as_ref()
            .map(|(p, k)| (*p, p.localize(k, engine_id)));
        let privacy = match (&self.keys.auth, &self.keys.privacy) {
            (Some((a, _)), Some((p, k))) => Some((*p, p.localize(*a, k, engine_id))),
            _ => None,
        };
        LocalizedUser {
            name: self.name.clone(),
            engine_id: engine_id.to_vec(),
            auth,
            privacy,
        }
    }
}

/// A user's keys localized to one engine: seals outgoing and opens
/// incoming messages.
#[derive(Clone)]
pub struct LocalizedUser {
    name: Arc<[u8]>,
    engine_id: Vec<u8>,
    auth: Option<(AuthProtocol, Vec<u8>)>,
    privacy: Option<(PrivProtocol, Vec<u8>)>,
}

impl fmt::Debug for LocalizedUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalizedUser")
            .field("name", &String::from_utf8_lossy(&self.name))
            .field("engine_id", &self.engine_id)
            .field("auth", &self.auth.as_ref().map(|a| a.0))
            .field("privacy", &self.privacy.as_ref().map(|p| p.0))
            .finish()
    }
}

impl LocalizedUser {
    /// The user name.
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    /// The engine the keys belong to.
    pub fn engine_id(&self) -> &[u8] {
        &self.engine_id
    }

    /// The user's security level.
    pub fn level(&self) -> SecurityLevel {
        match (&self.auth, &self.privacy) {
            (Some(_), Some(_)) => SecurityLevel::AuthPriv,
            (Some(_), None) => SecurityLevel::AuthNoPriv,
            _ => SecurityLevel::NoAuthNoPriv,
        }
    }

    /// Secures a message at the user's level: sets the user name, engine
    /// id and flags (keeping `reportable`), encrypts the scoped PDU and
    /// authenticates the whole message. The message's engine boots and
    /// time must already be set. `salt` must not repeat for the same key;
    /// a counter does.
    pub fn seal(&self, mut msg: V3Message, salt: u64) -> Result<Vec<u8>, UsmError> {
        if self.name.len() > 32 {
            return Err(UsmError::UserNameTooLong);
        }
        msg.usm.user_name = self.name.to_vec();
        msg.usm.engine_id.clone_from(&self.engine_id);
        msg.flags = (msg.flags & flags::REPORTABLE) | self.level().flags();
        msg.usm.priv_params.clear();
        msg.usm.auth_params.clear();
        let ScopedPduData::Plaintext(scoped) = &msg.data else {
            return Err(UsmError::UnsupportedSecurityLevel);
        };
        if let Some((p, key)) = &self.privacy {
            let (cipher, params) = p.encrypt(
                key,
                msg.usm.engine_boots,
                msg.usm.engine_time,
                salt,
                &scoped.encode(),
            );
            msg.usm.priv_params = params;
            msg.data = ScopedPduData::Encrypted(cipher);
        }
        let Some((a, key)) = &self.auth else {
            return Ok(msg.encode());
        };
        msg.usm.auth_params = vec![0; a.mac_len()];
        let (mut bytes, range) = msg.encode_with_auth_range();
        let mac = a.mac(key, &bytes);
        bytes[range].copy_from_slice(&mac);
        Ok(bytes)
    }

    /// Verifies and decrypts a message at the level its flags give;
    /// returns it with a plaintext scoped PDU. The caller checks that the
    /// level is the one it expects ([`SecurityLevel::from_flags`]):
    /// reports, for one, may come unauthenticated.
    ///
    /// Authenticated messages must name this user and engine. Timeliness
    /// (engine boots and time) is the caller's to check.
    pub fn open(&self, bytes: &[u8]) -> Result<V3Message, UsmError> {
        let (mut msg, range) = V3Message::decode_with_auth_range(bytes)?;
        if msg.flags & flags::AUTH != 0 {
            let Some((a, key)) = &self.auth else {
                return Err(UsmError::UnsupportedSecurityLevel);
            };
            if msg.usm.user_name != *self.name {
                return Err(UsmError::UnknownUserName);
            }
            if msg.usm.engine_id != self.engine_id {
                return Err(UsmError::UnknownEngineId);
            }
            if msg.usm.auth_params.len() != a.mac_len() {
                return Err(UsmError::WrongDigest);
            }
            let mut copy = bytes.to_vec();
            copy[range].fill(0);
            if !ct_eq(&a.mac(key, &copy), &msg.usm.auth_params) {
                return Err(UsmError::WrongDigest);
            }
        }
        match (&msg.data, msg.flags & flags::PRIV != 0) {
            (ScopedPduData::Encrypted(c), true) => {
                let Some((p, key)) = &self.privacy else {
                    return Err(UsmError::UnsupportedSecurityLevel);
                };
                let plain = p.decrypt(
                    key,
                    msg.usm.engine_boots,
                    msg.usm.engine_time,
                    &msg.usm.priv_params,
                    c,
                )?;
                let scoped =
                    ScopedPdu::decode_padded(&plain).map_err(|_| UsmError::DecryptionError)?;
                msg.data = ScopedPduData::Plaintext(scoped);
            }
            (ScopedPduData::Plaintext(_), false) => {}
            // Encrypted without the flag, or the flag without encryption.
            _ => return Err(UsmError::UnsupportedSecurityLevel),
        }
        Ok(msg)
    }
}

#[cfg(test)]
mod tests {
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
        des_cbc(&key, &[0; 8], &mut data, false);
        assert_eq!(
            data,
            hex("e5c7cdde872bf27c43e934008c389c0f683788499a7c05f6")
        );
        des_cbc(&key, &[0; 8], &mut data, true);
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
}
