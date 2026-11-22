//! MIBs: names for OIDs and readable values.
//!
//! [`Mib::standard`] knows the standard MIBs (SNMPv2-SMI, SNMPv2-MIB,
//! IF-MIB, IP-MIB, HOST-RESOURCES-MIB, … see [`STANDARD_MODULES`])
//! without reading any file. [`Mib::load_file`] / [`Mib::load_dir`] add
//! vendor MIBs (SMIv1 or SMIv2); modules may come in any order, imports
//! are resolved across everything loaded.
//!
//! ```
//! use snmpify::mib::Mib;
//! use snmpify::{Value, VarBind};
//!
//! let mib = Mib::standard();
//! let oid = mib.resolve("IF-MIB::ifOperStatus.3").unwrap();
//! assert_eq!(oid.to_string(), "1.3.6.1.2.1.2.2.1.8.3");
//! assert_eq!(mib.name(&oid), "IF-MIB::ifOperStatus.3");
//! let vb = VarBind::new(oid, Value::Integer(1));
//! assert_eq!(mib.format(&vb), "IF-MIB::ifOperStatus.3 = up(1)");
//! ```

mod builtin;
mod hint;
mod parse;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::path::Path;

use crate::{Oid, Value, VarBind};

pub use builtin::STANDARD_MODULES;
pub use hint::{format_integer, format_octets};

/// Errors loading MIBs or resolving names.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MibError {
    /// A MIB file that does not parse.
    Syntax {
        /// Line of the error.
        line: usize,
        /// What was wrong.
        message: String,
    },
    /// A file could not be read.
    Io(String),
    /// A name no loaded module defines.
    UnknownName(String),
}

impl fmt::Display for MibError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MibError::Syntax { line, message } => {
                write!(f, "MIB syntax error at line {line}: {message}")
            }
            MibError::Io(e) => write!(f, "{e}"),
            MibError::UnknownName(n) => write!(f, "unknown MIB name {n:?}"),
        }
    }
}

impl std::error::Error for MibError {}

/// What a MIB node is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// `OBJECT IDENTIFIER` or OBJECT-IDENTITY: a branch.
    Node,
    /// MODULE-IDENTITY.
    ModuleIdentity,
    /// A scalar object (one instance, `.0`).
    Scalar,
    /// A table (`SEQUENCE OF`).
    Table,
    /// A table row (`INDEX` / `AUGMENTS`).
    Row,
    /// A column of a table.
    Column,
    /// NOTIFICATION-TYPE or TRAP-TYPE.
    Notification,
    /// OBJECT-GROUP or NOTIFICATION-GROUP.
    Group,
    /// MODULE-COMPLIANCE.
    Compliance,
    /// AGENT-CAPABILITIES.
    Capabilities,
}

/// MAX-ACCESS (SMIv2) or ACCESS (SMIv1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Access {
    NotAccessible,
    AccessibleForNotify,
    ReadOnly,
    ReadWrite,
    ReadCreate,
    WriteOnly,
}

impl Access {
    pub(crate) fn parse(s: &str) -> Option<Access> {
        Some(match s {
            "not-accessible" => Access::NotAccessible,
            "accessible-for-notify" => Access::AccessibleForNotify,
            "read-only" => Access::ReadOnly,
            "read-write" => Access::ReadWrite,
            "read-create" => Access::ReadCreate,
            "write-only" => Access::WriteOnly,
            _ => return None,
        })
    }
}

/// STATUS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Status {
    Current,
    Deprecated,
    Obsolete,
    Mandatory,
    Optional,
}

impl Status {
    pub(crate) fn parse(s: &str) -> Option<Status> {
        Some(match s {
            "current" => Status::Current,
            "deprecated" => Status::Deprecated,
            "obsolete" => Status::Obsolete,
            "mandatory" => Status::Mandatory,
            "optional" => Status::Optional,
            _ => return None,
        })
    }
}

/// The SMI base type of an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum BaseType {
    Integer,
    OctetString,
    ObjectId,
    Bits,
    IpAddress,
    Counter32,
    Gauge32,
    Unsigned32,
    TimeTicks,
    Opaque,
    Counter64,
}

/// A MIB node: an object, notification, branch …
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MibObject {
    /// The module that defines it.
    pub module: String,
    /// Its descriptor (`ifDescr`).
    pub name: String,
    /// Its OID.
    pub oid: Oid,
    /// What it is.
    pub kind: Kind,
    /// The syntax as written (`DisplayString`, `INTEGER`).
    pub type_name: Option<String>,
    /// The base type, following textual conventions.
    pub base: Option<BaseType>,
    /// Enumerated values or named bits.
    pub enums: Vec<(i64, String)>,
    /// The DISPLAY-HINT of its textual convention.
    pub display_hint: Option<String>,
    /// MAX-ACCESS.
    pub access: Option<Access>,
    /// STATUS.
    pub status: Option<Status>,
    /// INDEX objects of a row (of the row's AUGMENTS target for
    /// augmenting rows).
    pub index: Vec<String>,
    /// UNITS.
    pub units: Option<String>,
}

impl MibObject {
    /// `MODULE::name`.
    pub fn qualified_name(&self) -> String {
        format!("{}::{}", self.module, self.name)
    }

    /// The label of an enumerated value.
    pub fn enum_label(&self, v: i64) -> Option<&str> {
        self.enums
            .iter()
            .find(|(n, _)| *n == v)
            .map(|(_, l)| l.as_str())
    }
}

/// A textual convention or type assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TextualConvention {
    /// The module.
    pub module: String,
    /// Its name (`DisplayString`).
    pub name: String,
    /// The type it refines.
    pub type_name: String,
    /// Enumerations.
    pub enums: Vec<(i64, String)>,
    /// DISPLAY-HINT.
    pub display_hint: Option<String>,
}

/// What [`Mib::load_dir`] loaded.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LoadReport {
    /// Modules loaded.
    pub loaded: Vec<String>,
    /// Files that did not parse, and why.
    pub failed: Vec<(String, MibError)>,
}

struct Pending {
    module: String,
    node: parse::RawNode,
}

/// A set of MIB modules.
#[derive(Default)]
pub struct Mib {
    objects: Vec<MibObject>,
    by_oid: BTreeMap<Oid, usize>,
    by_name: HashMap<String, Vec<usize>>,
    by_qualified: HashMap<(String, String), usize>,
    types: HashMap<(String, String), TextualConvention>,
    types_by_name: HashMap<String, Vec<(String, String)>>,
    imports: HashMap<String, HashMap<String, String>>,
    modules: Vec<String>,
    pending: Vec<Pending>,
    /// OBJECT-TYPE nodes whose kind and syntax are worked out after loads.
    raw: HashMap<usize, parse::RawNode>,
}

impl fmt::Debug for Mib {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mib")
            .field("modules", &self.modules.len())
            .field("objects", &self.objects.len())
            .field("unresolved", &self.pending.len())
            .finish()
    }
}

impl Mib {
    /// Only the ASN.1 roots (iso, ccitt, joint-iso-ccitt).
    pub fn new() -> Mib {
        let mut m = Mib::default();
        for (name, n) in [("ccitt", 0), ("iso", 1), ("joint-iso-ccitt", 2)] {
            m.add(MibObject {
                module: String::new(),
                name: name.into(),
                oid: Oid::from([n]),
                kind: Kind::Node,
                type_name: None,
                base: None,
                enums: Vec::new(),
                display_hint: None,
                access: None,
                status: None,
                index: Vec::new(),
                units: None,
            });
        }
        m
    }

    /// The standard MIBs, built in ([`STANDARD_MODULES`]).
    pub fn standard() -> Mib {
        let mut m = Mib::new();
        builtin::install(&mut m);
        m
    }

    fn add(&mut self, o: MibObject) -> usize {
        if let Some(&i) = self.by_qualified.get(&(o.module.clone(), o.name.clone())) {
            return i;
        }
        let i = self.objects.len();
        self.by_oid.entry(o.oid.clone()).or_insert(i);
        self.by_name.entry(o.name.clone()).or_default().push(i);
        self.by_qualified
            .insert((o.module.clone(), o.name.clone()), i);
        self.objects.push(o);
        i
    }

    pub(crate) fn add_type(&mut self, t: TextualConvention) {
        let key = (t.module.clone(), t.name.clone());
        self.types_by_name
            .entry(t.name.clone())
            .or_default()
            .push(key.clone());
        self.types.insert(key, t);
    }

    pub(crate) fn add_builtin(&mut self, o: MibObject) {
        if !self.modules.contains(&o.module) {
            self.modules.push(o.module.clone());
        }
        self.add(o);
    }

    /// Loads the modules in a MIB text. Objects whose parents are not
    /// loaded yet stay pending until they are ([`unresolved`](Self::unresolved)).
    pub fn load_str(&mut self, text: &str) -> Result<Vec<String>, MibError> {
        let mods = parse::parse(text)?;
        let names = mods.iter().map(|m| m.name.clone()).collect();
        for m in mods {
            let imports: HashMap<String, String> = m.imports.into_iter().collect();
            self.imports.insert(m.name.clone(), imports);
            if !self.modules.contains(&m.name) {
                self.modules.push(m.name.clone());
            }
            for t in m.types {
                self.add_type(TextualConvention {
                    module: m.name.clone(),
                    name: t.name,
                    type_name: t.syntax.type_name,
                    enums: t.syntax.enums,
                    display_hint: t.hint,
                });
            }
            for n in m.nodes {
                self.pending.push(Pending {
                    module: m.name.clone(),
                    node: n,
                });
            }
        }
        self.resolve_pending();
        Ok(names)
    }

    /// Loads a MIB file.
    pub fn load_file(&mut self, path: impl AsRef<Path>) -> Result<Vec<String>, MibError> {
        let p = path.as_ref();
        let bytes = std::fs::read(p).map_err(|e| MibError::Io(format!("{}: {e}", p.display())))?;
        self.load_str(&String::from_utf8_lossy(&bytes))
    }

    /// Loads every file in a directory that parses as MIB modules; reports
    /// the modules loaded and the files that failed.
    pub fn load_dir(&mut self, dir: impl AsRef<Path>) -> Result<LoadReport, MibError> {
        let d = dir.as_ref();
        let mut entries: Vec<_> = std::fs::read_dir(d)
            .map_err(|e| MibError::Io(format!("{}: {e}", d.display())))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_file())
            .collect();
        entries.sort();
        let (mut ok, mut failed) = (Vec::new(), Vec::new());
        for p in entries {
            match self.load_file(&p) {
                Ok(m) => ok.extend(m),
                Err(e) => failed.push((p.display().to_string(), e)),
            }
        }
        Ok(LoadReport { loaded: ok, failed })
    }

    /// The loaded module names.
    pub fn modules(&self) -> &[String] {
        &self.modules
    }

    /// Names that could not be placed (their parents are unknown).
    pub fn unresolved(&self) -> Vec<String> {
        self.pending
            .iter()
            .map(|p| format!("{}::{}", p.module, p.node.name))
            .collect()
    }

    /// Every known node, in no particular order.
    pub fn objects(&self) -> impl Iterator<Item = &MibObject> {
        self.objects.iter()
    }

    /// Every textual convention.
    pub fn textual_conventions(&self) -> impl Iterator<Item = &TextualConvention> {
        self.types.values()
    }

    /// Finds a name as seen from `module`: its own, its imports, then any.
    fn find(&self, module: &str, name: &str) -> Option<usize> {
        if let Some(&i) = self
            .by_qualified
            .get(&(module.to_string(), name.to_string()))
        {
            return Some(i);
        }
        if let Some(from) = self.imports.get(module).and_then(|im| im.get(name)) {
            if let Some(&i) = self.by_qualified.get(&(from.clone(), name.to_string())) {
                return Some(i);
            }
        }
        self.by_name.get(name).and_then(|v| v.first().copied())
    }

    fn resolve_pending(&mut self) {
        loop {
            let before = self.pending.len();
            let pending = std::mem::take(&mut self.pending);
            for p in pending {
                match self.place(&p.module, &p.node) {
                    Some(i) => {
                        if p.node.kind == Kind::Scalar {
                            self.raw.insert(i, p.node);
                        }
                    }
                    None => self.pending.push(p),
                }
            }
            if self.pending.len() == before || self.pending.is_empty() {
                break;
            }
        }
        self.refine();
    }

    /// Resolves a node's OID value and adds it; None if a parent is missing.
    fn place(&mut self, module: &str, n: &parse::RawNode) -> Option<usize> {
        use parse::Component;
        let mut arcs: Vec<u32> = Vec::new();
        let mut defined = Vec::new();
        for (k, c) in n.value.iter().enumerate() {
            match c {
                Component::Num(x) => arcs.push(*x),
                Component::Named(name, x) => {
                    arcs.push(*x);
                    defined.push((name.clone(), arcs.clone()));
                }
                Component::Name(name) if k == 0 => {
                    let i = self.find(module, name)?;
                    arcs.extend_from_slice(self.objects[i].oid.as_slice());
                }
                Component::Name(_) => return None,
            }
        }
        // `{ iso org(3) dod(6) }` also names org and dod.
        for (name, a) in defined {
            if self.find(module, &name).is_none() {
                self.add(node(module, &name, Oid::from(a), Kind::Node));
            }
        }
        let mut o = node(module, &n.name, Oid::from(arcs), n.kind);
        o.access = n.access;
        o.status = n.status;
        o.index = n.index.clone();
        o.units = n.units.clone();
        if let Some(s) = &n.syntax {
            o.type_name = Some(s.type_name.clone());
            o.enums = s.enums.clone();
        }
        Some(self.add(o))
    }

    /// Kinds of OBJECT-TYPEs and syntax details, now that everything
    /// loaded so far is placed.
    fn refine(&mut self) {
        let raw: Vec<(usize, parse::RawNode)> =
            self.raw.iter().map(|(i, n)| (*i, n.clone())).collect();
        for (i, n) in &raw {
            let kind = if n.syntax.as_ref().is_some_and(|s| s.sequence_of) {
                Kind::Table
            } else if !n.index.is_empty() || n.augments.is_some() {
                Kind::Row
            } else {
                Kind::Scalar
            };
            self.objects[*i].kind = kind;
            if let Some(a) = &n.augments {
                if let Some(j) = self.find(&self.objects[*i].module.clone(), a) {
                    self.objects[*i].index = self.objects[j].index.clone();
                }
            }
        }
        for (i, _) in &raw {
            if self.objects[*i].kind != Kind::Scalar {
                continue;
            }
            let oid = self.objects[*i].oid.clone();
            let parent = &oid[..oid.len().saturating_sub(1)];
            if let Some(&p) = self.by_oid.get(&Oid::from_slice(parent)) {
                if self.objects[p].kind == Kind::Row {
                    self.objects[*i].kind = Kind::Column;
                }
            }
        }
        for (i, _) in &raw {
            let (module, type_name) = {
                let o = &self.objects[*i];
                (o.module.clone(), o.type_name.clone())
            };
            let Some(t) = type_name else { continue };
            let (base, enums, hint) = self.follow_type(&module, &t);
            let o = &mut self.objects[*i];
            o.base = base;
            if o.enums.is_empty() {
                o.enums = enums;
            }
            o.display_hint = hint;
        }
    }

    /// Follows textual conventions to the base type; collects enums and
    /// the first display hint on the way.
    fn follow_type(
        &self,
        module: &str,
        type_name: &str,
    ) -> (Option<BaseType>, Vec<(i64, String)>, Option<String>) {
        let mut name = type_name.to_string();
        let mut module = module.to_string();
        let mut enums = Vec::new();
        let mut hint = None;
        for _ in 0..16 {
            if let Some(b) = parse::base_of(&name) {
                return (Some(b), enums, hint);
            }
            let key = self
                .imports
                .get(&module)
                .and_then(|im| im.get(&name))
                .map(|m| (m.clone(), name.clone()))
                .filter(|k| self.types.contains_key(k))
                .or_else(|| {
                    Some((module.clone(), name.clone())).filter(|k| self.types.contains_key(k))
                })
                .or_else(|| {
                    self.types_by_name
                        .get(&name)
                        .and_then(|v| v.first().cloned())
                });
            let Some(key) = key else { break };
            let t = &self.types[&key];
            if enums.is_empty() {
                enums = t.enums.clone();
            }
            if hint.is_none() {
                hint = t.display_hint.clone();
            }
            module = t.module.clone();
            name = t.type_name.clone();
        }
        (None, enums, hint)
    }

    /// An object by name: `ifDescr` or `IF-MIB::ifDescr`.
    pub fn object(&self, name: &str) -> Option<&MibObject> {
        let i = match name.split_once("::") {
            Some((m, n)) => *self.by_qualified.get(&(m.to_string(), n.to_string()))?,
            None => *self.by_name.get(name)?.first()?,
        };
        Some(&self.objects[i])
    }

    /// The deepest node at or above `oid`, and the rest of the OID (the
    /// instance index).
    pub fn lookup<'a>(&self, oid: &'a Oid) -> Option<(&MibObject, &'a [u32])> {
        let a = oid.as_slice();
        let at = |n: usize| {
            self.by_oid
                .get(&Oid::from_slice(&a[..n]))
                .map(|&i| (&self.objects[i], &a[n..]))
        };
        let first = (1..=a.len()).rev().find_map(at)?;
        // A plain node under an object is an alias for an instance (such
        // as DISMAN-EVENT-MIB::sysUpTimeInstance, sysUpTime.0): name the
        // object and its index instead.
        if first.0.kind == Kind::Node {
            let objectish = |k: Kind| matches!(k, Kind::Scalar | Kind::Column);
            let depth = a.len() - first.1.len();
            if let Some(obj) = (1..depth)
                .rev()
                .filter_map(at)
                .find(|(o, _)| objectish(o.kind))
            {
                return Some(obj);
            }
        }
        Some(first)
    }

    /// An OID from a name: `IF-MIB::ifDescr.3`, `ifDescr.3`, `sysName.0`,
    /// or numeric (`1.3.6.1.2.1.1.5.0`, `.1.3.6…`).
    pub fn resolve(&self, name: &str) -> Result<Oid, MibError> {
        let s = name.trim().trim_start_matches('.');
        if s.starts_with(|c: char| c.is_ascii_digit()) {
            return s.parse().map_err(|_| MibError::UnknownName(name.into()));
        }
        let (head, suffix) = match s.find('.') {
            Some(i) => (&s[..i], &s[i + 1..]),
            None => (s, ""),
        };
        let o = self
            .object(head)
            .ok_or_else(|| MibError::UnknownName(name.into()))?;
        let mut arcs = o.oid.as_slice().to_vec();
        if !suffix.is_empty() {
            for part in suffix.split('.') {
                arcs.push(
                    part.parse()
                        .map_err(|_| MibError::UnknownName(name.into()))?,
                );
            }
        }
        Ok(Oid::from(arcs))
    }

    /// `MODULE::name.index` for an OID, or the numeric form if no module
    /// knows it.
    pub fn name(&self, oid: &Oid) -> String {
        match self.lookup(oid) {
            Some((o, rest)) if !o.module.is_empty() => {
                let mut s = o.qualified_name();
                for a in rest {
                    s.push('.');
                    s.push_str(&a.to_string());
                }
                s
            }
            _ => oid.to_string(),
        }
    }

    /// A value as text, using what the MIB says about `oid`: enum labels,
    /// named bits, display hints, OID names.
    pub fn format_value(&self, oid: &Oid, v: &Value) -> String {
        let obj = self.lookup(oid).map(|(o, _)| o);
        match (v, obj) {
            (Value::Integer(n), Some(o)) => {
                if let Some(l) = o.enum_label(*n as i64) {
                    return format!("{l}({n})");
                }
                if let Some(h) = &o.display_hint {
                    return format_integer(h, *n as i64);
                }
                v.to_string()
            }
            (Value::OctetString(b), Some(o)) if o.base == Some(BaseType::Bits) => {
                let set: Vec<String> = (0..b.len() * 8)
                    .filter(|bit| b[bit / 8] & (0x80 >> (bit % 8)) != 0)
                    .map(|bit| match o.enum_label(bit as i64) {
                        Some(l) => format!("{l}({bit})"),
                        None => bit.to_string(),
                    })
                    .collect();
                set.join(" ")
            }
            (Value::OctetString(b), Some(o)) if o.display_hint.is_some() => {
                format_octets(o.display_hint.as_deref().unwrap_or(""), b)
            }
            (Value::ObjectId(x), _) => self.name(x),
            _ => v.to_string(),
        }
    }

    /// `name = value`, both through the MIB.
    pub fn format(&self, vb: &VarBind) -> String {
        format!(
            "{} = {}",
            self.name(&vb.oid),
            self.format_value(&vb.oid, &vb.value)
        )
    }
}

fn node(module: &str, name: &str, oid: Oid, kind: Kind) -> MibObject {
    MibObject {
        module: module.into(),
        name: name.into(),
        oid,
        kind,
        type_name: None,
        base: None,
        enums: Vec::new(),
        display_hint: None,
        access: None,
        status: None,
        index: Vec::new(),
        units: None,
    }
}

#[cfg(test)]
mod tests;
