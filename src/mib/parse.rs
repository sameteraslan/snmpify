//! A tolerant parser for SMIv1/SMIv2 MIB modules (RFC 1155, 1212, 2578,
//! 2579, 2580): enough of ASN.1 to collect every OID assignment, the
//! syntax and access of objects, textual conventions and imports.
//! Descriptions are skipped.

use super::{Access, BaseType, Kind, MibError, Status};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Tok {
    Word(String),
    Num(u64),
    Str(String),
    /// `::=`
    Assign,
    Sym(char),
    /// `..`
    Range,
}

pub(crate) fn tokenize(text: &str) -> Result<Vec<(Tok, usize)>, MibError> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1;
    while i < b.len() {
        let c = b[i];
        if c == b'\n' {
            line += 1;
            i += 1;
        } else if c.is_ascii_whitespace() {
            i += 1;
        } else if c == b'-' && b.get(i + 1) == Some(&b'-') {
            // A comment runs to the end of the line or the next "--".
            i += 2;
            while i < b.len() && b[i] != b'\n' {
                if b[i] == b'-' && b.get(i + 1) == Some(&b'-') {
                    i += 2;
                    break;
                }
                i += 1;
            }
        } else if c == b'"' {
            let start = i + 1;
            i += 1;
            while i < b.len() && b[i] != b'"' {
                if b[i] == b'\n' {
                    line += 1;
                }
                i += 1;
            }
            if i >= b.len() {
                return Err(MibError::Syntax {
                    line,
                    message: "unterminated string".into(),
                });
            }
            out.push((
                Tok::Str(String::from_utf8_lossy(&b[start..i]).into_owned()),
                line,
            ));
            i += 1;
        } else if c == b'\'' {
            // 'hex'H or 'bits'B: kept as a word.
            let start = i;
            i += 1;
            while i < b.len() && b[i] != b'\'' {
                i += 1;
            }
            i = (i + 2).min(b.len());
            out.push((
                Tok::Word(String::from_utf8_lossy(&b[start..i]).into_owned()),
                line,
            ));
        } else if c == b':' && b.get(i + 1) == Some(&b':') && b.get(i + 2) == Some(&b'=') {
            out.push((Tok::Assign, line));
            i += 3;
        } else if c == b'.' && b.get(i + 1) == Some(&b'.') {
            out.push((Tok::Range, line));
            i += 2;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let s = std::str::from_utf8(&b[start..i]).unwrap_or("0");
            match s.parse::<u64>() {
                Ok(n) => out.push((Tok::Num(n), line)),
                Err(_) => out.push((Tok::Word(s.into()), line)), // huge numbers in ranges
            }
        } else if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < b.len()
                && (b[i].is_ascii_alphanumeric()
                    || b[i] == b'_'
                    || (b[i] == b'-' && b.get(i + 1) != Some(&b'-')))
            {
                i += 1;
            }
            out.push((
                Tok::Word(String::from_utf8_lossy(&b[start..i]).into_owned()),
                line,
            ));
        } else {
            out.push((Tok::Sym(c as char), line));
            i += 1;
        }
    }
    Ok(out)
}

/// An OID value component: `name`, `n` or `name(n)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Component {
    Name(String),
    Num(u32),
    Named(String, u32),
}

/// A parsed `SYNTAX`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RawSyntax {
    /// The type as written (`DisplayString`, `INTEGER`, `OCTET STRING`).
    pub type_name: String,
    pub enums: Vec<(i64, String)>,
    /// `SEQUENCE OF X`.
    pub sequence_of: bool,
}

/// One OID assignment of a module.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawNode {
    pub name: String,
    pub kind: Kind,
    pub value: Vec<Component>,
    pub syntax: Option<RawSyntax>,
    pub access: Option<Access>,
    pub status: Option<Status>,
    pub index: Vec<String>,
    pub augments: Option<String>,
    pub units: Option<String>,
    /// TRAP-TYPE: the enterprise and the trap number.
    pub enterprise: Option<String>,
}

/// A textual convention or type assignment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RawType {
    pub name: String,
    pub syntax: RawSyntax,
    pub hint: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RawModule {
    pub name: String,
    /// (symbol, module it comes from)
    pub imports: Vec<(String, String)>,
    pub nodes: Vec<RawNode>,
    pub types: Vec<RawType>,
}

struct P {
    t: Vec<(Tok, usize)>,
    i: usize,
}

const MACROS: &[&str] = &[
    "MODULE-IDENTITY",
    "OBJECT-IDENTITY",
    "OBJECT-TYPE",
    "NOTIFICATION-TYPE",
    "TRAP-TYPE",
    "OBJECT-GROUP",
    "NOTIFICATION-GROUP",
    "MODULE-COMPLIANCE",
    "AGENT-CAPABILITIES",
];

/// Clause keywords: a clause runs until the next one or `::=`.
const CLAUSES: &[&str] = &[
    "SYNTAX",
    "MAX-ACCESS",
    "ACCESS",
    "MIN-ACCESS",
    "STATUS",
    "DESCRIPTION",
    "REFERENCE",
    "INDEX",
    "AUGMENTS",
    "DEFVAL",
    "UNITS",
    "DISPLAY-HINT",
    "LAST-UPDATED",
    "ORGANIZATION",
    "CONTACT-INFO",
    "REVISION",
    "OBJECTS",
    "NOTIFICATIONS",
    "ENTERPRISE",
    "VARIABLES",
    "MODULE",
    "MANDATORY-GROUPS",
    "GROUP",
    "OBJECT",
    "WRITE-SYNTAX",
    "PRODUCT-RELEASE",
    "SUPPORTS",
    "INCLUDES",
    "VARIATION",
    "CREATION-REQUIRES",
    "IMPLIED",
];

impl P {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i).map(|x| &x.0)
    }
    fn peek_at(&self, k: usize) -> Option<&Tok> {
        self.t.get(self.i + k).map(|x| &x.0)
    }
    fn line(&self) -> usize {
        self.t
            .get(self.i.min(self.t.len().saturating_sub(1)))
            .map_or(0, |x| x.1)
    }
    fn next(&mut self) -> Option<Tok> {
        let t = self.t.get(self.i).map(|x| x.0.clone());
        self.i += 1;
        t
    }
    fn err(&self, m: impl Into<String>) -> MibError {
        MibError::Syntax {
            line: self.line(),
            message: m.into(),
        }
    }
    fn is_word(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(x)) if x == w)
    }
    fn word(&mut self) -> Result<String, MibError> {
        match self.next() {
            Some(Tok::Word(w)) => Ok(w),
            t => Err(self.err(format!("expected a name, found {t:?}"))),
        }
    }
    fn expect(&mut self, t: Tok) -> Result<(), MibError> {
        match self.next() {
            Some(x) if x == t => Ok(()),
            x => Err(self.err(format!("expected {t:?}, found {x:?}"))),
        }
    }

    /// Skips a balanced group starting at an opening symbol.
    fn skip_group(&mut self) {
        let (open, close) = match self.peek() {
            Some(Tok::Sym('{')) => ('{', '}'),
            Some(Tok::Sym('(')) => ('(', ')'),
            Some(Tok::Sym('[')) => ('[', ']'),
            _ => return,
        };
        let mut depth = 0;
        while let Some(t) = self.next() {
            match t {
                Tok::Sym(c) if c == open => depth += 1,
                Tok::Sym(c) if c == close => {
                    depth -= 1;
                    if depth == 0 {
                        return;
                    }
                }
                _ => {}
            }
        }
    }

    /// `{ a b(1) 2 }`
    fn oid_value(&mut self) -> Result<Vec<Component>, MibError> {
        self.expect(Tok::Sym('{'))?;
        let mut v = Vec::new();
        loop {
            match self.next() {
                Some(Tok::Sym('}')) => return Ok(v),
                Some(Tok::Num(n)) => v.push(Component::Num(n as u32)),
                Some(Tok::Word(w)) => {
                    if self.peek() == Some(&Tok::Sym('(')) {
                        self.next();
                        let n = match self.next() {
                            Some(Tok::Num(n)) => n as u32,
                            t => return Err(self.err(format!("expected a number, found {t:?}"))),
                        };
                        self.expect(Tok::Sym(')'))?;
                        v.push(Component::Named(w, n));
                    } else {
                        v.push(Component::Name(w));
                    }
                }
                t => return Err(self.err(format!("bad OID value component {t:?}"))),
            }
        }
    }

    /// A type: `INTEGER { a(1) }`, `OCTET STRING (SIZE (6))`,
    /// `SEQUENCE OF X`, `X (1..10)`, `BITS { … }`.
    fn syntax(&mut self) -> Result<RawSyntax, MibError> {
        let mut s = RawSyntax::default();
        if self.is_word("SEQUENCE") && matches!(self.peek_at(1), Some(Tok::Word(w)) if w == "OF") {
            self.next();
            self.next();
            s.sequence_of = true;
            s.type_name = self.word()?;
            return Ok(s);
        }
        if self.peek() == Some(&Tok::Sym('[')) {
            self.skip_group(); // [APPLICATION n]
            if self.is_word("IMPLICIT") {
                self.next();
            }
        }
        let mut name = self.word()?;
        if (name == "OCTET" && self.is_word("STRING"))
            || (name == "OBJECT" && self.is_word("IDENTIFIER"))
        {
            name = format!("{name} {}", self.word()?);
        }
        s.type_name = name;
        loop {
            match self.peek() {
                Some(Tok::Sym('{')) => {
                    // Enumerations / named bits: { name(n), … }
                    self.next();
                    loop {
                        match self.next() {
                            Some(Tok::Sym('}')) => break,
                            Some(Tok::Sym(',')) => {}
                            Some(Tok::Word(w)) => {
                                self.expect(Tok::Sym('('))?;
                                let neg = self.peek() == Some(&Tok::Sym('-'));
                                if neg {
                                    self.next();
                                }
                                let n = match self.next() {
                                    Some(Tok::Num(n)) => n as i64,
                                    t => return Err(self.err(format!("bad enumeration {t:?}"))),
                                };
                                self.expect(Tok::Sym(')'))?;
                                s.enums.push((if neg { -n } else { n }, w));
                            }
                            t => return Err(self.err(format!("bad enumeration {t:?}"))),
                        }
                    }
                }
                Some(Tok::Sym('(')) => self.skip_group(), // ranges and sizes
                _ => return Ok(s),
            }
        }
    }

    /// Clause values up to the next clause keyword or `::=`.
    fn skip_clause_value(&mut self) {
        loop {
            match self.peek() {
                None | Some(Tok::Assign) => return,
                Some(Tok::Word(w)) if CLAUSES.contains(&w.as_str()) => return,
                Some(Tok::Sym('{' | '(' | '[')) => self.skip_group(),
                _ => {
                    self.next();
                }
            }
        }
    }

    fn names_in_braces(&mut self) -> Result<Vec<String>, MibError> {
        self.expect(Tok::Sym('{'))?;
        let mut v = Vec::new();
        loop {
            match self.next() {
                Some(Tok::Sym('}')) => return Ok(v),
                Some(Tok::Sym(',')) => {}
                Some(Tok::Word(w)) if w == "IMPLIED" => {}
                Some(Tok::Word(w)) => v.push(w),
                t => return Err(self.err(format!("bad name list {t:?}"))),
            }
        }
    }

    fn macro_node(&mut self, name: String, mac: &str) -> Result<RawNode, MibError> {
        let mut n = RawNode {
            name,
            kind: match mac {
                "OBJECT-TYPE" => Kind::Scalar, // refined after resolution
                "NOTIFICATION-TYPE" | "TRAP-TYPE" => Kind::Notification,
                "OBJECT-GROUP" | "NOTIFICATION-GROUP" => Kind::Group,
                "MODULE-COMPLIANCE" => Kind::Compliance,
                "AGENT-CAPABILITIES" => Kind::Capabilities,
                "MODULE-IDENTITY" => Kind::ModuleIdentity,
                _ => Kind::Node,
            },
            value: Vec::new(),
            syntax: None,
            access: None,
            status: None,
            index: Vec::new(),
            augments: None,
            units: None,
            enterprise: None,
        };
        // MODULE-COMPLIANCE / AGENT-CAPABILITIES contain nested SYNTAX and
        // ACCESS clauses for other objects: only take the first ones.
        let nested = matches!(n.kind, Kind::Compliance | Kind::Capabilities);
        loop {
            match self.next() {
                None => return Err(self.err(format!("{} never ends", n.name))),
                Some(Tok::Assign) => break,
                Some(Tok::Word(w)) => match w.as_str() {
                    "SYNTAX" if !nested && n.syntax.is_none() => n.syntax = Some(self.syntax()?),
                    "MAX-ACCESS" | "ACCESS" if !nested && n.access.is_none() => {
                        let a = self.word()?;
                        n.access = Access::parse(&a);
                    }
                    "STATUS" if n.status.is_none() => {
                        let s = self.word()?;
                        n.status = Status::parse(&s);
                    }
                    "INDEX" if !nested => n.index = self.names_in_braces()?,
                    "AUGMENTS" if !nested => {
                        n.augments = self.names_in_braces()?.into_iter().next();
                    }
                    "UNITS" => {
                        if let Some(Tok::Str(u)) = self.next() {
                            n.units = Some(u);
                        }
                    }
                    "ENTERPRISE" if mac == "TRAP-TYPE" => n.enterprise = Some(self.word()?),
                    _ => self.skip_clause_value(),
                },
                Some(Tok::Sym('{' | '(' | '[')) => {
                    self.i -= 1;
                    self.skip_group();
                }
                Some(_) => {}
            }
        }
        if mac == "TRAP-TYPE" {
            // SMIv1 traps: `::= n`, under enterprise.0.n (RFC 3584 §3.1).
            let num = match self.next() {
                Some(Tok::Num(x)) => x as u32,
                t => return Err(self.err(format!("bad TRAP-TYPE value {t:?}"))),
            };
            let e = n
                .enterprise
                .clone()
                .ok_or_else(|| self.err("TRAP-TYPE without ENTERPRISE"))?;
            n.value = vec![Component::Name(e), Component::Num(0), Component::Num(num)];
        } else {
            n.value = self.oid_value()?;
        }
        Ok(n)
    }

    fn module(&mut self) -> Result<RawModule, MibError> {
        let mut m = RawModule {
            name: self.word()?,
            ..RawModule::default()
        };
        // `NAME { oid } DEFINITIONS` (some SMIv1 modules)
        if self.peek() == Some(&Tok::Sym('{')) {
            self.skip_group();
        }
        if !self.is_word("DEFINITIONS") {
            return Err(self.err("expected DEFINITIONS"));
        }
        self.next();
        self.expect(Tok::Assign)?;
        if !self.is_word("BEGIN") {
            return Err(self.err("expected BEGIN"));
        }
        self.next();
        loop {
            let Some(t) = self.next() else {
                return Err(self.err(format!("module {} has no END", m.name)));
            };
            let w = match t {
                Tok::Word(w) => w,
                _ => continue, // stray symbol: resynchronise on the next name
            };
            match w.as_str() {
                "END" => return Ok(m),
                "IMPORTS" => {
                    let mut pending = Vec::new();
                    loop {
                        match self.next() {
                            Some(Tok::Sym(';')) | None => break,
                            Some(Tok::Word(f)) if f == "FROM" => {
                                let module = self.word()?;
                                for s in pending.drain(..) {
                                    m.imports.push((s, module.clone()));
                                }
                            }
                            Some(Tok::Word(s)) => pending.push(s),
                            _ => {}
                        }
                    }
                }
                "EXPORTS" => while !matches!(self.next(), Some(Tok::Sym(';')) | None) {},
                _ => {
                    // A macro definition: `NAME MACRO ::= BEGIN … END`.
                    if self.is_word("MACRO") {
                        while !matches!(self.next(), Some(Tok::Word(e)) if e == "END") {
                            if self.peek().is_none() {
                                return Err(self.err("unterminated MACRO"));
                            }
                        }
                        continue;
                    }
                    match self.peek() {
                        Some(Tok::Word(k))
                            if k == "OBJECT"
                                && matches!(self.peek_at(1), Some(Tok::Word(x)) if x == "IDENTIFIER") =>
                        {
                            self.next();
                            self.next();
                            self.expect(Tok::Assign)?;
                            let value = self.oid_value()?;
                            m.nodes.push(RawNode {
                                name: w,
                                kind: Kind::Node,
                                value,
                                syntax: None,
                                access: None,
                                status: None,
                                index: Vec::new(),
                                augments: None,
                                units: None,
                                enterprise: None,
                            });
                        }
                        Some(Tok::Word(k)) if MACROS.contains(&k.as_str()) => {
                            let mac = k.clone();
                            self.next();
                            m.nodes.push(self.macro_node(w, &mac)?);
                        }
                        Some(Tok::Assign) => {
                            self.next();
                            if self.is_word("TEXTUAL-CONVENTION") {
                                self.next();
                                let mut hint = None;
                                let mut syntax = None;
                                while !self.is_word("SYNTAX") {
                                    match self.next() {
                                        None => {
                                            return Err(
                                                self.err("TEXTUAL-CONVENTION without SYNTAX")
                                            )
                                        }
                                        Some(Tok::Word(k)) if k == "DISPLAY-HINT" => {
                                            if let Some(Tok::Str(h)) = self.next() {
                                                hint = Some(h);
                                            }
                                        }
                                        _ => {}
                                    }
                                }
                                self.next();
                                syntax.get_or_insert(self.syntax()?);
                                m.types.push(RawType {
                                    name: w,
                                    syntax: syntax.unwrap_or_default(),
                                    hint,
                                });
                            } else if self.is_word("SEQUENCE")
                                && self.peek_at(1) == Some(&Tok::Sym('{'))
                            {
                                // Row type: `X ::= SEQUENCE { a T, … }`
                                self.next();
                                self.skip_group();
                                m.types.push(RawType {
                                    name: w,
                                    syntax: RawSyntax {
                                        type_name: "SEQUENCE".into(),
                                        ..RawSyntax::default()
                                    },
                                    hint: None,
                                });
                            } else if self.is_word("CHOICE") {
                                self.next();
                                self.skip_group();
                            } else {
                                let syntax = self.syntax()?;
                                m.types.push(RawType {
                                    name: w,
                                    syntax,
                                    hint: None,
                                });
                            }
                        }
                        // Anything else (value assignments of other types,
                        // SMIv1 oddities): skip the name.
                        _ => {}
                    }
                }
            }
        }
    }
}

/// Parses every module in a text.
pub(crate) fn parse(text: &str) -> Result<Vec<RawModule>, MibError> {
    let mut p = P {
        t: tokenize(text)?,
        i: 0,
    };
    let mut mods = Vec::new();
    while p.peek().is_some() {
        // Find `NAME [{…}] DEFINITIONS`.
        let is_start = matches!(p.peek(), Some(Tok::Word(_)))
            && (matches!(p.peek_at(1), Some(Tok::Word(w)) if w == "DEFINITIONS")
                || p.peek_at(1) == Some(&Tok::Sym('{')));
        if is_start {
            let save = p.i;
            match p.module() {
                Ok(m) => mods.push(m),
                Err(e) if mods.is_empty() && p.i > save + 3 => return Err(e),
                Err(e) => return Err(e),
            }
        } else {
            p.next();
        }
    }
    if mods.is_empty() {
        return Err(MibError::Syntax {
            line: 0,
            message: "no MIB module found".into(),
        });
    }
    Ok(mods)
}

/// The base SMI type for a type name, following textual conventions.
pub(crate) fn base_of(type_name: &str) -> Option<BaseType> {
    Some(match type_name {
        "INTEGER" | "Integer32" => BaseType::Integer,
        "OCTET STRING" => BaseType::OctetString,
        "OBJECT IDENTIFIER" => BaseType::ObjectId,
        "BITS" => BaseType::Bits,
        "IpAddress" | "NetworkAddress" => BaseType::IpAddress,
        "Counter32" | "Counter" => BaseType::Counter32,
        "Gauge32" | "Gauge" => BaseType::Gauge32,
        "Unsigned32" => BaseType::Unsigned32,
        "TimeTicks" => BaseType::TimeTicks,
        "Opaque" => BaseType::Opaque,
        "Counter64" => BaseType::Counter64,
        _ => return None,
    })
}
