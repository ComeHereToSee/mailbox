//! Full-text search helpers: CJK bigram segmentation for the FTS5 index and a
//! Gmail-like query language (`from:` `has:attachment` `before:` ...).

use chrono::{Local, NaiveDate, TimeZone};
use rusqlite::types::Value;

fn is_cjk(c: char) -> bool {
    matches!(c as u32,
        0x3040..=0x30FF      // Hiragana, Katakana
        | 0x3400..=0x4DBF    // CJK Ext A
        | 0x4E00..=0x9FFF    // CJK Unified
        | 0xF900..=0xFAFF    // Compatibility
        | 0xAC00..=0xD7AF    // Hangul
        | 0x20000..=0x2FA1F) // Ext B..
}

/// Splits CJK runs into overlapping bigrams so `unicode61` can index substrings.
/// `"QQ邮箱客户端"` → `"QQ 邮箱 箱客 客户 户端 "`.
pub fn segment(text: &str) -> String {
    let mut out = String::with_capacity(text.len() * 2);
    let mut run: Vec<char> = Vec::new();
    for c in text.chars() {
        if is_cjk(c) {
            run.push(c);
        } else {
            flush(&mut run, &mut out);
            out.push(c);
        }
    }
    flush(&mut run, &mut out);
    out
}

fn flush(run: &mut Vec<char>, out: &mut String) {
    if run.is_empty() {
        return;
    }
    out.push(' ');
    if run.len() == 1 {
        out.push(run[0]);
        out.push(' ');
    } else {
        for w in run.windows(2) {
            out.push(w[0]);
            out.push(w[1]);
            out.push(' ');
        }
    }
    run.clear();
}

/// Turns one user term into an FTS5 phrase (`"客户 户端"`, `"hello"*`).
pub fn fts_phrase(term: &str) -> Option<String> {
    let seg = segment(term);
    let tokens: Vec<String> = seg
        .split(|c: char| !c.is_alphanumeric() && !is_cjk(c))
        .filter(|t| !t.is_empty())
        .map(|t| t.to_lowercase())
        .collect();
    if tokens.is_empty() {
        return None;
    }
    let last_is_cjk = term.chars().last().map(is_cjk).unwrap_or(false);
    let single_cjk = tokens.len() == 1 && tokens[0].chars().count() == 1 && last_is_cjk;
    let phrase = tokens.join(" ").replace('"', "\"\"");
    if !last_is_cjk || single_cjk {
        Some(format!("\"{phrase}\"*"))
    } else {
        Some(format!("\"{phrase}\""))
    }
}

/// SQL fragments (joined with AND) referring to `m` (messages) and `f` (folders).
#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub clauses: Vec<String>,
    pub params: Vec<Value>,
}

impl Filter {
    pub fn push(&mut self, clause: impl Into<String>, params: impl IntoIterator<Item = Value>) {
        self.clauses.push(clause.into());
        self.params.extend(params);
    }

    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty()
    }

    pub fn sql(&self) -> String {
        if self.clauses.is_empty() {
            "1".into()
        } else {
            self.clauses.iter().map(|c| format!("({c})")).collect::<Vec<_>>().join(" AND ")
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct ParsedQuery {
    pub terms: Vec<(bool, String)>,
    pub ops: Vec<(bool, String, String)>,
}

/// Tokenizes `from:"Zhang San" -is:read 报价单` into terms and operators.
pub fn parse(query: &str) -> ParsedQuery {
    let mut out = ParsedQuery::default();
    let chars: Vec<char> = query.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut negated = false;
        if chars[i] == '-' && i + 1 < chars.len() && !chars[i + 1].is_whitespace() {
            negated = true;
            i += 1;
        }
        let mut key = String::new();
        let mut value = String::new();
        let mut in_key = true;
        let mut quoted = false;
        while i < chars.len() {
            let c = chars[i];
            if c == '"' {
                quoted = !quoted;
                in_key = false;
                i += 1;
                continue;
            }
            if c.is_whitespace() && !quoted {
                break;
            }
            if in_key && c == ':' && !key.is_empty() && is_operator(&key) {
                in_key = false;
                i += 1;
                continue;
            }
            if in_key {
                key.push(c);
            } else {
                value.push(c);
            }
            i += 1;
        }
        if in_key {
            if !key.is_empty() {
                out.terms.push((negated, key));
            }
        } else if is_operator(&key) {
            out.ops.push((negated, key.to_lowercase(), value));
        } else {
            let term = if key.is_empty() { value } else { format!("{key}{value}") };
            if !term.is_empty() {
                out.terms.push((negated, term));
            }
        }
    }
    out
}

fn is_operator(key: &str) -> bool {
    matches!(
        key.to_lowercase().as_str(),
        "from" | "to" | "cc" | "subject" | "has" | "is" | "in" | "label" | "account" | "before" | "after"
            | "older_than" | "newer_than" | "larger" | "smaller" | "category" | "filename" | "body"
    )
}

fn parse_date(s: &str) -> Option<i64> {
    let s = s.replace('/', "-");
    let d = NaiveDate::parse_from_str(&s, "%Y-%m-%d").ok()?;
    Local.from_local_datetime(&d.and_hms_opt(0, 0, 0)?).earliest().map(|t| t.timestamp())
}

fn parse_age(s: &str) -> Option<i64> {
    let (num, unit) = s.split_at(s.find(|c: char| !c.is_ascii_digit())?);
    let n: i64 = num.parse().ok()?;
    let secs = match unit {
        "d" => 86_400,
        "w" => 7 * 86_400,
        "m" => 30 * 86_400,
        "y" => 365 * 86_400,
        "h" => 3_600,
        _ => return None,
    };
    Some(crate::store::now() - n * secs)
}

fn parse_size(s: &str) -> Option<i64> {
    let s = s.to_lowercase();
    let (num, mult) = if let Some(n) = s.strip_suffix('k') {
        (n, 1024)
    } else if let Some(n) = s.strip_suffix('m') {
        (n, 1024 * 1024)
    } else if let Some(n) = s.strip_suffix('g') {
        (n, 1024 * 1024 * 1024)
    } else {
        (s.as_str(), 1)
    };
    num.trim().parse::<f64>().ok().map(|v| (v * mult as f64) as i64)
}

fn like(v: &str) -> Value {
    Value::Text(format!("%{}%", v.replace('%', "").replace('_', "\\_")))
}

/// Compiles a query into a SQL filter. Free text goes through the FTS index.
pub fn compile(query: &str) -> Filter {
    let parsed = parse(query);
    let mut f = Filter::default();
    let mut fts_pos: Vec<String> = Vec::new();
    let mut fts_neg: Vec<String> = Vec::new();

    for (neg, term) in &parsed.terms {
        if let Some(p) = fts_phrase(term) {
            if *neg { fts_neg.push(p) } else { fts_pos.push(p) }
        }
    }

    for (neg, key, value) in &parsed.ops {
        let (clause, params): (String, Vec<Value>) = match key.as_str() {
            "from" => (
                "m.from_email LIKE ? ESCAPE '\\' OR m.from_name LIKE ? ESCAPE '\\'".into(),
                vec![like(value), like(value)],
            ),
            "to" => ("m.to_json LIKE ? ESCAPE '\\'".into(), vec![like(value)]),
            "cc" => ("m.cc_json LIKE ? ESCAPE '\\'".into(), vec![like(value)]),
            "subject" => ("m.subject LIKE ? ESCAPE '\\'".into(), vec![like(value)]),
            "body" | "filename" => {
                let col = if key == "body" { "body" } else { "attachments" };
                if let Some(p) = fts_phrase(value) {
                    let p = format!("{col} : {p}");
                    if *neg { fts_neg.push(p) } else { fts_pos.push(p) }
                }
                continue;
            }
            "has" => match value.to_lowercase().as_str() {
                "attachment" | "attachments" | "附件" => ("m.has_attachments = 1".into(), vec![]),
                "unsubscribe" => ("m.unsubscribe IS NOT NULL".into(), vec![]),
                _ => continue,
            },
            "is" => match value.to_lowercase().as_str() {
                "unread" | "未读" => ("m.seen = 0".into(), vec![]),
                "read" | "已读" => ("m.seen = 1".into(), vec![]),
                "starred" | "flagged" | "星标" => ("m.flagged = 1".into(), vec![]),
                "answered" | "replied" => ("m.answered = 1".into(), vec![]),
                "pinned" => ("m.pinned = 1".into(), vec![]),
                "snoozed" => ("m.snoozed_until IS NOT NULL".into(), vec![]),
                "vip" => ("m.from_email IN (SELECT email FROM contacts WHERE vip = 1)".into(), vec![]),
                _ => continue,
            },
            "in" => {
                let role = crate::model::FolderRole::parse(&value.to_lowercase());
                if role != crate::model::FolderRole::Custom {
                    ("f.role = ?".into(), vec![Value::Text(role.as_str().into())])
                } else {
                    ("f.name LIKE ? ESCAPE '\\' OR f.path LIKE ? ESCAPE '\\'".into(), vec![like(value), like(value)])
                }
            }
            "label" => (
                "m.labels LIKE ? ESCAPE '\\' OR f.name LIKE ? ESCAPE '\\'".into(),
                vec![like(value), like(value)],
            ),
            "account" => (
                "m.account_id IN (SELECT id FROM accounts WHERE label LIKE ? ESCAPE '\\' OR email LIKE ? ESCAPE '\\' OR id = ?)".into(),
                vec![like(value), like(value), Value::Text(value.clone())],
            ),
            "category" => ("m.category = ?".into(), vec![Value::Text(value.to_lowercase())]),
            "before" | "older_than" | "after" | "newer_than" => {
                let ts = if key == "before" || key == "after" { parse_date(value) } else { parse_age(value) };
                let Some(ts) = ts else { continue };
                let op = if key == "before" || key == "older_than" { "<" } else { ">=" };
                (format!("m.date {op} ?"), vec![Value::Integer(ts)])
            }
            "larger" | "smaller" => {
                let Some(sz) = parse_size(value) else { continue };
                let op = if key == "larger" { ">" } else { "<" };
                (format!("m.size {op} ?"), vec![Value::Integer(sz)])
            }
            _ => continue,
        };
        if *neg {
            f.push(format!("NOT ({clause})"), params);
        } else {
            f.push(clause, params);
        }
    }

    if !fts_pos.is_empty() {
        f.push(
            "m.id IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)",
            [Value::Text(fts_pos.join(" AND "))],
        );
    }
    if !fts_neg.is_empty() {
        f.push(
            "m.id NOT IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)",
            [Value::Text(fts_neg.join(" OR "))],
        );
    }
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segments_cjk_into_bigrams() {
        assert_eq!(segment("QQ邮箱"), "QQ 邮箱 ");
        assert_eq!(segment("客户端v2"), " 客户 户端 v2");
        assert_eq!(segment("a中b"), "a 中 b");
    }

    #[test]
    fn phrases() {
        assert_eq!(fts_phrase("客户端").unwrap(), "\"客户 户端\"");
        assert_eq!(fts_phrase("Hello").unwrap(), "\"hello\"*");
        assert_eq!(fts_phrase("邮").unwrap(), "\"邮\"*");
        assert_eq!(fts_phrase("QQ邮箱").unwrap(), "\"qq 邮箱\"");
        assert!(fts_phrase("!!").is_none());
    }

    #[test]
    fn parses_operators() {
        let p = parse(r#"from:"Zhang San" -is:read 报价单 subject:合同 -spam"#);
        assert_eq!(p.terms, vec![(false, "报价单".into()), (true, "spam".into())]);
        assert_eq!(
            p.ops,
            vec![
                (false, "from".into(), "Zhang San".into()),
                (true, "is".into(), "read".into()),
                (false, "subject".into(), "合同".into())
            ]
        );
        // URLs and times are not operators
        let p = parse("http://x.com 10:30");
        assert_eq!(p.terms.len(), 2);
    }

    #[test]
    fn compiles() {
        let f = compile("from:boss has:attachment larger:1M 报价");
        assert_eq!(f.clauses.len(), 4);
        assert!(f.sql().contains("messages_fts MATCH"));
        let f = compile("before:2024-01-01 newer_than:7d");
        assert_eq!(f.clauses.len(), 2);
    }
}
