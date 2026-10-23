//! Local mail rules: conditions evaluated against new messages, producing actions.

use crate::model::{Rule, RuleCondition};
use regex::Regex;

pub struct RuleInput<'a> {
    pub account_id: &'a str,
    pub from: &'a str,
    pub from_name: &'a str,
    pub to: &'a [String],
    pub cc: &'a [String],
    pub subject: &'a str,
    pub body: Option<&'a str>,
    pub has_attachment: bool,
    pub list_id: Option<&'a str>,
    /// Raw header block for `header:<Name>` conditions.
    pub raw_headers: Option<&'a [u8]>,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct RuleOutcome {
    pub move_to: Option<String>,
    pub archive: bool,
    pub trash: bool,
    pub mark_read: bool,
    pub flag: bool,
    pub labels: Vec<String>,
    pub category: Option<String>,
    pub forward_to: Vec<String>,
    /// Some(false) suppresses the notification, Some(true) forces it.
    pub notify: Option<bool>,
    pub vip: bool,
    pub matched: Vec<String>,
}

fn header_value(raw: &[u8], name: &str) -> Option<String> {
    let msg = mail_parser::MessageParser::default().parse_headers(raw)?;
    msg.header_raw(name).map(|s| s.trim().to_string())
}

fn test(op: &str, haystack: &str, value: &str) -> bool {
    let h = haystack.to_lowercase();
    let v = value.to_lowercase();
    match op {
        "contains" => h.contains(&v),
        "not_contains" => !h.contains(&v),
        "equals" => h == v,
        "starts_with" => h.starts_with(&v),
        "ends_with" => h.ends_with(&v),
        "regex" => Regex::new(value).map(|r| r.is_match(haystack)).unwrap_or(false),
        "exists" => !haystack.is_empty(),
        _ => false,
    }
}

fn eval(c: &RuleCondition, m: &RuleInput) -> bool {
    let joined = |v: &[String]| v.join(", ");
    match c.field.as_str() {
        "from" => test(&c.op, &format!("{} <{}>", m.from_name, m.from), &c.value),
        "to" => test(&c.op, &joined(m.to), &c.value),
        "cc" => test(&c.op, &joined(m.cc), &c.value),
        "recipients" => test(&c.op, &format!("{}, {}", joined(m.to), joined(m.cc)), &c.value),
        "subject" => test(&c.op, m.subject, &c.value),
        "body" => m.body.map(|b| test(&c.op, b, &c.value)).unwrap_or(c.op == "not_contains"),
        "has_attachment" => m.has_attachment == (c.value != "false"),
        "account" => m.account_id == c.value,
        "list_id" => test(&c.op, m.list_id.unwrap_or(""), &c.value),
        f if f.starts_with("header:") => {
            let name = &f[7..];
            let v = m.raw_headers.and_then(|r| header_value(r, name)).unwrap_or_default();
            test(&c.op, &v, &c.value)
        }
        _ => false,
    }
}

pub fn rule_matches(rule: &Rule, m: &RuleInput) -> bool {
    if !rule.enabled || rule.conditions.is_empty() {
        return false;
    }
    if let Some(acc) = &rule.account_id {
        if !acc.is_empty() && acc != m.account_id {
            return false;
        }
    }
    if rule.match_all {
        rule.conditions.iter().all(|c| eval(c, m))
    } else {
        rule.conditions.iter().any(|c| eval(c, m))
    }
}

/// Applies all matching rules in order (a `stop` action ends processing).
pub fn evaluate(rules: &[Rule], m: &RuleInput) -> RuleOutcome {
    let mut out = RuleOutcome::default();
    for rule in rules {
        if !rule_matches(rule, m) {
            continue;
        }
        out.matched.push(rule.name.clone());
        let mut stop = false;
        for a in &rule.actions {
            match a.kind.as_str() {
                "move" => out.move_to = Some(a.value.clone()),
                "archive" => out.archive = true,
                "trash" => out.trash = true,
                "mark_read" => out.mark_read = true,
                "flag" => out.flag = true,
                "label" => out.labels.push(a.value.clone()),
                "category" => out.category = Some(a.value.clone()),
                "forward" => out.forward_to.extend(a.value.split([',', ';']).map(|s| s.trim().to_string()).filter(|s| !s.is_empty())),
                "no_notify" => out.notify = Some(false),
                "notify" => out.notify = Some(true),
                "vip" => out.vip = true,
                "stop" => stop = true,
                _ => {}
            }
        }
        if stop {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::RuleAction;

    #[test]
    fn evaluates_rules() {
        let rules = vec![
            Rule {
                name: "账单".into(),
                enabled: true,
                match_all: true,
                conditions: vec![
                    RuleCondition { field: "from".into(), op: "ends_with".into(), value: "@alipay.com>".into() },
                    RuleCondition { field: "subject".into(), op: "contains".into(), value: "账单".into() },
                ],
                actions: vec![
                    RuleAction { kind: "move".into(), value: "账单".into() },
                    RuleAction { kind: "mark_read".into(), value: String::new() },
                    RuleAction { kind: "stop".into(), value: String::new() },
                ],
                ..Default::default()
            },
            Rule {
                name: "all".into(),
                enabled: true,
                conditions: vec![RuleCondition { field: "subject".into(), op: "exists".into(), value: String::new() }],
                actions: vec![RuleAction { kind: "flag".into(), value: String::new() }],
                ..Default::default()
            },
        ];
        let input = RuleInput {
            account_id: "a",
            from: "service@alipay.com",
            from_name: "支付宝",
            to: &[],
            cc: &[],
            subject: "您的10月账单",
            body: None,
            has_attachment: false,
            list_id: None,
            raw_headers: Some(b"X-Spam: yes\r\nSubject: x\r\n\r\n"),
        };
        let out = evaluate(&rules, &input);
        assert_eq!(out.move_to.as_deref(), Some("账单"));
        assert!(out.mark_read);
        assert!(!out.flag, "stop must prevent later rules");
        let hdr = Rule {
            name: "h".into(),
            enabled: true,
            conditions: vec![RuleCondition { field: "header:X-Spam".into(), op: "equals".into(), value: "yes".into() }],
            actions: vec![RuleAction { kind: "trash".into(), value: String::new() }],
            ..Default::default()
        };
        assert!(evaluate(&[hdr], &input).trash);
    }
}
