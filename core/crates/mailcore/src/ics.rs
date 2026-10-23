//! iCalendar invites (RFC 5545) and iMIP replies (RFC 5546 / RFC 6047).
//!
//! Times in [`CalendarInvite`] are unix seconds. All-day events (`VALUE=DATE`)
//! are stored as midnight **UTC** of the calendar date with an exclusive end
//! (a one-day event on 10-23 has `end` = 10-24 00:00 UTC), so the UI formats
//! all-day values in UTC.

use crate::error::{Error, Result};
use crate::model::{CalendarInvite, EmailAddress};
use chrono::{Datelike, NaiveDate, NaiveDateTime, TimeDelta, TimeZone, Timelike, Utc, Weekday};
use chrono_tz::Tz;

const PRODID: &str = "-//Mailbox//Mailbox Mail 1.0//ZH-CN";
/// Maximum octets per physical line (RFC 5545 §3.1), excluding the CRLF.
const FOLD_OCTETS: usize = 75;
const DAY: i64 = 86_400;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parses the first VEVENT of a text/calendar body into the model type.
/// `own` = the user's addresses (lowercase) used to fill `my_status`.
pub fn parse_invite(ics: &str, own: &[String]) -> Option<CalendarInvite> {
    let root = parse_tree(ics);
    let cal = root.find("VCALENDAR").unwrap_or(&root);
    let ev = cal.find("VEVENT")?;
    let ctx = Ctx { cal };

    let method = cal
        .prop("METHOD")
        .map(|p| p.value.trim().to_ascii_uppercase())
        .filter(|m| !m.is_empty())
        .unwrap_or_else(|| "PUBLISH".into());

    let start = ev.prop("DTSTART").and_then(|p| ctx.eval_dt(p));
    let end = match (ev.prop("DTEND"), ev.prop("DURATION")) {
        (Some(p), _) => ctx.eval_dt(p).map(|w| w.ts),
        (None, Some(dur)) => start.as_ref().and_then(|s| parse_duration(&dur.value).and_then(|d| s.add(d))),
        // RFC 5545 §3.6.1: a DATE start without end lasts one day, a DATE-TIME start ends at the start.
        (None, None) => start.as_ref().map(|s| if s.all_day { s.ts + DAY } else { s.ts }),
    };

    let attendees: Vec<EmailAddress> = ev.props_named("ATTENDEE").filter_map(address).collect();
    let my_status = ev
        .props_named("ATTENDEE")
        .find(|p| address(p).is_some_and(|a| own.iter().any(|o| o.trim().eq_ignore_ascii_case(&a.email))))
        .map(|p| {
            p.param("PARTSTAT")
                .map(|s| s.trim().to_ascii_uppercase())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "NEEDS-ACTION".into())
        });

    Some(CalendarInvite {
        method,
        uid: ev.prop("UID").map(|p| p.value.trim().to_string()).unwrap_or_default(),
        summary: ev.prop("SUMMARY").map(|p| p.text().trim().to_string()).unwrap_or_default(),
        location: ev.prop("LOCATION").map(|p| p.text().trim().to_string()).filter(|s| !s.is_empty()),
        description: ev.prop("DESCRIPTION").map(|p| p.text().trim().to_string()).filter(|s| !s.is_empty()),
        all_day: start.as_ref().is_some_and(|s| s.all_day),
        start: start.as_ref().map(|s| s.ts),
        end,
        organizer: ev.prop("ORGANIZER").and_then(address),
        attendees,
        my_status,
        raw: ics.to_string(),
    })
}

/// Builds the METHOD:REPLY calendar for `attendee` with PARTSTAT (ACCEPTED | TENTATIVE | DECLINED),
/// keeping UID, RECURRENCE-ID, SEQUENCE, DTSTART/DTEND (or DURATION), a new DTSTAMP, ORGANIZER,
/// SUMMARY and only our ATTENDEE line. VTIMEZONEs referenced by the copied dates are included.
pub fn build_reply(
    original_ics: &str,
    attendee_email: &str,
    attendee_name: Option<&str>,
    partstat: &str,
) -> Result<String> {
    let partstat = partstat.trim().to_ascii_uppercase();
    if !matches!(partstat.as_str(), "ACCEPTED" | "TENTATIVE" | "DECLINED") {
        return Err(Error::Invalid(format!("无效的参与状态: {partstat}")));
    }
    let email = strip_mailto(attendee_email);
    if !email.contains('@') {
        return Err(Error::Invalid(format!("无效的邮箱地址: {attendee_email}")));
    }

    let root = parse_tree(original_ics);
    let cal = root.find("VCALENDAR").unwrap_or(&root);
    let ev = cal.find("VEVENT").ok_or_else(|| Error::Invalid("日历邀请中没有找到日程 (VEVENT)".into()))?;
    let uid = ev.prop("UID").ok_or_else(|| Error::Invalid("日历邀请缺少 UID".into()))?;

    // Our ATTENDEE line: keep the organizer's parameters (CN, ROLE, CUTYPE ...) but replace PARTSTAT/RSVP.
    let mut attendee = ev
        .props_named("ATTENDEE")
        .find(|p| address(p).is_some_and(|a| a.email.eq_ignore_ascii_case(email)))
        .cloned()
        .unwrap_or_else(|| Prop::new("ATTENDEE", format!("mailto:{email}")));
    attendee.params.retain(|p| p.name != "PARTSTAT" && p.name != "RSVP");
    if let Some(name) = attendee_name.map(str::trim).filter(|n| !n.is_empty()) {
        attendee.params.retain(|p| p.name != "CN");
        attendee.params.insert(0, Param::new("CN", name));
    }
    attendee.params.push(Param::new("PARTSTAT", &partstat));

    let mut out = String::new();
    push_line(&mut out, "BEGIN:VCALENDAR");
    push_line(&mut out, &format!("PRODID:{PRODID}"));
    push_line(&mut out, "VERSION:2.0");
    push_line(&mut out, "CALSCALE:GREGORIAN");
    push_line(&mut out, "METHOD:REPLY");

    let date_props: Vec<&Prop> = ["DTSTART", "DTEND", "RECURRENCE-ID"].iter().filter_map(|n| ev.prop(n)).collect();
    let tzids: Vec<String> = date_props.iter().filter_map(|p| p.param("TZID")).map(norm_tzid).collect();
    let mut written: Vec<String> = Vec::new();
    for vtz in cal.descendants("VTIMEZONE") {
        let Some(id) = vtz.prop("TZID").map(|p| norm_tzid(&p.value)) else { continue };
        if tzids.contains(&id) && !written.contains(&id) {
            write_component(&mut out, vtz);
            written.push(id);
        }
    }

    push_line(&mut out, "BEGIN:VEVENT");
    write_prop(&mut out, uid);
    if let Some(p) = ev.prop("RECURRENCE-ID") {
        write_prop(&mut out, p);
    }
    match ev.prop("SEQUENCE") {
        Some(p) => write_prop(&mut out, p),
        None => push_line(&mut out, "SEQUENCE:0"),
    }
    push_line(&mut out, &format!("DTSTAMP:{}", utc_stamp(Utc::now().timestamp())));
    for name in ["DTSTART", "DTEND"] {
        if let Some(p) = ev.prop(name) {
            write_prop(&mut out, p);
        }
    }
    if ev.prop("DTEND").is_none()
        && let Some(p) = ev.prop("DURATION")
    {
        write_prop(&mut out, p);
    }
    for name in ["ORGANIZER", "SUMMARY"] {
        if let Some(p) = ev.prop(name) {
            write_prop(&mut out, p);
        }
    }
    write_prop(&mut out, &attendee);
    push_line(&mut out, "END:VEVENT");
    push_line(&mut out, "END:VCALENDAR");
    Ok(out)
}

/// Generates a new VEVENT invite (METHOD:REQUEST) — used when the user creates an event from a mail.
///
/// Timed events are written in UTC. For all-day events `start`/`end` may be either midnight UTC
/// (the convention used by [`parse_invite`]) or local midnight; `end` is exclusive, and an end that
/// is not at midnight (e.g. 23:59 of the last day) is treated as inclusive.
#[allow(clippy::too_many_arguments)]
pub fn build_request(
    uid: &str,
    summary: &str,
    start: i64,
    end: i64,
    all_day: bool,
    location: Option<&str>,
    description: Option<&str>,
    organizer: &EmailAddress,
    attendees: &[EmailAddress],
) -> String {
    let mut out = String::new();
    push_line(&mut out, "BEGIN:VCALENDAR");
    push_line(&mut out, &format!("PRODID:{PRODID}"));
    push_line(&mut out, "VERSION:2.0");
    push_line(&mut out, "CALSCALE:GREGORIAN");
    push_line(&mut out, "METHOD:REQUEST");
    push_line(&mut out, "BEGIN:VEVENT");
    write_prop(&mut out, &Prop::new("UID", escape_text(uid.trim())));
    push_line(&mut out, &format!("DTSTAMP:{}", utc_stamp(Utc::now().timestamp())));
    if all_day {
        let (first, _) = calendar_date(start);
        let (last, at_midnight) = calendar_date(end);
        let mut until = if at_midnight { last } else { last.succ_opt().unwrap_or(last) };
        if until <= first {
            until = first.succ_opt().unwrap_or(first);
        }
        push_line(&mut out, &format!("DTSTART;VALUE=DATE:{}", first.format("%Y%m%d")));
        push_line(&mut out, &format!("DTEND;VALUE=DATE:{}", until.format("%Y%m%d")));
    } else {
        push_line(&mut out, &format!("DTSTART:{}", utc_stamp(start)));
        if end > start {
            push_line(&mut out, &format!("DTEND:{}", utc_stamp(end)));
        }
    }
    write_prop(&mut out, &Prop::new("SUMMARY", escape_text(summary.trim())));
    if let Some(l) = location.map(str::trim).filter(|s| !s.is_empty()) {
        write_prop(&mut out, &Prop::new("LOCATION", escape_text(l)));
    }
    if let Some(d) = description.map(str::trim).filter(|s| !s.is_empty()) {
        write_prop(&mut out, &Prop::new("DESCRIPTION", escape_text(d)));
    }
    let organizer_email = strip_mailto(&organizer.email);
    write_prop(&mut out, &address_prop("ORGANIZER", organizer.name.as_deref(), organizer_email));

    let mut seen: Vec<String> = Vec::new();
    for a in attendees {
        let email = strip_mailto(&a.email);
        if email.is_empty() || seen.iter().any(|s| s.eq_ignore_ascii_case(email)) {
            continue;
        }
        seen.push(email.to_string());
        let mut p = address_prop("ATTENDEE", a.name.as_deref(), email);
        p.params.push(Param::new("CUTYPE", "INDIVIDUAL"));
        p.params.push(Param::new("ROLE", "REQ-PARTICIPANT"));
        if email.eq_ignore_ascii_case(organizer_email) {
            p.params.push(Param::new("PARTSTAT", "ACCEPTED"));
        } else {
            p.params.push(Param::new("PARTSTAT", "NEEDS-ACTION"));
            p.params.push(Param::new("RSVP", "TRUE"));
        }
        write_prop(&mut out, &p);
    }
    push_line(&mut out, "SEQUENCE:0");
    push_line(&mut out, "STATUS:CONFIRMED");
    push_line(&mut out, if all_day { "TRANSP:TRANSPARENT" } else { "TRANSP:OPAQUE" });
    push_line(&mut out, "END:VEVENT");
    push_line(&mut out, "END:VCALENDAR");
    out
}

// ---------------------------------------------------------------------------
// Content lines and components
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct Param {
    /// Upper-case parameter name.
    name: String,
    /// Decoded values (quotes removed, RFC 6868 caret escapes resolved).
    values: Vec<String>,
}

impl Param {
    fn new(name: &str, value: &str) -> Self {
        Param { name: name.to_ascii_uppercase(), values: vec![value.to_string()] }
    }
}

#[derive(Debug, Clone)]
struct Prop {
    /// Upper-case property name.
    name: String,
    params: Vec<Param>,
    /// Raw (still escaped) value.
    value: String,
}

impl Prop {
    fn new(name: &str, value: impl Into<String>) -> Self {
        Prop { name: name.to_ascii_uppercase(), params: Vec::new(), value: value.into() }
    }

    fn param(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|p| p.name.eq_ignore_ascii_case(name)).and_then(|p| p.values.first()).map(String::as_str)
    }

    fn text(&self) -> String {
        unescape_text(&self.value)
    }
}

#[derive(Debug, Clone, Default)]
struct Component {
    name: String,
    props: Vec<Prop>,
    children: Vec<Component>,
}

impl Component {
    fn prop(&self, name: &str) -> Option<&Prop> {
        self.props.iter().find(|p| p.name == name)
    }

    fn props_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a Prop> + 'a {
        self.props.iter().filter(move |p| p.name == name)
    }

    /// Depth-first search for the first descendant component with this name.
    fn find(&self, name: &str) -> Option<&Component> {
        self.children.iter().find_map(|c| if c.name == name { Some(c) } else { c.find(name) })
    }

    fn descendants<'a>(&'a self, name: &str) -> Vec<&'a Component> {
        let mut out = Vec::new();
        fn walk<'a>(c: &'a Component, name: &str, out: &mut Vec<&'a Component>) {
            for ch in &c.children {
                if ch.name == name {
                    out.push(ch);
                }
                walk(ch, name, out);
            }
        }
        walk(self, name, &mut out);
        out
    }
}

/// Unfolds content lines (CRLF or bare LF followed by a space or tab).
fn unfold(text: &str) -> Vec<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut lines: Vec<String> = Vec::new();
    for raw in text.split('\n') {
        let line = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = line.strip_prefix([' ', '\t'])
            && let Some(last) = lines.last_mut()
        {
            last.push_str(rest);
            continue;
        }
        if !line.trim().is_empty() {
            lines.push(line.to_string());
        }
    }
    lines
}

/// Parses `NAME *(;PARAM=VALUE[,VALUE]) : VALUE`, honouring quoted parameter values.
fn parse_line(line: &str) -> Option<Prop> {
    let name_end = line.find([';', ':'])?;
    let name = line[..name_end].trim().to_ascii_uppercase();
    if name.is_empty() {
        return None;
    }
    let mut pos = name_end;
    let mut params = Vec::new();
    while line[pos..].starts_with(';') {
        pos += 1;
        let rest = &line[pos..];
        let end = rest.find(['=', ';', ':']).unwrap_or(rest.len());
        let pname = rest[..end].trim().to_ascii_uppercase();
        pos += end;
        let mut values = Vec::new();
        if line[pos..].starts_with('=') {
            pos += 1;
            loop {
                let rest = &line[pos..];
                if let Some(quoted) = rest.strip_prefix('"') {
                    let close = quoted.find('"')?;
                    values.push(decode_caret(&quoted[..close]));
                    pos += close + 2;
                    // Ignore anything between the closing quote and the next delimiter.
                    let rest = &line[pos..];
                    pos += rest.find([',', ';', ':']).unwrap_or(rest.len());
                } else {
                    let end = rest.find([',', ';', ':']).unwrap_or(rest.len());
                    values.push(decode_caret(rest[..end].trim()));
                    pos += end;
                }
                if line[pos..].starts_with(',') {
                    pos += 1;
                } else {
                    break;
                }
            }
        }
        if !pname.is_empty() {
            params.push(Param { name: pname, values });
        }
    }
    let value = line[pos..].strip_prefix(':')?;
    Some(Prop { name, params, value: value.to_string() })
}

fn parse_tree(text: &str) -> Component {
    let mut stack = vec![Component::default()];
    for line in unfold(text) {
        let Some(prop) = parse_line(&line) else { continue };
        match prop.name.as_str() {
            "BEGIN" => stack.push(Component { name: prop.value.trim().to_ascii_uppercase(), ..Default::default() }),
            "END" => {
                let name = prop.value.trim().to_ascii_uppercase();
                // Tolerate missing END lines of nested components; ignore stray ENDs.
                if stack.iter().skip(1).any(|c| c.name == name) {
                    while stack.len() > 1 {
                        let done = stack.last().is_some_and(|c| c.name == name);
                        close_top(&mut stack);
                        if done {
                            break;
                        }
                    }
                }
            }
            _ => {
                if let Some(top) = stack.last_mut() {
                    top.props.push(prop);
                }
            }
        }
    }
    while stack.len() > 1 {
        close_top(&mut stack);
    }
    stack.pop().unwrap_or_default()
}

fn close_top(stack: &mut Vec<Component>) {
    if let Some(c) = stack.pop()
        && let Some(parent) = stack.last_mut()
    {
        parent.children.push(c);
    }
}

/// RFC 6868 parameter value decoding (`^n`, `^'`, `^^`).
fn decode_caret(s: &str) -> String {
    if !s.contains('^') {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '^' {
            match it.peek() {
                Some('n') => out.push('\n'),
                Some('\'') => out.push('"'),
                Some('^') => out.push('^'),
                _ => {
                    out.push('^');
                    continue;
                }
            }
            it.next();
        } else {
            out.push(c);
        }
    }
    out
}

fn encode_param_value(v: &str) -> String {
    let mut enc = String::with_capacity(v.len() + 2);
    for c in v.chars() {
        match c {
            '^' => enc.push_str("^^"),
            '"' => enc.push_str("^'"),
            '\n' => enc.push_str("^n"),
            '\r' => {}
            c if c.is_control() => {}
            c => enc.push(c),
        }
    }
    let needs_quotes = enc.chars().any(|c| matches!(c, ':' | ';' | ',') || c.is_whitespace() || !c.is_ascii());
    if needs_quotes { format!("\"{enc}\"") } else { enc }
}

/// TEXT value unescaping (RFC 5545 §3.3.11).
fn unescape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('n' | 'N') => out.push('\n'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// TEXT value escaping (RFC 5545 §3.3.11).
fn escape_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            ',' => out.push_str("\\,"),
            '\r' => {
                if chars.peek() != Some(&'\n') {
                    out.push_str("\\n");
                }
            }
            '\n' => out.push_str("\\n"),
            '\t' => out.push('\t'),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Appends one logical line folded at 75 octets without splitting UTF-8 sequences.
fn push_line(out: &mut String, line: &str) {
    let mut used = 0;
    for c in line.chars() {
        let len = c.len_utf8();
        if used + len > FOLD_OCTETS {
            out.push_str("\r\n ");
            used = 1;
        }
        out.push(c);
        used += len;
    }
    out.push_str("\r\n");
}

fn write_prop(out: &mut String, p: &Prop) {
    let mut line = p.name.clone();
    for param in &p.params {
        line.push(';');
        line.push_str(&param.name);
        if !param.values.is_empty() {
            line.push('=');
            let values: Vec<String> = param.values.iter().map(|v| encode_param_value(v)).collect();
            line.push_str(&values.join(","));
        }
    }
    line.push(':');
    line.push_str(&p.value);
    push_line(out, &line);
}

fn write_component(out: &mut String, c: &Component) {
    push_line(out, &format!("BEGIN:{}", c.name));
    for p in &c.props {
        write_prop(out, p);
    }
    for ch in &c.children {
        write_component(out, ch);
    }
    push_line(out, &format!("END:{}", c.name));
}

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

fn strip_mailto(v: &str) -> &str {
    let v = v.trim();
    match v.get(..7) {
        Some(prefix) if prefix.eq_ignore_ascii_case("mailto:") => v[7..].trim(),
        _ => v,
    }
}

fn address(p: &Prop) -> Option<EmailAddress> {
    let mut email = strip_mailto(&p.value);
    if !email.contains('@')
        && let Some(e) = p.param("EMAIL").map(strip_mailto).filter(|e| e.contains('@'))
    {
        email = e;
    }
    if email.is_empty() {
        return None;
    }
    let name = p.param("CN").map(|n| n.trim().trim_matches('"').trim());
    Some(EmailAddress::new(name, email))
}

fn address_prop(name: &str, cn: Option<&str>, email: &str) -> Prop {
    let mut p = Prop::new(name, format!("mailto:{email}"));
    if let Some(cn) = cn.map(str::trim).filter(|n| !n.is_empty()) {
        p.params.push(Param::new("CN", cn));
    }
    p
}

// ---------------------------------------------------------------------------
// Date-times and time zones
// ---------------------------------------------------------------------------

fn utc_stamp(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default().format("%Y%m%dT%H%M%SZ").to_string()
}

/// Calendar date for an all-day timestamp, and whether it sits exactly on midnight.
fn calendar_date(ts: i64) -> (NaiveDate, bool) {
    if ts.rem_euclid(DAY) == 0 {
        let d = chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default().date_naive();
        return (d, true);
    }
    match chrono::Local.timestamp_opt(ts, 0).single() {
        Some(local) => (local.date_naive(), local.time().num_seconds_from_midnight() == 0),
        None => (chrono::DateTime::from_timestamp(ts, 0).unwrap_or_default().date_naive(), false),
    }
}

/// A resolved DTSTART/DTEND value.
struct When {
    ts: i64,
    all_day: bool,
    naive: NaiveDateTime,
    zone: Zone,
}

impl When {
    /// Adds a DURATION: days/weeks are nominal (wall clock), the rest exact.
    fn add(&self, (days, secs): (i64, i64)) -> Option<i64> {
        if self.all_day || days == 0 {
            return Some(self.ts + days * DAY + secs);
        }
        let shifted = self.naive.checked_add_signed(TimeDelta::try_days(days)?)?;
        Some(self.zone.to_utc(shifted)? + secs)
    }
}

enum Zone {
    Utc,
    Tz(Tz),
    Fixed(i32),
    Rules(Vec<Observance>),
    Local,
}

impl Zone {
    fn to_utc(&self, naive: NaiveDateTime) -> Option<i64> {
        let wall = naive.and_utc().timestamp();
        match self {
            Zone::Utc => Some(wall),
            Zone::Tz(tz) => resolve_local(tz, naive),
            Zone::Fixed(offset) => Some(wall - i64::from(*offset)),
            Zone::Rules(obs) => Some(wall - i64::from(offset_at(obs, naive))),
            Zone::Local => resolve_local(&chrono::Local, naive),
        }
    }
}

/// Local → UTC. Ambiguous times take the earlier instant; times in a DST gap move forward an hour.
fn resolve_local<T: TimeZone>(tz: &T, naive: NaiveDateTime) -> Option<i64> {
    tz.from_local_datetime(&naive)
        .earliest()
        .or_else(|| tz.from_local_datetime(&(naive + TimeDelta::hours(1))).earliest())
        .map(|d| d.timestamp())
}

struct Ctx<'a> {
    cal: &'a Component,
}

impl Ctx<'_> {
    fn eval_dt(&self, p: &Prop) -> Option<When> {
        // A list value (RDATE style) — take the first entry.
        let value = p.value.split(',').next()?.trim();
        let (naive, utc, date_only) = parse_naive(value)?;
        let is_date = date_only || p.param("VALUE").is_some_and(|v| v.trim().eq_ignore_ascii_case("DATE"));
        if is_date {
            let midnight = naive.date().and_hms_opt(0, 0, 0)?;
            return Some(When { ts: midnight.and_utc().timestamp(), all_day: true, naive: midnight, zone: Zone::Utc });
        }
        let zone = if utc {
            Zone::Utc
        } else if let Some(tzid) = p.param("TZID").filter(|t| !t.trim().is_empty()) {
            self.zone_for(tzid)
        } else {
            self.floating_zone()
        };
        let ts = zone.to_utc(naive)?;
        Some(When { ts, all_day: false, naive, zone })
    }

    fn zone_for(&self, tzid: &str) -> Zone {
        if let Some(tz) = lookup_tz(tzid) {
            return Zone::Tz(tz);
        }
        let id = norm_tzid(tzid);
        let vtz = self
            .cal
            .descendants("VTIMEZONE")
            .into_iter()
            .find(|c| c.prop("TZID").is_some_and(|p| norm_tzid(&p.value) == id));
        if let Some(zone) = vtz.and_then(zone_from_vtimezone) {
            return zone;
        }
        if let Some(offset) = offset_in_name(tzid) {
            return Zone::Fixed(offset);
        }
        Zone::Utc
    }

    /// Floating times use the calendar's X-WR-TIMEZONE, else the user's local zone.
    fn floating_zone(&self) -> Zone {
        self.cal
            .prop("X-WR-TIMEZONE")
            .and_then(|p| lookup_tz(&p.value))
            .map(Zone::Tz)
            .unwrap_or(Zone::Local)
    }
}

/// Parses `YYYYMMDD`, `YYYYMMDDTHHMMSS[Z]` (also tolerating `-`/`:` separators and missing seconds).
/// Returns (naive, is_utc, is_date_only).
fn parse_naive(v: &str) -> Option<(NaiveDateTime, bool, bool)> {
    let compact: String = v.trim().chars().filter(|c| !matches!(c, '-' | ':')).collect();
    if compact.len() == 8 && compact.bytes().all(|b| b.is_ascii_digit()) {
        let d = NaiveDate::parse_from_str(&compact, "%Y%m%d").ok()?;
        return Some((d.and_hms_opt(0, 0, 0)?, false, true));
    }
    let (body, utc) = match compact.strip_suffix(['Z', 'z']) {
        Some(b) => (b, true),
        None => (compact.as_str(), false),
    };
    let body = body.split('.').next()?; // drop fractional seconds
    let naive = NaiveDateTime::parse_from_str(body, "%Y%m%dT%H%M%S")
        .or_else(|_| NaiveDateTime::parse_from_str(body, "%Y%m%dT%H%M"))
        .ok()?;
    Some((naive, utc, false))
}

/// Parses an RFC 5545 DURATION (`PT1H30M`, `P1D`, `P2W`, `-PT15M`) into (nominal days, exact seconds).
fn parse_duration(v: &str) -> Option<(i64, i64)> {
    let v = v.trim().to_ascii_uppercase();
    let (sign, rest) = match v.as_bytes().first()? {
        b'-' => (-1, &v[1..]),
        b'+' => (1, &v[1..]),
        _ => (1, v.as_str()),
    };
    let rest = rest.strip_prefix('P')?;
    let (mut days, mut secs) = (0i64, 0i64);
    let mut in_time = false;
    let mut num = String::new();
    let mut any = false;
    for c in rest.chars() {
        match c {
            '0'..='9' => num.push(c),
            'T' if num.is_empty() => in_time = true,
            'W' | 'D' | 'H' | 'M' | 'S' => {
                let n: i64 = num.parse().ok()?;
                num.clear();
                any = true;
                match (c, in_time) {
                    ('W', false) => days = days.checked_add(n.checked_mul(7)?)?,
                    ('D', false) => days = days.checked_add(n)?,
                    ('H', true) => secs = secs.checked_add(n.checked_mul(3600)?)?,
                    ('M', true) => secs = secs.checked_add(n.checked_mul(60)?)?,
                    ('S', true) => secs = secs.checked_add(n)?,
                    _ => return None,
                }
            }
            _ => return None,
        }
    }
    if !any || !num.is_empty() {
        return None;
    }
    Some((sign * days, sign * secs))
}

fn norm_tzid(id: &str) -> String {
    id.trim().trim_matches('"').trim().to_ascii_lowercase()
}

/// IANA name, Windows zone name, or an IANA name embedded in a path-like TZID
/// (`/mozilla.org/20050126_1/Asia/Shanghai`).
fn lookup_tz(tzid: &str) -> Option<Tz> {
    let id = tzid.trim().trim_matches('"').trim();
    let id = id.trim_start_matches('/');
    if id.is_empty() {
        return None;
    }
    if let Ok(tz) = id.parse::<Tz>() {
        return Some(tz);
    }
    if let Some(iana) = windows_to_iana(id) {
        return iana.parse().ok();
    }
    if let Some(tz) = chrono_tz::TZ_VARIANTS.iter().find(|tz| tz.name().eq_ignore_ascii_case(id)) {
        return Some(*tz);
    }
    let parts: Vec<&str> = id.split('/').filter(|s| !s.is_empty()).collect();
    for k in [3, 2] {
        if parts.len() > k
            && let Ok(tz) = parts[parts.len() - k..].join("/").parse::<Tz>()
        {
            return Some(tz);
        }
    }
    None
}

fn windows_to_iana(name: &str) -> Option<&'static str> {
    let name = name.trim();
    WINDOWS_ZONES.iter().find(|(w, _)| w.eq_ignore_ascii_case(name)).map(|(_, iana)| *iana)
}

/// Fixed offset from display-style names such as `(UTC+08:00) Beijing, Chongqing` or `GMT-0500`.
fn offset_in_name(name: &str) -> Option<i32> {
    let upper = name.to_ascii_uppercase();
    let idx = upper.find("UTC").or_else(|| upper.find("GMT"))?;
    let rest = upper[idx + 3..].trim_start();
    let sign = match rest.chars().next() {
        Some('+') => 1,
        Some('-') => -1,
        _ => return Some(0),
    };
    let digits: String = rest[1..].chars().take_while(|c| c.is_ascii_digit() || *c == ':').filter(|c| *c != ':').collect();
    let (h, m) = match digits.len() {
        1 | 2 => (digits.parse::<i32>().ok()?, 0),
        3 | 4 => {
            let split = digits.len() - 2;
            (digits[..split].parse::<i32>().ok()?, digits[split..].parse::<i32>().ok()?)
        }
        _ => return None,
    };
    (h <= 14 && m < 60).then_some(sign * (h * 3600 + m * 60))
}

/// UTC offset value (`+0800`, `-0430`, `+053000`) in seconds.
fn parse_offset(v: &str) -> Option<i32> {
    let v = v.trim();
    let sign = match v.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let d = &v[1..];
    if !(d.len() == 4 || d.len() == 6) || !d.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let h: i32 = d[0..2].parse().ok()?;
    let m: i32 = d[2..4].parse().ok()?;
    let s: i32 = if d.len() == 6 { d[4..6].parse().ok()? } else { 0 };
    Some(sign * (h * 3600 + m * 60 + s))
}

/// One STANDARD / DAYLIGHT sub-component of a VTIMEZONE.
struct Observance {
    from: i32,
    to: i32,
    start: NaiveDateTime,
    rule: Option<YearlyRule>,
}

#[derive(Default)]
struct YearlyRule {
    month: Option<u32>,
    ordinal: i32,
    weekday: Option<Weekday>,
    monthday: Option<u32>,
    until: Option<NaiveDateTime>,
}

impl Observance {
    /// Local date-time at which this observance begins in `year`.
    fn onset(&self, year: i32) -> Option<NaiveDateTime> {
        let Some(rule) = &self.rule else {
            return (year == self.start.year()).then_some(self.start);
        };
        if year < self.start.year() {
            return None;
        }
        let month = rule.month.unwrap_or(self.start.month());
        let date = match rule.weekday {
            Some(wd) => nth_weekday(year, month, rule.ordinal, wd, rule.monthday)?,
            None => NaiveDate::from_ymd_opt(year, month, rule.monthday.unwrap_or(self.start.day()))?,
        };
        let at = date.and_time(self.start.time());
        if rule.until.is_some_and(|u| at > u) {
            return None;
        }
        Some(at)
    }
}

fn nth_weekday(year: i32, month: u32, ordinal: i32, wd: Weekday, from_day: Option<u32>) -> Option<NaiveDate> {
    let wd_idx = i64::from(wd.num_days_from_monday());
    if ordinal >= 0 {
        let first = NaiveDate::from_ymd_opt(year, month, from_day.unwrap_or(1))?;
        let delta = (7 + wd_idx - i64::from(first.weekday().num_days_from_monday())) % 7;
        let mut d = first + TimeDelta::days(delta + 7 * i64::from(ordinal.max(1) - 1));
        while d.month() != month {
            d -= TimeDelta::days(7);
        }
        Some(d)
    } else {
        let next = if month == 12 { NaiveDate::from_ymd_opt(year + 1, 1, 1) } else { NaiveDate::from_ymd_opt(year, month + 1, 1) };
        let last = next?.pred_opt()?;
        let delta = (7 + i64::from(last.weekday().num_days_from_monday()) - wd_idx) % 7;
        let mut d = last - TimeDelta::days(delta + 7 * i64::from(-ordinal - 1));
        while d.month() != month {
            d += TimeDelta::days(7);
        }
        Some(d)
    }
}

fn parse_weekday(s: &str) -> Option<Weekday> {
    Some(match s.to_ascii_uppercase().as_str() {
        "MO" => Weekday::Mon,
        "TU" => Weekday::Tue,
        "WE" => Weekday::Wed,
        "TH" => Weekday::Thu,
        "FR" => Weekday::Fri,
        "SA" => Weekday::Sat,
        "SU" => Weekday::Sun,
        _ => return None,
    })
}

/// Parses a yearly RRULE of a VTIMEZONE observance; other frequencies are unsupported.
fn parse_rrule(v: &str) -> Option<YearlyRule> {
    let mut rule = YearlyRule::default();
    for part in v.split(';') {
        let Some((key, val)) = part.split_once('=') else { continue };
        let first = val.split(',').next().unwrap_or("").trim();
        match key.trim().to_ascii_uppercase().as_str() {
            "FREQ" if !val.trim().eq_ignore_ascii_case("YEARLY") => return None,
            "BYMONTH" => rule.month = first.parse().ok().filter(|m| (1..=12).contains(m)),
            "BYDAY" if first.len() >= 2 => {
                let (num, day) = first.split_at(first.len() - 2);
                rule.weekday = parse_weekday(day);
                rule.ordinal = num.trim_start_matches('+').parse().unwrap_or(0);
            }
            "BYMONTHDAY" => {
                rule.monthday = val.split(',').filter_map(|d| d.trim().parse::<u32>().ok()).filter(|d| (1..=31).contains(d)).min();
            }
            "UNTIL" => rule.until = parse_naive(val).map(|(n, _, _)| n),
            _ => {}
        }
    }
    Some(rule)
}

fn zone_from_vtimezone(vtz: &Component) -> Option<Zone> {
    let mut obs = Vec::new();
    let mut standard_to = None;
    for c in vtz.children.iter().filter(|c| c.name == "STANDARD" || c.name == "DAYLIGHT") {
        let Some(to) = c.prop("TZOFFSETTO").and_then(|p| parse_offset(&p.value)) else { continue };
        if c.name == "STANDARD" && standard_to.is_none() {
            standard_to = Some(to);
        }
        let from = c.prop("TZOFFSETFROM").and_then(|p| parse_offset(&p.value)).unwrap_or(to);
        let start = c
            .prop("DTSTART")
            .and_then(|p| parse_naive(&p.value))
            .map(|(n, _, _)| n)
            .or_else(|| NaiveDate::from_ymd_opt(1601, 1, 1)?.and_hms_opt(0, 0, 0))?;
        let rule = c.prop("RRULE").and_then(|p| parse_rrule(&p.value));
        obs.push(Observance { from, to, start, rule });
    }
    if obs.is_empty() {
        return None;
    }
    if obs.iter().all(|o| o.to == obs[0].to && o.from == obs[0].to) {
        return Some(Zone::Fixed(obs[0].to));
    }
    if obs.iter().all(|o| o.rule.is_none()) && obs.len() == 1 {
        return Some(Zone::Fixed(standard_to.unwrap_or(obs[0].to)));
    }
    Some(Zone::Rules(obs))
}

/// UTC offset in effect at local time `t` according to the observances: the one whose most
/// recent onset is at or before `t` wins.
fn offset_at(obs: &[Observance], t: NaiveDateTime) -> i32 {
    let mut best: Option<(NaiveDateTime, i32)> = None;
    for o in obs {
        let candidates = if o.rule.is_some() {
            [o.onset(t.year()), o.onset(t.year() - 1)]
        } else {
            [Some(o.start), None]
        };
        for c in candidates.into_iter().flatten() {
            if c <= t && best.is_none_or(|(b, _)| c > b) {
                best = Some((c, o.to));
            }
        }
    }
    match best {
        Some((_, to)) => to,
        None => obs.iter().min_by_key(|o| o.start).map(|o| o.from).unwrap_or(0),
    }
}

/// Windows time zone names (as emitted by Outlook / Exchange) → IANA, after CLDR windowsZones.xml.
const WINDOWS_ZONES: &[(&str, &str)] = &[
    ("Dateline Standard Time", "Etc/GMT+12"),
    ("UTC-11", "Etc/GMT+11"),
    ("Aleutian Standard Time", "America/Adak"),
    ("Hawaiian Standard Time", "Pacific/Honolulu"),
    ("Marquesas Standard Time", "Pacific/Marquesas"),
    ("Alaskan Standard Time", "America/Anchorage"),
    ("UTC-09", "Etc/GMT+9"),
    ("Pacific Standard Time (Mexico)", "America/Tijuana"),
    ("UTC-08", "Etc/GMT+8"),
    ("Pacific Standard Time", "America/Los_Angeles"),
    ("US Mountain Standard Time", "America/Phoenix"),
    ("Mountain Standard Time (Mexico)", "America/Mazatlan"),
    ("Mountain Standard Time", "America/Denver"),
    ("Yukon Standard Time", "America/Whitehorse"),
    ("Central America Standard Time", "America/Guatemala"),
    ("Central Standard Time", "America/Chicago"),
    ("Easter Island Standard Time", "Pacific/Easter"),
    ("Central Standard Time (Mexico)", "America/Mexico_City"),
    ("Canada Central Standard Time", "America/Regina"),
    ("SA Pacific Standard Time", "America/Bogota"),
    ("Eastern Standard Time (Mexico)", "America/Cancun"),
    ("Eastern Standard Time", "America/New_York"),
    ("Haiti Standard Time", "America/Port-au-Prince"),
    ("Cuba Standard Time", "America/Havana"),
    ("US Eastern Standard Time", "America/Indiana/Indianapolis"),
    ("Turks And Caicos Standard Time", "America/Grand_Turk"),
    ("Paraguay Standard Time", "America/Asuncion"),
    ("Atlantic Standard Time", "America/Halifax"),
    ("Venezuela Standard Time", "America/Caracas"),
    ("Central Brazilian Standard Time", "America/Cuiaba"),
    ("SA Western Standard Time", "America/La_Paz"),
    ("Pacific SA Standard Time", "America/Santiago"),
    ("Newfoundland Standard Time", "America/St_Johns"),
    ("Tocantins Standard Time", "America/Araguaina"),
    ("E. South America Standard Time", "America/Sao_Paulo"),
    ("SA Eastern Standard Time", "America/Cayenne"),
    ("Argentina Standard Time", "America/Argentina/Buenos_Aires"),
    ("Greenland Standard Time", "America/Nuuk"),
    ("Montevideo Standard Time", "America/Montevideo"),
    ("Magallanes Standard Time", "America/Punta_Arenas"),
    ("Saint Pierre Standard Time", "America/Miquelon"),
    ("Bahia Standard Time", "America/Bahia"),
    ("UTC-02", "Etc/GMT+2"),
    ("Mid-Atlantic Standard Time", "Etc/GMT+2"),
    ("Azores Standard Time", "Atlantic/Azores"),
    ("Cape Verde Standard Time", "Atlantic/Cape_Verde"),
    ("UTC", "Etc/UTC"),
    ("Coordinated Universal Time", "Etc/UTC"),
    ("GMT Standard Time", "Europe/London"),
    ("Greenwich Standard Time", "Atlantic/Reykjavik"),
    ("Sao Tome Standard Time", "Africa/Sao_Tome"),
    ("Morocco Standard Time", "Africa/Casablanca"),
    ("W. Europe Standard Time", "Europe/Berlin"),
    ("Central Europe Standard Time", "Europe/Budapest"),
    ("Romance Standard Time", "Europe/Paris"),
    ("Central European Standard Time", "Europe/Warsaw"),
    ("W. Central Africa Standard Time", "Africa/Lagos"),
    ("Jordan Standard Time", "Asia/Amman"),
    ("GTB Standard Time", "Europe/Bucharest"),
    ("Middle East Standard Time", "Asia/Beirut"),
    ("Egypt Standard Time", "Africa/Cairo"),
    ("E. Europe Standard Time", "Europe/Chisinau"),
    ("Syria Standard Time", "Asia/Damascus"),
    ("West Bank Standard Time", "Asia/Hebron"),
    ("South Africa Standard Time", "Africa/Johannesburg"),
    ("FLE Standard Time", "Europe/Kyiv"),
    ("Israel Standard Time", "Asia/Jerusalem"),
    ("South Sudan Standard Time", "Africa/Juba"),
    ("Kaliningrad Standard Time", "Europe/Kaliningrad"),
    ("Sudan Standard Time", "Africa/Khartoum"),
    ("Libya Standard Time", "Africa/Tripoli"),
    ("Namibia Standard Time", "Africa/Windhoek"),
    ("Arabic Standard Time", "Asia/Baghdad"),
    ("Turkey Standard Time", "Europe/Istanbul"),
    ("Arab Standard Time", "Asia/Riyadh"),
    ("Belarus Standard Time", "Europe/Minsk"),
    ("Russian Standard Time", "Europe/Moscow"),
    ("E. Africa Standard Time", "Africa/Nairobi"),
    ("Volgograd Standard Time", "Europe/Volgograd"),
    ("Iran Standard Time", "Asia/Tehran"),
    ("Arabian Standard Time", "Asia/Dubai"),
    ("Astrakhan Standard Time", "Europe/Astrakhan"),
    ("Azerbaijan Standard Time", "Asia/Baku"),
    ("Russia Time Zone 3", "Europe/Samara"),
    ("Mauritius Standard Time", "Indian/Mauritius"),
    ("Saratov Standard Time", "Europe/Saratov"),
    ("Georgian Standard Time", "Asia/Tbilisi"),
    ("Caucasus Standard Time", "Asia/Yerevan"),
    ("Afghanistan Standard Time", "Asia/Kabul"),
    ("West Asia Standard Time", "Asia/Tashkent"),
    ("Ekaterinburg Standard Time", "Asia/Yekaterinburg"),
    ("Pakistan Standard Time", "Asia/Karachi"),
    ("Qyzylorda Standard Time", "Asia/Qyzylorda"),
    ("India Standard Time", "Asia/Kolkata"),
    ("Sri Lanka Standard Time", "Asia/Colombo"),
    ("Nepal Standard Time", "Asia/Kathmandu"),
    ("Central Asia Standard Time", "Asia/Almaty"),
    ("Bangladesh Standard Time", "Asia/Dhaka"),
    ("Omsk Standard Time", "Asia/Omsk"),
    ("Myanmar Standard Time", "Asia/Yangon"),
    ("SE Asia Standard Time", "Asia/Bangkok"),
    ("Altai Standard Time", "Asia/Barnaul"),
    ("W. Mongolia Standard Time", "Asia/Hovd"),
    ("North Asia Standard Time", "Asia/Krasnoyarsk"),
    ("N. Central Asia Standard Time", "Asia/Novosibirsk"),
    ("Tomsk Standard Time", "Asia/Tomsk"),
    ("China Standard Time", "Asia/Shanghai"),
    ("North Asia East Standard Time", "Asia/Irkutsk"),
    ("Singapore Standard Time", "Asia/Singapore"),
    ("Malay Peninsula Standard Time", "Asia/Kuala_Lumpur"),
    ("W. Australia Standard Time", "Australia/Perth"),
    ("Taipei Standard Time", "Asia/Taipei"),
    ("Ulaanbaatar Standard Time", "Asia/Ulaanbaatar"),
    ("Aus Central W. Standard Time", "Australia/Eucla"),
    ("Transbaikal Standard Time", "Asia/Chita"),
    ("Tokyo Standard Time", "Asia/Tokyo"),
    ("North Korea Standard Time", "Asia/Pyongyang"),
    ("Korea Standard Time", "Asia/Seoul"),
    ("Yakutsk Standard Time", "Asia/Yakutsk"),
    ("Cen. Australia Standard Time", "Australia/Adelaide"),
    ("AUS Central Standard Time", "Australia/Darwin"),
    ("E. Australia Standard Time", "Australia/Brisbane"),
    ("AUS Eastern Standard Time", "Australia/Sydney"),
    ("West Pacific Standard Time", "Pacific/Port_Moresby"),
    ("Tasmania Standard Time", "Australia/Hobart"),
    ("Vladivostok Standard Time", "Asia/Vladivostok"),
    ("Lord Howe Standard Time", "Australia/Lord_Howe"),
    ("Bougainville Standard Time", "Pacific/Bougainville"),
    ("Russia Time Zone 10", "Asia/Srednekolymsk"),
    ("Magadan Standard Time", "Asia/Magadan"),
    ("Norfolk Standard Time", "Pacific/Norfolk"),
    ("Sakhalin Standard Time", "Asia/Sakhalin"),
    ("Central Pacific Standard Time", "Pacific/Guadalcanal"),
    ("Russia Time Zone 11", "Asia/Kamchatka"),
    ("New Zealand Standard Time", "Pacific/Auckland"),
    ("UTC+12", "Etc/GMT-12"),
    ("Fiji Standard Time", "Pacific/Fiji"),
    ("Chatham Islands Standard Time", "Pacific/Chatham"),
    ("UTC+13", "Etc/GMT-13"),
    ("Tonga Standard Time", "Pacific/Tongatapu"),
    ("Samoa Standard Time", "Pacific/Apia"),
    ("Line Islands Standard Time", "Pacific/Kiritimati"),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn crlf(s: &str) -> String {
        s.replace('\n', "\r\n")
    }

    fn utc(y: i32, mo: u32, d: u32, h: u32, mi: u32) -> i64 {
        Utc.with_ymd_and_hms(y, mo, d, h, mi, 0).unwrap().timestamp()
    }

    fn own(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn assert_folded(ics: &str) {
        assert!(ics.ends_with("\r\n"));
        for line in ics.split("\r\n") {
            assert!(line.len() <= FOLD_OCTETS, "line longer than 75 octets: {line:?}");
            assert!(!line.contains('\n') && !line.contains('\r'));
        }
    }

    const OUTLOOK: &str = "BEGIN:VCALENDAR
METHOD:REQUEST
PRODID:Microsoft Exchange Server 2010
VERSION:2.0
BEGIN:VTIMEZONE
TZID:China Standard Time
BEGIN:STANDARD
DTSTART:16010101T000000
TZOFFSETFROM:+0800
TZOFFSETTO:+0800
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:16010101T000000
TZOFFSETFROM:+0800
TZOFFSETTO:+0800
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VEVENT
ORGANIZER;CN=李四:mailto:lisi@example.com
ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=TRUE;CN=\"张三\":MAILTO:Zh
 angSan@Example.com
ATTENDEE;ROLE=OPT-PARTICIPANT;PARTSTAT=TENTATIVE;RSVP=TRUE;CN=王五:mailto:wangwu@
 example.com
DESCRIPTION;LANGUAGE=zh-CN:各位好\\,\\n\\n本周五讨论 Q4 规划\\; 请准时参加。\\n路径: C:\\\\share\\n
UID:040000008200E00074C5B7101A82E00800000000A0B1C2D3E4F5A6B70000000000000000100
 000001234567890ABCDEF
SUMMARY;LANGUAGE=zh-CN:Q4 规划评审
DTSTART;TZID=China Standard Time:20261023T090000
DTEND;TZID=China Standard Time:20261023T103000
CLASS:PUBLIC
PRIORITY:5
DTSTAMP:20261020T020000Z
TRANSP:OPAQUE
STATUS:CONFIRMED
SEQUENCE:2
LOCATION;LANGUAGE=zh-CN:3楼 会议室 A
X-MICROSOFT-CDO-APPT-SEQUENCE:2
BEGIN:VALARM
DESCRIPTION:REMINDER
TRIGGER;RELATED=START:-PT15M
ACTION:DISPLAY
END:VALARM
END:VEVENT
END:VCALENDAR
";

    const GOOGLE: &str = "BEGIN:VCALENDAR
PRODID:-//Google Inc//Google Calendar 70.9054//EN
VERSION:2.0
CALSCALE:GREGORIAN
METHOD:REQUEST
BEGIN:VEVENT
DTSTART:20261023T090000Z
DTEND:20261023T100000Z
DTSTAMP:20261020T081530Z
ORGANIZER;CN=Alice Chen:mailto:alice@gmail.com
UID:7kukuqrfedlm2f9t5vl6aaa@google.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE
 ;CN=Alice Chen;X-NUM-GUESTS=0:mailto:alice@gmail.com
ATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=
 TRUE;CN=\"Bob: Team; Lead, Ops\";X-NUM-GUESTS=0:mailto:bob@example.org
X-GOOGLE-CONFERENCE:https://meet.google.com/abc-defg-hij
CREATED:20261020T081529Z
DESCRIPTION:-::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~
 :~:~::~:~::-\\nJoin with Google Meet: https://meet.google.com/abc-defg-hij
LAST-MODIFIED:20261020T081529Z
LOCATION:
SEQUENCE:0
STATUS:CONFIRMED
SUMMARY:Weekly sync
TRANSP:OPAQUE
END:VEVENT
END:VCALENDAR
";

    #[test]
    fn outlook_invite_with_windows_tzid_and_chinese_cn() {
        let ics = crlf(OUTLOOK);
        let inv = parse_invite(&ics, &own(&["zhangsan@example.com"])).expect("invite");
        assert_eq!(inv.method, "REQUEST");
        assert_eq!(
            inv.uid,
            "040000008200E00074C5B7101A82E00800000000A0B1C2D3E4F5A6B70000000000000000100000001234567890ABCDEF"
        );
        assert_eq!(inv.summary, "Q4 规划评审");
        assert_eq!(inv.location.as_deref(), Some("3楼 会议室 A"));
        assert_eq!(inv.description.as_deref(), Some("各位好,\n\n本周五讨论 Q4 规划; 请准时参加。\n路径: C:\\share"));
        assert!(!inv.all_day);
        assert_eq!(inv.start, Some(utc(2026, 10, 23, 1, 0)));
        assert_eq!(inv.end, Some(utc(2026, 10, 23, 2, 30)));
        assert_eq!(inv.organizer, Some(EmailAddress::new(Some("李四"), "lisi@example.com")));
        assert_eq!(
            inv.attendees,
            vec![
                EmailAddress::new(Some("张三"), "ZhangSan@Example.com"),
                EmailAddress::new(Some("王五"), "wangwu@example.com"),
            ]
        );
        assert_eq!(inv.my_status.as_deref(), Some("NEEDS-ACTION"));
        assert_eq!(inv.raw, ics);

        let other = parse_invite(&ics, &own(&["wangwu@example.com"])).unwrap();
        assert_eq!(other.my_status.as_deref(), Some("TENTATIVE"));
        let none = parse_invite(&ics, &own(&["nobody@example.com"])).unwrap();
        assert_eq!(none.my_status, None);
    }

    #[test]
    fn windows_zones_follow_dst() {
        let ev = |tzid: &str, local: &str| {
            format!(
                "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nUID:x\r\nDTSTART;TZID={tzid}:{local}\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
            )
        };
        let start = |tzid: &str, local: &str| parse_invite(&ev(tzid, local), &[]).unwrap().start.unwrap();
        // 2026-10-23: US still on daylight time (ends Nov 1), Europe on summer time (ends Oct 25).
        assert_eq!(start("Pacific Standard Time", "20261023T090000"), utc(2026, 10, 23, 16, 0));
        assert_eq!(start("Pacific Standard Time", "20261201T090000"), utc(2026, 12, 1, 17, 0));
        assert_eq!(start("\"W. Europe Standard Time\"", "20261023T090000"), utc(2026, 10, 23, 7, 0));
        assert_eq!(start("W. Europe Standard Time", "20261026T090000"), utc(2026, 10, 26, 8, 0));
        assert_eq!(start("Tokyo Standard Time", "20261023T090000"), utc(2026, 10, 23, 0, 0));
        assert_eq!(start("india standard time", "20261023T090000"), utc(2026, 10, 23, 3, 30));
        assert_eq!(start("AUS Eastern Standard Time", "20261023T090000"), utc(2026, 10, 22, 22, 0));
        assert_eq!(start("Asia/Shanghai", "20261023T090000"), utc(2026, 10, 23, 1, 0));
        assert_eq!(start("/mozilla.org/20050126_1/Asia/Shanghai", "20261023T090000"), utc(2026, 10, 23, 1, 0));
        assert_eq!(start("\"(UTC+08:00) Beijing, Chongqing, Hong Kong, Urumqi\"", "20261023T090000"), utc(2026, 10, 23, 1, 0));
        // Unknown and no VTIMEZONE → UTC.
        assert_eq!(start("Mars Standard Time", "20261023T090000"), utc(2026, 10, 23, 9, 0));
    }

    #[test]
    fn required_windows_zones_are_mapped() {
        for name in [
            "China Standard Time",
            "Pacific Standard Time",
            "W. Europe Standard Time",
            "Tokyo Standard Time",
            "GMT Standard Time",
            "Eastern Standard Time",
            "Central Standard Time",
            "Mountain Standard Time",
            "Singapore Standard Time",
            "Taipei Standard Time",
            "Korea Standard Time",
            "India Standard Time",
            "AUS Eastern Standard Time",
            "Romance Standard Time",
            "Russian Standard Time",
        ] {
            assert!(lookup_tz(name).is_some(), "{name} not mapped");
        }
        for (win, iana) in WINDOWS_ZONES {
            assert!(iana.parse::<Tz>().is_ok(), "{win} → {iana} is not a known IANA zone");
        }
    }

    #[test]
    fn unknown_tzid_uses_vtimezone() {
        let ics = crlf(
            "BEGIN:VCALENDAR
METHOD:REQUEST
BEGIN:VTIMEZONE
TZID:Customized Time Zone
BEGIN:STANDARD
DTSTART:16010101T020000
TZOFFSETFROM:-0400
TZOFFSETTO:-0500
RRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=1SU;BYMONTH=11
END:STANDARD
BEGIN:DAYLIGHT
DTSTART:16010101T020000
TZOFFSETFROM:-0500
TZOFFSETTO:-0400
RRULE:FREQ=YEARLY;INTERVAL=1;BYDAY=2SU;BYMONTH=3
END:DAYLIGHT
END:VTIMEZONE
BEGIN:VTIMEZONE
TZID:Customized Time Zone 1
BEGIN:STANDARD
DTSTART:16010101T000000
TZOFFSETFROM:+0800
TZOFFSETTO:+0800
END:STANDARD
END:VTIMEZONE
BEGIN:VEVENT
UID:custom-1
DTSTART;TZID=Customized Time Zone:20261023T100000
DTEND;TZID=Customized Time Zone:20261201T100000
END:VEVENT
END:VCALENDAR
",
        );
        let inv = parse_invite(&ics, &[]).unwrap();
        assert_eq!(inv.start, Some(utc(2026, 10, 23, 14, 0)));
        assert_eq!(inv.end, Some(utc(2026, 12, 1, 15, 0)));

        let fixed = ics.replace("TZID=Customized Time Zone:", "TZID=Customized Time Zone 1:");
        let inv = parse_invite(&fixed, &[]).unwrap();
        assert_eq!(inv.start, Some(utc(2026, 10, 23, 2, 0)));
    }

    #[test]
    fn google_utc_invite_with_quoted_params() {
        let inv = parse_invite(&crlf(GOOGLE), &own(&["bob@example.org"])).unwrap();
        assert_eq!(inv.method, "REQUEST");
        assert_eq!(inv.uid, "7kukuqrfedlm2f9t5vl6aaa@google.com");
        assert_eq!(inv.summary, "Weekly sync");
        assert_eq!(inv.location, None);
        assert!(inv.description.unwrap().ends_with("\nJoin with Google Meet: https://meet.google.com/abc-defg-hij"));
        assert_eq!(inv.start, Some(utc(2026, 10, 23, 9, 0)));
        assert_eq!(inv.end, Some(utc(2026, 10, 23, 10, 0)));
        assert_eq!(inv.organizer.as_ref().unwrap().email, "alice@gmail.com");
        assert_eq!(inv.attendees.len(), 2);
        assert_eq!(inv.attendees[1], EmailAddress::new(Some("Bob: Team; Lead, Ops"), "bob@example.org"));
        assert_eq!(inv.my_status.as_deref(), Some("NEEDS-ACTION"));
    }

    #[test]
    fn all_day_events() {
        let ics = crlf(
            "BEGIN:VCALENDAR
BEGIN:VEVENT
UID:holiday
SUMMARY:国庆调休
DTSTART;VALUE=DATE:20261023
DTEND;VALUE=DATE:20261025
END:VEVENT
END:VCALENDAR
",
        );
        let inv = parse_invite(&ics, &[]).unwrap();
        assert_eq!(inv.method, "PUBLISH");
        assert!(inv.all_day);
        assert_eq!(inv.start, Some(utc(2026, 10, 23, 0, 0)));
        assert_eq!(inv.end, Some(utc(2026, 10, 25, 0, 0)));

        // Bare date without DTEND lasts one day.
        let ics = "BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:d\nDTSTART:20261023\nEND:VEVENT\nEND:VCALENDAR\n";
        let inv = parse_invite(ics, &[]).unwrap();
        assert!(inv.all_day);
        assert_eq!(inv.end, Some(utc(2026, 10, 24, 0, 0)));
    }

    #[test]
    fn duration_instead_of_dtend() {
        let mk = |start: &str, dur: &str| {
            crlf(&format!("BEGIN:VCALENDAR\nBEGIN:VEVENT\nUID:d\nDTSTART{start}\nDURATION:{dur}\nEND:VEVENT\nEND:VCALENDAR\n"))
        };
        let inv = parse_invite(&mk(";TZID=Asia/Shanghai:20261023T140000", "PT1H30M"), &[]).unwrap();
        assert_eq!(inv.start, Some(utc(2026, 10, 23, 6, 0)));
        assert_eq!(inv.end, Some(utc(2026, 10, 23, 7, 30)));

        let inv = parse_invite(&mk(":20261023T090000Z", "PT1H"), &[]).unwrap();
        assert_eq!(inv.end, Some(utc(2026, 10, 23, 10, 0)));

        let inv = parse_invite(&mk(";VALUE=DATE:20261023", "P1D"), &[]).unwrap();
        assert!(inv.all_day);
        assert_eq!(inv.end, Some(utc(2026, 10, 24, 0, 0)));

        // P1D is a nominal day: across the US DST change it is 25 hours long.
        let inv = parse_invite(&mk(";TZID=America/New_York:20261031T120000", "P1D"), &[]).unwrap();
        assert_eq!(inv.start, Some(utc(2026, 10, 31, 16, 0)));
        assert_eq!(inv.end, Some(utc(2026, 11, 1, 17, 0)));

        assert_eq!(parse_duration("P2W"), Some((14, 0)));
        assert_eq!(parse_duration("P1DT2H3M4S"), Some((1, 2 * 3600 + 3 * 60 + 4)));
        assert_eq!(parse_duration("-PT15M"), Some((0, -900)));
        assert_eq!(parse_duration("PT"), None);
        assert_eq!(parse_duration("1H"), None);
        assert_eq!(parse_duration("PT5X"), None);
    }

    #[test]
    fn folded_lines_and_floating_time() {
        // LF-only endings, space and tab continuations, folding inside a quoted parameter.
        let ics = "BEGIN:VCALENDAR\nX-WR-TIMEZONE:Asia/Shanghai\nBEGIN:VEVENT\nUID:fold-1\nSUMMARY:关于下周\n \t二的项目评审\n\t会议\nATTENDEE;CN=\"赵\n 六\";PARTSTAT=ACCEPTED:mailto:zhao\n liu@example.com\nDTSTART:20261023T090000\nEND:VEVENT\nEND:VCALENDAR\n";
        let inv = parse_invite(ics, &own(&["zhaoliu@example.com"])).unwrap();
        assert_eq!(inv.summary, "关于下周\t二的项目评审会议");
        assert_eq!(inv.attendees, vec![EmailAddress::new(Some("赵六"), "zhaoliu@example.com")]);
        assert_eq!(inv.my_status.as_deref(), Some("ACCEPTED"));
        // Floating time resolved through X-WR-TIMEZONE.
        assert_eq!(inv.start, Some(utc(2026, 10, 23, 1, 0)));
        assert_eq!(inv.end, inv.start);

        // Without X-WR-TIMEZONE a floating time is local time.
        let local = ics.replace("X-WR-TIMEZONE:Asia/Shanghai\n", "");
        let inv = parse_invite(&local, &[]).unwrap();
        let naive = NaiveDate::from_ymd_opt(2026, 10, 23).unwrap().and_hms_opt(9, 0, 0).unwrap();
        assert_eq!(inv.start, resolve_local(&chrono::Local, naive));
    }

    #[test]
    fn no_vevent_returns_none() {
        assert!(parse_invite("BEGIN:VCALENDAR\r\nMETHOD:PUBLISH\r\nEND:VCALENDAR\r\n", &[]).is_none());
        assert!(parse_invite("", &[]).is_none());
    }

    #[test]
    fn reply_round_trip() {
        let original = crlf(OUTLOOK);
        let reply = build_reply(&original, "zhangsan@example.com", Some("张三"), "accepted").unwrap();
        assert_folded(&reply);
        assert!(reply.contains("METHOD:REPLY\r\n"));
        assert!(reply.contains("SEQUENCE:2\r\n"));
        assert!(reply.contains("TZID:China Standard Time\r\n"), "referenced VTIMEZONE is copied");
        assert!(!reply.contains("RSVP"));
        assert!(!reply.contains("wangwu"), "only our own ATTENDEE line is kept");
        assert!(!reply.contains("VALARM"));

        let parsed = parse_invite(&reply, &own(&["zhangsan@example.com"])).unwrap();
        assert_eq!(parsed.method, "REPLY");
        assert_eq!(parsed.my_status.as_deref(), Some("ACCEPTED"));
        let orig = parse_invite(&original, &[]).unwrap();
        assert_eq!(parsed.uid, orig.uid);
        assert_eq!(parsed.summary, orig.summary);
        assert_eq!(parsed.start, orig.start);
        assert_eq!(parsed.end, orig.end);
        assert_eq!(parsed.organizer, orig.organizer);
        assert_eq!(parsed.attendees, vec![EmailAddress::new(Some("张三"), "ZhangSan@Example.com")]);

        // Google invite: quoted CN with delimiters survives re-serialization.
        let reply = build_reply(&crlf(GOOGLE), "mailto:BOB@example.org", None, "Tentative").unwrap();
        let parsed = parse_invite(&reply, &own(&["bob@example.org"])).unwrap();
        assert_eq!(parsed.my_status.as_deref(), Some("TENTATIVE"));
        assert_eq!(parsed.attendees, vec![EmailAddress::new(Some("Bob: Team; Lead, Ops"), "bob@example.org")]);
        assert!(reply.contains("SEQUENCE:0\r\n"));

        // Not listed (e.g. invited through a mailing list): a fresh ATTENDEE line is added.
        let reply = build_reply(&crlf(GOOGLE), "carol@example.com", Some("Carol"), "DECLINED").unwrap();
        let parsed = parse_invite(&reply, &own(&["carol@example.com"])).unwrap();
        assert_eq!(parsed.my_status.as_deref(), Some("DECLINED"));
        assert_eq!(parsed.attendees, vec![EmailAddress::new(Some("Carol"), "carol@example.com")]);
    }

    #[test]
    fn reply_errors() {
        let original = crlf(OUTLOOK);
        assert!(matches!(build_reply(&original, "zhangsan@example.com", None, "MAYBE"), Err(Error::Invalid(_))));
        assert!(matches!(build_reply(&original, "", None, "ACCEPTED"), Err(Error::Invalid(_))));
        assert!(matches!(
            build_reply("BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n", "a@b.com", None, "ACCEPTED"),
            Err(Error::Invalid(_))
        ));
    }

    #[test]
    fn request_round_trip() {
        let organizer = EmailAddress::new(Some("李四"), "lisi@example.com");
        let attendees = vec![
            EmailAddress::new(Some("张三"), "zhangsan@example.com"),
            EmailAddress::new(None, "ZHANGSAN@example.com"),
            EmailAddress::new(Some("李四"), "lisi@example.com"),
        ];
        let desc = "会议议程：\n1. 回顾上周进度，确认各模块负责人；\n2. 讨论下一阶段的发布计划与风险，C:\\path";
        let ics = build_request(
            "evt-123@mailbox",
            "周会, 讨论; 计划",
            utc(2026, 10, 23, 1, 0),
            utc(2026, 10, 23, 2, 0),
            false,
            Some("线上 (腾讯会议)"),
            Some(desc),
            &organizer,
            &attendees,
        );
        assert_folded(&ics);
        assert!(ics.contains("DTSTART:20261023T010000Z\r\n"));
        assert!(ics.contains("SUMMARY:周会\\, 讨论\\; 计划\r\n"));
        let inv = parse_invite(&ics, &own(&["zhangsan@example.com"])).unwrap();
        assert_eq!(inv.method, "REQUEST");
        assert_eq!(inv.uid, "evt-123@mailbox");
        assert_eq!(inv.summary, "周会, 讨论; 计划");
        assert_eq!(inv.location.as_deref(), Some("线上 (腾讯会议)"));
        assert_eq!(inv.description.as_deref(), Some(desc));
        assert_eq!(inv.start, Some(utc(2026, 10, 23, 1, 0)));
        assert_eq!(inv.end, Some(utc(2026, 10, 23, 2, 0)));
        assert_eq!(inv.organizer, Some(organizer.clone()));
        assert_eq!(inv.attendees.len(), 2, "duplicate attendee removed");
        assert_eq!(inv.my_status.as_deref(), Some("NEEDS-ACTION"));
        let as_organizer = parse_invite(&ics, &own(&["lisi@example.com"])).unwrap();
        assert_eq!(as_organizer.my_status.as_deref(), Some("ACCEPTED"));

        let all_day = build_request(
            "evt-2",
            "团建",
            utc(2026, 10, 23, 0, 0),
            utc(2026, 10, 23, 0, 0),
            true,
            None,
            None,
            &organizer,
            &[],
        );
        assert!(all_day.contains("DTSTART;VALUE=DATE:20261023\r\n"));
        assert!(all_day.contains("DTEND;VALUE=DATE:20261024\r\n"));
        let inv = parse_invite(&all_day, &[]).unwrap();
        assert!(inv.all_day);
        assert_eq!(inv.start, Some(utc(2026, 10, 23, 0, 0)));
        assert_eq!(inv.end, Some(utc(2026, 10, 24, 0, 0)));
        assert_eq!(inv.location, None);
    }

    #[test]
    fn folding_is_utf8_safe() {
        let mut out = String::new();
        let long = format!("DESCRIPTION:{}", "中文字符🎉abc".repeat(30));
        push_line(&mut out, &long);
        assert_folded(&out);
        assert!(out.split("\r\n").count() > 3);
        assert_eq!(unfold(&out), vec![long]);
    }

    #[test]
    fn text_escaping() {
        let s = "a,b;c\\d\ne\r\nf";
        assert_eq!(escape_text(s), "a\\,b\\;c\\\\d\\ne\\nf");
        assert_eq!(unescape_text(&escape_text(s)), "a,b;c\\d\ne\nf");
        assert_eq!(unescape_text("x\\Ny\\:z\\"), "x\ny:z\\");
        assert_eq!(decode_caret("a^nb^'c^^d^x"), "a\nb\"c^d^x");
        assert_eq!(encode_param_value("Bob \"B\" ^"), "\"Bob ^'B^' ^^\"");
        assert_eq!(encode_param_value("ACCEPTED"), "ACCEPTED");
    }

    #[test]
    fn parses_content_lines() {
        let p = parse_line("ATTENDEE;CN=\"Doe; John: Jr.\";DELEGATED-TO=\"mailto:a@x.com\",\"mailto:b@x.com\";RSVP=TRUE:mailto:j@x.com").unwrap();
        assert_eq!(p.name, "ATTENDEE");
        assert_eq!(p.param("cn"), Some("Doe; John: Jr."));
        assert_eq!(p.params[1].values, vec!["mailto:a@x.com", "mailto:b@x.com"]);
        assert_eq!(p.param("RSVP"), Some("TRUE"));
        assert_eq!(p.value, "mailto:j@x.com");
        assert!(parse_line("NO-COLON-HERE").is_none());
        assert_eq!(parse_line("x-custom:a:b").unwrap().value, "a:b");
    }
}
