//! Heuristic inbox categories (Primary / Social / Promotions / Updates / Forums).

use crate::mime::Headers;
use crate::model::Category;

const SOCIAL_DOMAINS: &[&str] = &[
    "facebookmail.com", "linkedin.com", "twitter.com", "x.com", "instagram.com", "pinterest.com", "tiktok.com",
    "weibo.com", "weibo.cn", "douban.com", "zhihu.com", "xiaohongshu.com", "bilibili.com", "quora.com", "reddit.com",
    "redditmail.com", "discord.com", "slack.com", "meetup.com", "tumblr.com", "youtube.com", "qzone.qq.com",
    "telegram.org", "whatsapp.com", "snapchat.com", "mastodon.social", "threads.net",
];

const PROMO_WORDS: &[&str] = &[
    "优惠", "促销", "限时", "折扣", "特价", "满减", "红包", "秒杀", "抢购", "大促", "领券", "立减", "包邮", "会员日",
    "sale", "% off", "discount", "deal", "coupon", "promo", "newsletter", "offer", "free shipping", "black friday",
    "webinar", "limited time",
];

const UPDATE_WORDS: &[&str] = &[
    "验证码", "订单", "账单", "发票", "收据", "物流", "快递", "已发货", "通知", "提醒", "支付", "交易", "安全", "登录",
    "receipt", "invoice", "order", "verification", "verify", "password", "security", "alert", "statement", "shipped",
    "delivery", "payment", "confirm", "your account", "sign-in", "login",
];

fn domain(email: &str) -> &str {
    email.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
}

fn domain_matches(d: &str, list: &[&str]) -> bool {
    list.iter().any(|x| d == *x || d.ends_with(&format!(".{x}")))
}

/// `known_sender`: the user has written to this address before (always Primary).
pub fn categorize(h: &Headers, known_sender: bool) -> Category {
    if known_sender {
        return Category::Primary;
    }
    let from = h.from.email.to_lowercase();
    let d = domain(&from);
    let local = from.split('@').next().unwrap_or("");
    let subject = h.subject.to_lowercase();
    let bulk = h.precedence.as_deref().is_some_and(|p| p == "bulk" || p == "list" || p == "junk");
    let has = |n: &str| h.header_names.iter().any(|x| x == n);
    let esp = has("x-mailchimp-campaign")
        || has("x-campaign")
        || has("x-campaignid")
        || has("x-mc-user")
        || has("x-sg-eid")
        || has("x-mailgun-tag")
        || has("x-ses-outgoing")
        || has("x-marketo-id")
        || has("x-sfmc-stack")
        || has("x-edm-id");

    if domain_matches(d, SOCIAL_DOMAINS) {
        return Category::Social;
    }
    let is_list = h.list_id.is_some();
    let list_like = is_list && !bulk && !esp && h.unsubscribe.as_ref().map(|u| !u.one_click).unwrap_or(true);
    if list_like
        && (h.list_id.as_deref().is_some_and(|l| l.contains("googlegroups") || l.contains("lists.") || l.contains("discourse"))
            || subject.starts_with('['))
    {
        return Category::Forums;
    }
    let promo_word = PROMO_WORDS.iter().any(|w| subject.contains(w));
    let update_word = UPDATE_WORDS.iter().any(|w| subject.contains(w));
    let noreply = local.contains("noreply")
        || local.contains("no-reply")
        || local.contains("donotreply")
        || local.contains("notification")
        || local.contains("notify")
        || local.contains("alert")
        || local.contains("service")
        || local.contains("system")
        || local.contains("account")
        || local.starts_with("info");
    if update_word && (noreply || h.auto_submitted || !promo_word) && !esp {
        return Category::Updates;
    }
    if esp || promo_word || (h.unsubscribe.is_some() && (bulk || local.contains("news") || local.contains("marketing") || local.contains("promo"))) {
        return Category::Promotions;
    }
    if h.unsubscribe.is_some() && bulk {
        return Category::Promotions;
    }
    if noreply || h.auto_submitted {
        return Category::Updates;
    }
    if h.unsubscribe.is_some() {
        return Category::Promotions;
    }
    Category::Primary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EmailAddress, Unsubscribe};

    fn h(from: &str, subject: &str) -> Headers {
        Headers { from: EmailAddress::new(None, from), subject: subject.into(), ..Default::default() }
    }

    #[test]
    fn categories() {
        assert_eq!(categorize(&h("friend@qq.com", "周末吃饭"), false), Category::Primary);
        assert_eq!(categorize(&h("notification@weibo.com", "有人@了你"), false), Category::Social);
        assert_eq!(categorize(&h("no-reply@alipay.com", "您的账单已出"), false), Category::Updates);
        let mut p = h("news@shop.com", "双十一大促 全场5折");
        p.unsubscribe = Some(Unsubscribe { http: Some("https://x".into()), mailto: None, one_click: true });
        assert_eq!(categorize(&p, false), Category::Promotions);
        let mut f = h("someone@gmail.com", "[rust-dev] RFC");
        f.list_id = Some("rust-dev.googlegroups.com".into());
        assert_eq!(categorize(&f, false), Category::Forums);
        assert_eq!(categorize(&p, true), Category::Primary);
    }
}
