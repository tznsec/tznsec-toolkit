use serde_json::json;

pub fn parse_user_agent(ua: &str) -> serde_json::Value {
    let ua_lower = ua.to_lowercase();
    
    let browser = if ua_lower.contains("chrome") && !ua_lower.contains("edg") {
        "Chrome"
    } else if ua_lower.contains("firefox") {
        "Firefox"
    } else if ua_lower.contains("safari") && !ua_lower.contains("chrome") {
        "Safari"
    } else if ua_lower.contains("edg") {
        "Edge"
    } else if ua_lower.contains("opera") || ua_lower.contains("opr") {
        "Opera"
    } else {
        "Nieznana"
    };

    let os = if ua_lower.contains("windows") {
        "Windows"
    } else if ua_lower.contains("mac os") || ua_lower.contains("macintosh") {
        "macOS"
    } else if ua_lower.contains("linux") {
        "Linux"
    } else if ua_lower.contains("android") {
        "Android"
    } else if ua_lower.contains("ios") || ua_lower.contains("iphone") || ua_lower.contains("ipad") {
        "iOS"
    } else {
        "Nieznany"
    };

    let is_mobile = ua_lower.contains("mobile") || ua_lower.contains("android") || ua_lower.contains("iphone");
    let is_bot = ua_lower.contains("bot") || ua_lower.contains("crawler") || ua_lower.contains("spider");

    json!({
        "browser": browser,
        "os": os,
        "is_mobile": is_mobile,
        "is_bot": is_bot,
        "user_agent": ua
    })
}
