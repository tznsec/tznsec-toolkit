use serde_json::json;
use trust_dns_resolver::config::*;
use trust_dns_resolver::TokioAsyncResolver;

pub async fn lookup(domain: &str, record_type: Option<&str>) -> serde_json::Value {
    let resolver = TokioAsyncResolver::tokio(
        ResolverConfig::default(),
        ResolverOpts::default(),
    );

    let rtype = record_type.unwrap_or("A").to_uppercase();

    let result = match rtype.as_str() {
        "A" => {
            match resolver.ipv4_lookup(domain).await {
                Ok(lookup) => {
                    let records: Vec<String> = lookup.iter().map(|r| r.to_string()).collect();
                    json!({ "domain": domain, "type": "A", "records": records })
                }
                Err(e) => json!({ "error": format!("Błąd zapytania A: {}", e) }),
            }
        }
        "AAAA" => {
            match resolver.ipv6_lookup(domain).await {
                Ok(lookup) => {
                    let records: Vec<String> = lookup.iter().map(|r| r.to_string()).collect();
                    json!({ "domain": domain, "type": "AAAA", "records": records })
                }
                Err(e) => json!({ "error": format!("Błąd zapytania AAAA: {}", e) }),
            }
        }
        "MX" => {
            match resolver.mx_lookup(domain).await {
                Ok(lookup) => {
                    let records: Vec<String> = lookup.iter().map(|r| {
                        format!("{} (priorytet: {})", r.exchange(), r.preference())
                    }).collect();
                    json!({ "domain": domain, "type": "MX", "records": records })
                }
                Err(e) => json!({ "error": format!("Błąd zapytania MX: {}", e) }),
            }
        }
        "TXT" => {
            match resolver.txt_lookup(domain).await {
                Ok(lookup) => {
                    let records: Vec<String> = lookup.iter().map(|r| {
                        r.txt_data().iter().map(|b| String::from_utf8_lossy(b).to_string()).collect::<Vec<_>>().join("")
                    }).collect();
                    json!({ "domain": domain, "type": "TXT", "records": records })
                }
                Err(e) => json!({ "error": format!("Błąd zapytania TXT: {}", e) }),
            }
        }
        "NS" => {
            match resolver.ns_lookup(domain).await {
                Ok(lookup) => {
                    let records: Vec<String> = lookup.iter().map(|r| r.to_string()).collect();
                    json!({ "domain": domain, "type": "NS", "records": records })
                }
                Err(e) => json!({ "error": format!("Błąd zapytania NS: {}", e) }),
            }
        }
        "CNAME" => {
            use trust_dns_resolver::proto::rr::RecordType;
            match resolver.lookup(domain, RecordType::CNAME).await {
                Ok(lookup) => {
                    let records: Vec<String> = lookup.iter().map(|r| r.to_string()).collect();
                    json!({ "domain": domain, "type": "CNAME", "records": records })
                }
                Err(e) => json!({ "error": format!("Błąd zapytania CNAME: {}", e) }),
            }
        }
        _ => json!({ "error": format!("Nieobsługiwany typ rekordu: {}", rtype) }),
    };

    result
}
