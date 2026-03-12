use std::collections::HashMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::mpsc;
use std::thread;

use super::special::check_special;

const MAX_CACHE_SIZE: usize = 10_000;

#[derive(Debug, Clone)]
pub struct IpInfo {
    pub address: String,
    pub asn: String,
    pub as_name: String,
    pub country: String,
    pub rir: String,
    pub is_special: bool,
    pub error: Option<String>,
}

impl IpInfo {
    /// Create a "looking up..." placeholder.
    pub fn pending(address: &str) -> Self {
        Self {
            address: address.to_string(),
            asn: "Looking up...".to_string(),
            as_name: String::new(),
            country: String::new(),
            rir: String::new(),
            is_special: false,
            error: None,
        }
    }

    /// Create an error result.
    fn error(address: &str, msg: String) -> Self {
        Self {
            address: address.to_string(),
            asn: "N/A".to_string(),
            as_name: "Lookup failed".to_string(),
            country: "N/A".to_string(),
            rir: "N/A".to_string(),
            is_special: false,
            error: Some(msg),
        }
    }
}

#[derive(Default)]
pub struct IpLookup {
    cache: HashMap<String, IpInfo>,
    in_flight: std::collections::HashSet<String>,
}

impl IpLookup {
    pub fn new() -> Self {
        Self::default()
    }

    /// Look up an IP address. Returns immediately for special/cached IPs.
    /// Returns `None` if a background lookup is needed (caller should spawn a thread).
    pub fn lookup(&mut self, addr_str: &str) -> Option<IpInfo> {
        // Check cache first
        if let Some(info) = self.cache.get(addr_str) {
            return Some(info.clone());
        }

        // Try parsing as IP
        let addr: IpAddr = match addr_str.parse() {
            Ok(a) => a,
            Err(_) => return None, // Not an IP address (e.g., MAC for ARP)
        };

        // Check special ranges
        if let Some(info) = check_special(addr) {
            self.cache.insert(addr_str.to_string(), info.clone());
            return Some(info);
        }

        // Needs background lookup — return None to signal caller
        None
    }

    /// Check if an address is already being looked up in the background.
    pub fn is_in_flight(&self, addr: &str) -> bool {
        self.in_flight.contains(addr)
    }

    /// Mark an address as having an in-flight lookup.
    pub fn mark_in_flight(&mut self, addr: &str) {
        self.in_flight.insert(addr.to_string());
    }

    /// Insert a result into the cache and remove from in-flight set.
    pub fn insert(&mut self, addr: String, info: IpInfo) {
        self.in_flight.remove(&addr);
        // Evict oldest entries if cache is too large
        if self.cache.len() >= MAX_CACHE_SIZE {
            let keys: Vec<String> = self.cache.keys().take(MAX_CACHE_SIZE / 4).cloned().collect();
            for k in keys {
                self.cache.remove(&k);
            }
        }
        self.cache.insert(addr, info);
    }
}

/// Query Team Cymru DNS for IP-to-ASN mapping. Blocking call — run in a background thread.
///
/// Uses two DNS TXT lookups:
///   1. `{reversed_ip}.origin.asn.cymru.com` → "ASN | prefix | CC | RIR | date"
///   2. `AS{asn}.asn.cymru.com` → "ASN | CC | RIR | date | AS Name"
pub fn query_cymru(addr: &str) -> IpInfo {
    let ip: IpAddr = match addr.parse() {
        Ok(a) => a,
        Err(e) => return IpInfo::error(addr, format!("Invalid IP: {e}")),
    };

    // Step 1: IP-to-ASN lookup
    let origin_name = build_origin_query(&ip);
    let origin_result = dns_txt_lookup(&origin_name);
    let origin_line = match origin_result {
        Ok(line) => line,
        Err(e) => return IpInfo::error(addr, e),
    };

    // Parse: "13335 | 1.1.1.0/24 | AU | apnic | 2011-08-11"
    let origin_parts: Vec<&str> = origin_line.split('|').map(|s| s.trim()).collect();
    if origin_parts.len() < 5 {
        return IpInfo::error(addr, format!("Unexpected origin response: {origin_line}"));
    }

    let asn_num = origin_parts[0].trim();
    let country = origin_parts[2].trim().to_uppercase();
    let rir = origin_parts[3].trim().to_uppercase();

    // Step 2: ASN-to-name lookup
    let as_query = format!("AS{asn_num}.asn.cymru.com");
    let as_name = match dns_txt_lookup(&as_query) {
        Ok(line) => {
            // Parse: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US"
            let parts: Vec<&str> = line.splitn(5, '|').collect();
            if parts.len() >= 5 {
                parts[4].trim().to_string()
            } else {
                "N/A".to_string()
            }
        }
        Err(_) => "N/A".to_string(),
    };

    IpInfo {
        address: addr.to_string(),
        asn: format!("AS{asn_num}"),
        as_name,
        country,
        rir,
        is_special: false,
        error: None,
    }
}

/// Build the DNS query name for Team Cymru origin lookup.
fn build_origin_query(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let expanded = v6.octets();
            let nibbles: String = expanded
                .iter()
                .rev()
                .flat_map(|byte| {
                    let lo = byte & 0x0F;
                    let hi = (byte >> 4) & 0x0F;
                    [
                        char::from(if lo < 10 { b'0' + lo } else { b'a' + lo - 10 }),
                        '.',
                        char::from(if hi < 10 { b'0' + hi } else { b'a' + hi - 10 }),
                        '.',
                    ]
                })
                .collect();
            format!("{}origin6.asn.cymru.com", nibbles)
        }
    }
}

/// Perform a DNS TXT lookup using the `dig` command.
fn dns_txt_lookup(name: &str) -> Result<String, String> {
    let output = Command::new("dig")
        .args(["+short", "+time=3", "+tries=1", "TXT", name])
        .output()
        .map_err(|e| format!("Failed to run dig: {e}"))?;

    if !output.status.success() {
        return Err(format!("dig failed: {}", String::from_utf8_lossy(&output.stderr)));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim().trim_matches('"');
    if line.is_empty() {
        return Err("No DNS response".to_string());
    }
    Ok(line.to_string())
}

/// Spawn a background thread to look up an IP address.
/// Returns a receiver that will contain the result.
pub fn spawn_lookup(addr: String) -> mpsc::Receiver<(String, IpInfo)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let info = query_cymru(&addr);
        let _ = tx.send((addr, info));
    });
    rx
}
