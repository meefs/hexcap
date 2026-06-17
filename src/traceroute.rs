//! Active traceroute runner.
//!
//! Spawns standard OS `traceroute` (macOS/Linux) or `tracert` (Windows) binary
//! in a background thread, parses hop endpoints, resolves reverse DNS and `GeoIP` country,
//! and updates the active `App` state.

use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::app::App;
use crate::dns;
use crate::geoip;

#[derive(Debug, Clone)]
pub struct TracerouteHop {
    pub hop: u8,
    pub ip: String,
    pub hostname: Option<String>,
    pub geoip: Option<String>,
    pub rtt: Option<f64>,
}

pub struct TracerouteState {
    pub target: String,
    pub hops: Vec<TracerouteHop>,
    pub running: bool,
    pub error: Option<String>,
}

impl TracerouteState {
    pub fn new(target: String) -> Self {
        Self {
            target,
            hops: Vec::new(),
            running: true,
            error: None,
        }
    }
}

/// Start active traceroute in background thread
pub fn run_traceroute(target: String, app: Arc<Mutex<App>>, geoip_db: Option<Arc<geoip::GeoDb>>) {
    thread::spawn(move || {
        // Run traceroute with -I (ICMP Echo) which is less likely to be
        // blocked by firewalls than UDP probes, and -n (numerical IPs).
        // macOS/Linux: traceroute -I -n -q 1 -w 3 -m 30 <target>
        // Windows: tracert -d -h 30 -w 2000 <target>
        #[cfg(windows)]
        let mut cmd = Command::new("tracert");
        #[cfg(windows)]
        cmd.args(["-d", "-h", "30", "-w", "2000", &target]);

        #[cfg(not(windows))]
        let mut cmd = Command::new("traceroute");
        #[cfg(not(windows))]
        cmd.args(["-I", "-n", "-q", "1", "-w", "3", "-m", "30", &target]);

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                let mut app_guard = app.lock().expect("app mutex poisoned");
                if let Some(ref mut state) = app_guard.traceroute_state {
                    state.running = false;
                    state.error = Some(format!("Failed to spawn traceroute: {e}"));
                }
                return;
            }
        };

        let stdout = child
            .stdout
            .take()
            .expect("stdout configured via Stdio::piped");
        let reader = BufReader::new(stdout);

        for line_result in reader.lines() {
            let Ok(line) = line_result else { break };

            if let Some(hop) = parse_line(&line) {
                // Enrich hop with DNS & GeoIP in background
                let mut resolved_hop = hop.clone();
                if hop.ip != "*"
                    && let Ok(ip_addr) = hop.ip.parse::<IpAddr>()
                {
                    // Reverse DNS
                    resolved_hop.hostname = dns::resolve_blocking(ip_addr);
                    // GeoIP
                    if let Some(ref db) = geoip_db {
                        resolved_hop.geoip = db.country(ip_addr);
                    }
                }

                // Update app state
                let mut app_guard = app.lock().expect("app mutex poisoned");
                if let Some(ref mut state) = app_guard.traceroute_state {
                    if let Some(existing) =
                        state.hops.iter_mut().find(|h| h.hop == resolved_hop.hop)
                    {
                        *existing = resolved_hop;
                    } else {
                        state.hops.push(resolved_hop);
                        state.hops.sort_by_key(|h| h.hop);
                    }
                }
            }
        }

        // Wait for child process to finish
        let status = child.wait().ok();
        let mut app_guard = app.lock().expect("app mutex poisoned");
        if let Some(ref mut state) = app_guard.traceroute_state {
            state.running = false;
            if let Some(stat) = status
                && !stat.success()
                && state.hops.is_empty()
            {
                state.error = Some("Traceroute exited with error".to_string());
            }
        }
    });
}

fn parse_line(line: &str) -> Option<TracerouteHop> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return None;
    }

    // First part must be hop number
    let hop: u8 = parts[0].parse().ok()?;

    // Check timeout
    if line.contains('*') {
        return Some(TracerouteHop {
            hop,
            ip: "*".to_string(),
            hostname: None,
            geoip: None,
            rtt: None,
        });
    }

    #[cfg(not(windows))]
    {
        if parts.len() >= 3 {
            let ip = parts[1].to_string();
            let rtt = parts[2].parse::<f64>().ok();
            return Some(TracerouteHop {
                hop,
                ip,
                hostname: None,
                geoip: None,
                rtt,
            });
        }
    }

    #[cfg(windows)]
    {
        if parts.len() >= 5 {
            let ip = parts[parts.len() - 1].to_string();
            let mut rtt = None;
            for part in parts.iter().skip(1).take(3) {
                if part.contains('<') {
                    rtt = Some(0.5);
                    break;
                } else if let Ok(val) = part.parse::<f64>() {
                    rtt = Some(val);
                    break;
                }
            }
            return Some(TracerouteHop {
                hop,
                ip,
                hostname: None,
                geoip: None,
                rtt,
            });
        }
    }

    None
}
