use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use anyhow::{Context, Result};
use pcap::{Capture, Device};
use tracing::{error, info};

use crate::app::App;
use crate::packet::{self, LinkType};

pub struct CaptureHandle {
    _handle: thread::JoinHandle<()>,
    stop: Arc<AtomicBool>,
}

/// A group of capture handles for multi-interface capture.
pub struct CaptureGroup {
    handles: Vec<CaptureHandle>,
}

impl CaptureGroup {
    /// Start capturing on multiple interfaces.
    /// Each interface gets its own capture thread sharing the same App state.
    #[allow(clippy::needless_pass_by_value)]
    pub fn start(
        interfaces: &[String],
        filter: Option<&str>,
        app: Arc<Mutex<App>>,
        counter: Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<Self> {
        let mut handles = Vec::new();
        let iface_names: Vec<String> = interfaces.to_vec();
        for name in &iface_names {
            let h =
                CaptureHandle::start_named(name, filter, Arc::clone(&app), Arc::clone(&counter))?;
            handles.push(h);
        }
        if let Ok(mut a) = app.lock() {
            a.interface_name = iface_names.join(",");
        }
        Ok(Self { handles })
    }

    /// Signal all capture threads to stop.
    pub fn stop(&self) {
        for h in &self.handles {
            h.stop();
        }
    }
}

impl Drop for CaptureGroup {
    fn drop(&mut self) {
        self.stop();
    }
}

impl CaptureHandle {
    pub fn start(
        interface: Option<&str>,
        filter: Option<&str>,
        app: Arc<Mutex<App>>,
    ) -> Result<Self> {
        let device = match interface {
            Some(name) => Device::list()
                .context("failed to list devices")?
                .into_iter()
                .find(|d| d.name == name)
                .with_context(|| format!("interface '{name}' not found"))?,
            None => Device::lookup()
                .context("failed to lookup default device")?
                .context("no default device found")?,
        };

        // Store the active interface name.
        if let Ok(mut a) = app.lock() {
            a.interface_name.clone_from(&device.name);
        }

        let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        Self::start_on_device(device, filter, app, counter)
    }

    /// Start capture on a named interface with a shared counter.
    fn start_named(
        name: &str,
        filter: Option<&str>,
        app: Arc<Mutex<App>>,
        counter: Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<Self> {
        let device = Device::list()
            .context("failed to list devices")?
            .into_iter()
            .find(|d| d.name == name)
            .with_context(|| format!("interface '{name}' not found"))?;
        Self::start_on_device(device, filter, app, counter)
    }

    fn start_on_device(
        device: Device,
        filter: Option<&str>,
        app: Arc<Mutex<App>>,
        counter: Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<Self> {
        info!(interface = %device.name, "starting capture");

        let mut cap = Capture::from_device(device)
            .context("failed to open device")?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()
            .context("failed to activate capture")?;

        // Detect link-layer type for correct packet parsing.
        let link_type = LinkType::from_dlt(cap.get_datalink().0.cast_unsigned());

        if let Some(f) = filter {
            cap.filter(f, true)
                .with_context(|| format!("bad BPF filter: {f}"))?;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop);

        let handle = thread::spawn(move || {
            loop {
                if stop_clone.load(Ordering::Relaxed) {
                    break;
                }
                match cap.next_packet() {
                    Ok(pkt) => {
                        let id = counter.fetch_add(1, Ordering::Relaxed) + 1;
                        let parsed = packet::parse_packet_with_link(id, pkt.data, link_type);
                        if let Ok(mut app) = app.lock() {
                            app.push_packet(parsed);
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {}
                    Err(e) => {
                        error!(%e, "capture error");
                        break;
                    }
                }
            }
        });

        Ok(Self {
            _handle: handle,
            stop,
        })
    }

    /// Signal the capture thread to stop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for CaptureHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// List available network interfaces.
pub fn list_interfaces() -> Result<Vec<InterfaceInfo>> {
    let devices = Device::list().context("failed to list devices")?;
    Ok(devices
        .into_iter()
        .map(|d| {
            let addrs: Vec<String> = d.addresses.iter().map(|a| format!("{}", a.addr)).collect();
            InterfaceInfo {
                name: d.name,
                description: d.desc.unwrap_or_default(),
                addresses: addrs,
            }
        })
        .collect())
}

/// Info about a network interface for display in the picker.
#[derive(Debug, Clone, serde::Serialize)]
#[allow(dead_code)]
pub struct InterfaceInfo {
    pub name: String,
    pub description: String,
    pub addresses: Vec<String>,
}
