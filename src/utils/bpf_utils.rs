use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsFd;

use crate::bpf::{self, FilterSkel};
use libbpf_rs::{Xdp, XdpFlags};
use nix::libc;

fn is_ipv6_disabled(iface: Option<&str>) -> bool {
    // Check if IPv6 is disabled for a specific interface or system-wide
    if let Some(iface_name) = iface
        && let Ok(content) = fs::read_to_string(format!(
            "/proc/sys/net/ipv6/conf/{}/disable_ipv6",
            iface_name
        ))
    {
        return content.trim() == "1";
    }
    // Fall back to system-wide check
    if let Ok(content) = fs::read_to_string("/proc/sys/net/ipv6/conf/all/disable_ipv6") {
        return content.trim() == "1";
    }
    false
}

fn try_enable_ipv6_for_interface(iface: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Try to enable IPv6 only for the specific interface (not system-wide)
    // This allows IPv4-only operation elsewhere while enabling XDP on this interface
    let disable_path = format!("/proc/sys/net/ipv6/conf/{}/disable_ipv6", iface);

    if is_ipv6_disabled(Some(iface)) {
        log::debug!(
            "IPv6 is disabled for interface {}, attempting to enable it for XDP attachment",
            iface
        );
        std::fs::write(&disable_path, "0")?;
        log::info!(
            "Enabled IPv6 for interface {} (required for XDP, IPv4-only elsewhere)",
            iface
        );
        Ok(())
    } else {
        Ok(())
    }
}

pub fn bpf_attach_to_xdp(
    skel: &mut FilterSkel<'_>,
    ifindex: i32,
    iface_name: Option<&str>,
    ip_version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // Try hardware mode first, fall back to driver mode if not supported
    let xdp = Xdp::new(skel.progs.arxignis_xdp_filter.as_fd().into());

    // Try hardware offload mode first
    if let Ok(()) = xdp.attach(ifindex, XdpFlags::HW_MODE) {
        log::info!("XDP program attached in hardware offload mode");
        return Ok(());
    }

    // Fall back to driver mode if hardware mode fails
    match xdp.attach(ifindex, XdpFlags::DRV_MODE) {
        Ok(()) => {
            log::info!("XDP program attached in driver mode");
            return Ok(());
        }
        Err(e) => {
            // Check if error is EEXIST (error 17) - XDP program already attached
            let error_msg = e.to_string();
            if error_msg.contains("17") || error_msg.contains("File exists") {
                log::debug!(
                    "Driver mode failed: XDP program already attached, trying to replace with REPLACE flag"
                );
                // Try to replace existing XDP program
                match xdp.attach(ifindex, XdpFlags::DRV_MODE | XdpFlags::REPLACE) {
                    Ok(()) => {
                        log::info!("XDP program replaced existing program in driver mode");
                        return Ok(());
                    }
                    Err(e2) => {
                        log::debug!(
                            "Replace in driver mode failed: {}, trying generic SKB mode",
                            e2
                        );
                    }
                }
            } else {
                log::debug!("Driver mode failed, trying generic SKB mode: {}", e);
            }
        }
    }

    // Try SKB mode (should work on all interfaces, including IPv4-only)
    match xdp.attach(ifindex, XdpFlags::SKB_MODE) {
        Ok(()) => {
            log::info!("XDP program attached in generic SKB mode");
            return Ok(());
        }
        Err(e) => {
            // Check if error is EEXIST (error 17) first
            let error_msg = e.to_string();
            if error_msg.contains("17") || error_msg.contains("File exists") {
                log::debug!("SKB mode failed: XDP program already attached, trying to replace");
                // Try to replace existing XDP program in SKB mode
                match xdp.attach(ifindex, XdpFlags::SKB_MODE | XdpFlags::REPLACE) {
                    Ok(()) => {
                        log::info!("XDP program replaced existing program in generic SKB mode");
                        return Ok(());
                    }
                    Err(e2) => {
                        log::debug!(
                            "Replace in SKB mode failed: {}, continuing with other fallbacks",
                            e2
                        );
                    }
                }
            }
            // If SKB mode fails with EAFNOSUPPORT (error 97), it's likely due to IPv6 being disabled
            if error_msg.contains("97") || error_msg.contains("Address family not supported") {
                log::debug!("SKB mode failed with EAFNOSUPPORT, IPv6 might be disabled");

                // Note: XDP requires IPv6 to be enabled at the kernel level for attachment,
                // even when processing only IPv4 packets. This is a kernel limitation.
                // For IPv4-only mode, we can enable IPv6 just for this interface (not system-wide)
                // which allows XDP to attach while still operating in IPv4-only mode.
                if ip_version == "ipv4" {
                    log::info!(
                        "IPv4-only mode: Attempting to enable IPv6 on interface for XDP attachment (kernel requirement)"
                    );
                }

                // Try to enable IPv6 only for this specific interface (not system-wide)
                // This allows IPv4-only operation elsewhere while enabling XDP on this interface
                if let Some(iface) = iface_name {
                    if try_enable_ipv6_for_interface(iface).is_ok() {
                        log::debug!(
                            "Retrying XDP attachment after enabling IPv6 for interface {}",
                            iface
                        );

                        // Retry SKB mode after enabling IPv6 for the interface
                        match xdp.attach(ifindex, XdpFlags::SKB_MODE) {
                            Ok(()) => {
                                if ip_version == "ipv4" {
                                    log::info!(
                                        "XDP program attached in generic SKB mode (IPv6 enabled on interface {} for kernel compatibility, processing IPv4 only)",
                                        iface
                                    );
                                } else {
                                    log::info!(
                                        "XDP program attached in generic SKB mode (IPv6 enabled for interface {})",
                                        iface
                                    );
                                }
                                return Ok(());
                            }
                            Err(e2) => {
                                log::debug!(
                                    "SKB mode still failed after enabling IPv6 for interface: {}",
                                    e2
                                );
                            }
                        }
                    } else {
                        log::debug!(
                            "Failed to enable IPv6 for interface {} or no permission",
                            iface
                        );
                    }
                } else {
                    log::debug!("Interface name not provided, cannot enable IPv6 per-interface");
                }

                // Try with UPDATE_IF_NOEXIST flag as last resort
                match xdp.attach(ifindex, XdpFlags::SKB_MODE | XdpFlags::UPDATE_IF_NOEXIST) {
                    Ok(()) => {
                        log::info!(
                            "XDP program attached in generic SKB mode (with UPDATE_IF_NOEXIST)"
                        );
                        return Ok(());
                    }
                    Err(e2) => {
                        log::debug!("SKB mode with UPDATE_IF_NOEXIST also failed: {}", e2);
                    }
                }
            }

            Err(Box::new(e))
        }
    }
}

pub fn ipv4_to_u32_be(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

pub fn convert_ip_into_bpf_map_key_bytes(ip: Ipv4Addr, prefixlen: u32) -> Box<[u8]> {
    let ip_u32: u32 = ip.into();
    let ip_be = ip_u32.to_be();

    let my_ip_key: bpf::types::lpm_key = bpf::types::lpm_key {
        prefixlen,
        addr: ip_be,
    };

    let my_ip_key_bytes = unsafe { plain::as_bytes(&my_ip_key) };
    my_ip_key_bytes.to_vec().into_boxed_slice()
}

pub fn convert_ipv6_into_bpf_map_key_bytes(ip: Ipv6Addr, prefixlen: u32) -> Box<[u8]> {
    let ip_bytes = ip.octets();

    let my_ip_key: bpf::types::lpm_key_v6 = bpf::types::lpm_key_v6 {
        prefixlen,
        addr: ip_bytes,
    };

    let my_ip_key_bytes = unsafe { plain::as_bytes(&my_ip_key) };
    my_ip_key_bytes.to_vec().into_boxed_slice()
}

pub fn convert_ip_port_into_bpf_map_key_bytes(ip: Ipv4Addr, port: u16) -> Box<[u8]> {
    let ip_u32: u32 = ip.into();
    let ip_be = ip_u32.to_be();

    let ip_port_key: bpf::types::src_port_key_v4 = bpf::types::src_port_key_v4 {
        addr: ip_be,
        port: port.to_be(),
    };

    let ip_port_key_bytes = unsafe { plain::as_bytes(&ip_port_key) };
    ip_port_key_bytes.to_vec().into_boxed_slice()
}

pub fn convert_ipv6_port_into_map_key_bytes(ip: Ipv6Addr, port: u16) -> Box<[u8]> {
    let ip_bytes = ip.octets();

    let ip_port_key: bpf::types::src_port_key_v6 = bpf::types::src_port_key_v6 {
        addr: ip_bytes,
        port: port.to_be(),
    };

    let ip_port_key_bytes = unsafe { plain::as_bytes(&ip_port_key) };
    ip_port_key_bytes.to_vec().into_boxed_slice()
}

pub fn bpf_detach_from_xdp(ifindex: i32) -> Result<(), Box<dyn std::error::Error>> {
    // Create a dummy XDP instance for detaching
    // We need to query first to get the existing program ID
    let dummy_fd = unsafe {
        libc::open(
            "/dev/null\0".as_ptr() as *const libc::c_char,
            libc::O_RDONLY,
        )
    };
    if dummy_fd < 0 {
        return Err("Failed to create dummy file descriptor".into());
    }

    let xdp = Xdp::new(unsafe { std::os::fd::BorrowedFd::borrow_raw(dummy_fd) });

    // Try to detach using different modes
    let modes = [XdpFlags::HW_MODE, XdpFlags::DRV_MODE, XdpFlags::SKB_MODE];

    for mode in modes {
        if let Ok(()) = xdp.detach(ifindex, mode) {
            log::info!("XDP program detached from interface");
            unsafe {
                libc::close(dummy_fd);
            }
            return Ok(());
        }
    }

    unsafe {
        libc::close(dummy_fd);
    }
    Err("Failed to detach XDP program from interface".into())
}
