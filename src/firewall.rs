use std::{error::Error, net::{Ipv4Addr, Ipv6Addr}};

use libbpf_rs::{MapCore, MapFlags};

use crate::utils::bpf_utils;

pub trait Firewall {
    fn ban_ip_with_notice(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn ban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn unban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn check_if_notice(&mut self, ip: Ipv4Addr) -> Result<bool, Box<dyn Error>>;

    // IPv6 methods
    fn ban_ipv6_with_notice(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn ban_ipv6(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn unban_ipv6(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>>;
    fn check_if_notice_ipv6(&mut self, ip: Ipv6Addr) -> Result<bool, Box<dyn Error>>;

    // TCP fingerprint blocking methods
    fn block_tcp_fingerprint(&mut self, fingerprint: &str) -> Result<(), Box<dyn Error>>;
    fn unblock_tcp_fingerprint(&mut self, fingerprint: &str) -> Result<(), Box<dyn Error>>;
    fn block_tcp_fingerprint_v6(&mut self, fingerprint: &str) -> Result<(), Box<dyn Error>>;
    fn unblock_tcp_fingerprint_v6(&mut self, fingerprint: &str) -> Result<(), Box<dyn Error>>;
    fn is_tcp_fingerprint_blocked(&self, fingerprint: &str) -> Result<bool, Box<dyn Error>>;
    fn is_tcp_fingerprint_blocked_v6(&self, fingerprint: &str) -> Result<bool, Box<dyn Error>>;
}

pub struct MOATFirewall<'a> {
    skel: &'a crate::bpf::FilterSkel<'a>,
}

impl<'a> MOATFirewall<'a> {
    pub fn new(skel: &'a crate::bpf::FilterSkel<'a>) -> Self {
        Self { skel }
    }

    /// Convert a fingerprint string to a 14-byte array for BPF map
    /// Fingerprint format is typically: "TTL:MSS:Window:Scale" (e.g., "064:1460:65535:7")
    /// This is truncated/padded to exactly 14 bytes
    fn fingerprint_to_bytes(fingerprint: &str) -> Result<[u8; 14], Box<dyn Error>> {
        let mut bytes = [0u8; 14];
        let fp_bytes = fingerprint.as_bytes();
        
        // Copy up to 14 bytes
        let copy_len = std::cmp::min(fp_bytes.len(), 14);
        bytes[..copy_len].copy_from_slice(&fp_bytes[..copy_len]);
        
        Ok(bytes)
    }
}

impl<'a> Firewall for MOATFirewall<'a> {
    fn ban_ip_with_notice(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.skel
            .maps
            .recently_banned_ips
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn ban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.skel
            .maps
            .banned_ips
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn check_if_notice(&mut self, ip: Ipv4Addr) -> Result<bool, Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, 32);

        if let Some(val) = self
            .skel
            .maps
            .recently_banned_ips
            .lookup(ip_bytes, MapFlags::ANY)?
        {
            if val[0] == 1_u8 {
                return Ok(true);
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn unban_ip(&mut self, ip: Ipv4Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ip_into_bpf_map_key_bytes(ip, prefixlen);

        self.skel.maps.banned_ips.delete(ip_bytes)?;

        Ok(())
    }

    // IPv6 implementations
    fn ban_ipv6_with_notice(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ipv6_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.skel
            .maps
            .recently_banned_ips_v6
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn ban_ipv6(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ipv6_into_bpf_map_key_bytes(ip, prefixlen);
        let flag = 1_u8;

        self.skel
            .maps
            .banned_ips_v6
            .update(ip_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        Ok(())
    }

    fn check_if_notice_ipv6(&mut self, ip: Ipv6Addr) -> Result<bool, Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ipv6_into_bpf_map_key_bytes(ip, 128);

        if let Some(val) = self
            .skel
            .maps
            .recently_banned_ips_v6
            .lookup(ip_bytes, MapFlags::ANY)?
        {
            if val[0] == 1_u8 {
                return Ok(true);
            } else {
                return Ok(false);
            }
        }

        Ok(true)
    }

    fn unban_ipv6(&mut self, ip: Ipv6Addr, prefixlen: u32) -> Result<(), Box<dyn Error>> {
        let ip_bytes = &bpf_utils::convert_ipv6_into_bpf_map_key_bytes(ip, prefixlen);

        self.skel.maps.banned_ips_v6.delete(ip_bytes)?;

        Ok(())
    }

    fn block_tcp_fingerprint(&mut self, fingerprint: &str) -> Result<(), Box<dyn Error>> {
        let fp_bytes = Self::fingerprint_to_bytes(fingerprint)?;
        let flag = 1_u8;

        self.skel
            .maps
            .blocked_tcp_fingerprints
            .update(&fp_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        log::info!("Blocked TCP fingerprint (IPv4): {}", fingerprint);
        Ok(())
    }

    fn unblock_tcp_fingerprint(&mut self, fingerprint: &str) -> Result<(), Box<dyn Error>> {
        let fp_bytes = Self::fingerprint_to_bytes(fingerprint)?;

        self.skel
            .maps
            .blocked_tcp_fingerprints
            .delete(&fp_bytes)?;

        log::info!("Unblocked TCP fingerprint (IPv4): {}", fingerprint);
        Ok(())
    }

    fn block_tcp_fingerprint_v6(&mut self, fingerprint: &str) -> Result<(), Box<dyn Error>> {
        let fp_bytes = Self::fingerprint_to_bytes(fingerprint)?;
        let flag = 1_u8;

        self.skel
            .maps
            .blocked_tcp_fingerprints_v6
            .update(&fp_bytes, &flag.to_le_bytes(), MapFlags::ANY)?;

        log::info!("Blocked TCP fingerprint (IPv6): {}", fingerprint);
        Ok(())
    }

    fn unblock_tcp_fingerprint_v6(&mut self, fingerprint: &str) -> Result<(), Box<dyn Error>> {
        let fp_bytes = Self::fingerprint_to_bytes(fingerprint)?;

        self.skel
            .maps
            .blocked_tcp_fingerprints_v6
            .delete(&fp_bytes)?;

        log::info!("Unblocked TCP fingerprint (IPv6): {}", fingerprint);
        Ok(())
    }

    fn is_tcp_fingerprint_blocked(&self, fingerprint: &str) -> Result<bool, Box<dyn Error>> {
        let fp_bytes = Self::fingerprint_to_bytes(fingerprint)?;

        if let Some(val) = self
            .skel
            .maps
            .blocked_tcp_fingerprints
            .lookup(&fp_bytes, MapFlags::ANY)?
        {
            if val[0] == 1_u8 {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn is_tcp_fingerprint_blocked_v6(&self, fingerprint: &str) -> Result<bool, Box<dyn Error>> {
        let fp_bytes = Self::fingerprint_to_bytes(fingerprint)?;

        if let Some(val) = self
            .skel
            .maps
            .blocked_tcp_fingerprints_v6
            .lookup(&fp_bytes, MapFlags::ANY)?
        {
            if val[0] == 1_u8 {
                return Ok(true);
            }
        }

        Ok(false)
    }
}
