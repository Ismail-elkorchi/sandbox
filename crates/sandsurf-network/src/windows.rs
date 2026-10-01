//! HCN native isolated endpoint ownership. Creation needs HCN setup privileges;
//! enforcement is an intrinsic private switch and endpoint ACL, never a guest
//! firewall. External routing and inbound forwarding are explicitly unsupported
//! until a packet gateway transport is implemented and qualified on Windows.
use sandsurf_protocol::{Exposure, NetworkPolicy};
use serde_json::{Value, json};
use std::ffi::c_void;
use std::io;
use std::ptr;
use windows_sys::core::GUID;

#[link(name = "computenetwork")]
// SAFETY: these declarations match the Windows HCN C ABI. Each call below
// supplies terminated UTF-16, live GUIDs and owned handle/output slots.
unsafe extern "system" {
    fn HcnCreateNetwork(
        id: *const GUID,
        settings: *const u16,
        network: *mut *mut c_void,
        error: *mut *mut u16,
    ) -> i32;
    fn HcnCreateEndpoint(
        network: *mut c_void,
        id: *const GUID,
        settings: *const u16,
        endpoint: *mut *mut c_void,
        error: *mut *mut u16,
    ) -> i32;
    fn HcnQueryNetworkProperties(
        network: *mut c_void,
        query: *const u16,
        properties: *mut *mut u16,
        error: *mut *mut u16,
    ) -> i32;
    fn HcnQueryEndpointProperties(
        endpoint: *mut c_void,
        query: *const u16,
        properties: *mut *mut u16,
        error: *mut *mut u16,
    ) -> i32;
    fn HcnCloseNetwork(network: *mut c_void) -> i32;
    fn HcnCloseEndpoint(endpoint: *mut c_void) -> i32;
    fn HcnDeleteNetwork(id: *const GUID, error: *mut *mut u16) -> i32;
    fn HcnDeleteEndpoint(id: *const GUID, error: *mut *mut u16) -> i32;
}
#[link(name = "ole32")]
// SAFETY: CoTaskMemFree uses the Windows allocator ABI and receives only the
// HCN-owned result pointers returned by that ABI, never Rust allocations.
unsafe extern "system" {
    fn CoTaskMemFree(memory: *const c_void);
}

pub struct IsolatedEndpoint {
    mac_address: String,
    network_id: GUID,
    endpoint_id: GUID,
    endpoint_text: String,
    network: *mut c_void,
    endpoint: *mut c_void,
}

impl IsolatedEndpoint {
    pub fn create(link: crate::LinkIdentity) -> io::Result<Self> {
        let (network_id, network_text) = identity()?;
        let (endpoint_id, endpoint_text) = identity()?;
        let document = wide(&network_document(&network_text).to_string());
        let mut network = ptr::null_mut();
        let mut error = ptr::null_mut();
        // SAFETY: live GUID/UTF-16 input and writable handle/error out pointers.
        let hr =
            unsafe { HcnCreateNetwork(&network_id, document.as_ptr(), &mut network, &mut error) };
        check(
            hr,
            error,
            "HCN private switch creation requires native setup privileges",
        )?;
        if network.is_null() {
            return Err(io::Error::other("HCN returned a null network handle"));
        }
        let mut owner = Self {
            network_id,
            endpoint_id,
            endpoint_text,
            network,
            endpoint: ptr::null_mut(),
            mac_address: link.mac_address().replace(':', "-"),
        };
        let installed = owner.query(false)?;
        if installed["Type"] != "Private"
            || installed["Flags"]
                .as_u64()
                .is_none_or(|flags| flags & 1024 == 0)
        {
            return Err(io::Error::other(
                "HCN did not retain the required isolated switch without a host port",
            ));
        }
        let document = wide(&endpoint_document(&network_text, &owner.mac_address).to_string());
        let mut error = ptr::null_mut();
        // SAFETY: owner retains network; GUID/input/out pointers are live.
        let hr = unsafe {
            HcnCreateEndpoint(
                owner.network,
                &owner.endpoint_id,
                document.as_ptr(),
                &mut owner.endpoint,
                &mut error,
            )
        };
        check(
            hr,
            error,
            "HCN isolated endpoint/default-deny ACL installation",
        )?;
        if owner.endpoint.is_null() {
            return Err(io::Error::other("HCN returned a null endpoint handle"));
        }
        let installed = owner.query(true)?;
        let policies = installed["Policies"]
            .as_array()
            .ok_or_else(|| io::Error::other("HCN did not retain endpoint policies"))?;
        for direction in ["In", "Out"] {
            if !policies.iter().any(|p| {
                p["Type"] == "ACL"
                    && p["Settings"]["Action"] == "Block"
                    && p["Settings"]["Direction"] == direction
                    && p["Settings"]["RuleType"] == "Switch"
            }) {
                return Err(io::Error::other(
                    "HCN did not retain the required default-deny switch ACL",
                ));
            }
        }
        if !policies.iter().any(|p| {
            p["Type"] == "QOS"
                && p["Settings"]["MaximumOutgoingBandwidthInBytes"]
                    .as_u64()
                    .is_some_and(|limit| limit > 0 && limit <= 8388608)
        }) {
            return Err(io::Error::other(
                "HCN did not retain the required endpoint bandwidth bound",
            ));
        }
        Ok(owner)
    }
    fn query(&self, endpoint: bool) -> io::Result<Value> {
        let query = wide(r#"{"SchemaVersion":{"Major":2,"Minor":0}}"#);
        let mut properties = ptr::null_mut();
        let mut error = ptr::null_mut();
        // SAFETY: this owner retains the native handle; query and out pointers
        // are live for the synchronous HCN call.
        let hr = unsafe {
            if endpoint {
                HcnQueryEndpointProperties(
                    self.endpoint,
                    query.as_ptr(),
                    &mut properties,
                    &mut error,
                )
            } else {
                HcnQueryNetworkProperties(self.network, query.as_ptr(), &mut properties, &mut error)
            }
        };
        let status = check(hr, error, "HCN isolation policy readback");
        let parsed = if status.is_ok() {
            native_json(properties)
        } else {
            status.map(|_| Value::Null)
        };
        if !properties.is_null() {
            // SAFETY: HCN documents CoTaskMemFree for this returned allocation.
            unsafe { CoTaskMemFree(properties.cast()) };
        }
        parsed
    }
    pub fn id(&self) -> &str {
        &self.endpoint_text
    }
    pub fn mac_address(&self) -> &str {
        &self.mac_address
    }
    pub fn configure(&self, policy: &NetworkPolicy, exposures: &[Exposure]) -> io::Result<()> {
        policy
            .validate()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        if !policy.rules.is_empty() || exposures.iter().any(|e| e.active) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows native isolated NIC supports deny only; external packet gateway and native inbound forwarding are unavailable",
            ));
        }
        // No connections can exist: the private switch has no host port,
        // physical adapter, NAT, route, or second machine endpoint.
        Ok(())
    }
}
impl Drop for IsolatedEndpoint {
    fn drop(&mut self) {
        // SAFETY: this owner alone closes the live handles. Deletion is by its
        // fresh GUIDs only; never discover/delete another machine's network.
        unsafe {
            if !self.endpoint.is_null() {
                let _ = HcnCloseEndpoint(self.endpoint);
                let mut error = ptr::null_mut();
                let hr = HcnDeleteEndpoint(&self.endpoint_id, &mut error);
                if let Err(e) = check(hr, error, "HCN endpoint deletion") {
                    eprintln!("{e}");
                }
            }
            if !self.network.is_null() {
                let _ = HcnCloseNetwork(self.network);
                let mut error = ptr::null_mut();
                let hr = HcnDeleteNetwork(&self.network_id, &mut error);
                if let Err(e) = check(hr, error, "HCN private switch deletion") {
                    eprintln!("{e}");
                }
            }
        }
    }
}
fn network_document(id: &str) -> Value {
    json!({
        "Name": format!("sandsurf-{id}"), "Type": "Private", "Flags": 1032,
        "Ipams": [{"Type": "Static", "Subnets": [{"IpAddressPrefix": "100.64.0.0/30"}]}],
        "SchemaVersion": {"Major": 2, "Minor": 0}
    })
}
fn endpoint_document(network: &str, mac_address: &str) -> Value {
    json!({
        "HostComputeNetwork": network, "MacAddress": mac_address,
        "IpConfigurations": [{"IpAddress": "100.64.0.2", "PrefixLength": 30}],
        "Policies": [
            {"Type": "ACL", "Settings": {"Action": "Block", "Direction": "Out", "RuleType": "Switch", "Priority": 100}},
            {"Type": "ACL", "Settings": {"Action": "Block", "Direction": "In", "RuleType": "Switch", "Priority": 100}},
            {"Type": "QOS", "Settings": {"MaximumOutgoingBandwidthInBytes": 8388608}}
        ],
        "SchemaVersion": {"Major": 2, "Minor": 0}
    })
}
fn identity() -> io::Result<(GUID, String)> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes).map_err(io::Error::other)?;
    bytes[6] = bytes[6] & 15 | 64;
    bytes[8] = bytes[8] & 63 | 128;
    let guid = GUID {
        data1: u32::from_be_bytes(bytes[..4].try_into().expect("fixed UUID")),
        data2: u16::from_be_bytes(bytes[4..6].try_into().expect("fixed UUID")),
        data3: u16::from_be_bytes(bytes[6..8].try_into().expect("fixed UUID")),
        data4: bytes[8..].try_into().expect("fixed UUID"),
    };
    let text = format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid.data1,
        guid.data2,
        guid.data3,
        guid.data4[0],
        guid.data4[1],
        guid.data4[2],
        guid.data4[3],
        guid.data4[4],
        guid.data4[5],
        guid.data4[6],
        guid.data4[7]
    );
    Ok((guid, text))
}
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}
fn native_json(pointer: *const u16) -> io::Result<Value> {
    if pointer.is_null() {
        return Err(io::Error::other("HCN isolation readback is absent"));
    }
    for len in 0..512 * 1024 {
        // SAFETY: HCN guarantees a valid NUL-terminated UTF-16 allocation.
        if unsafe { *pointer.add(len) } == 0 {
            // SAFETY: every unit in this prefix precedes the terminator in the
            // live HCN-owned allocation and the prefix length is bounded.
            let units = unsafe { std::slice::from_raw_parts(pointer, len) };
            let text = String::from_utf16(units).map_err(io::Error::other)?;
            return serde_json::from_str(&text).map_err(io::Error::other);
        }
    }
    Err(io::Error::other("HCN isolation readback exceeds its bound"))
}
fn check(hr: i32, error: *mut u16, operation: &str) -> io::Result<()> {
    if !error.is_null() {
        // SAFETY: HCN owns this allocation and documents CoTaskMemFree. Do not
        // parse or retain unbounded native diagnostic JSON.
        unsafe { CoTaskMemFree(error.cast()) };
    }
    if hr < 0 {
        Err(io::Error::other(format!("{operation}: HRESULT {hr:#x}")))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn isolated_switch_has_no_host_port_nat_or_physical_adapter() {
        let n = network_document("fixture");
        let e = endpoint_document("fixture", "26-F8-56-7F-25-69");
        assert_eq!(n["Type"], "Private");
        assert_eq!(n["Flags"], 1032);
        let encoded = format!("{n}{e}");
        for denied in [
            "OutboundNAT",
            "OutBoundNAT",
            "PortMapping",
            "NetAdapterName",
            "Routes",
        ] {
            assert!(!encoded.contains(denied));
        }
        assert_eq!(e["Policies"][0]["Settings"]["Action"], "Block");
        assert_eq!(e["Policies"][1]["Settings"]["Action"], "Block");
    }
}
