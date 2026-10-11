//! Kernel network isolation attached to each original socket. A fresh,
//! unregistered AppContainer identity denies local delivery even after the
//! originating thread reverts. The gateway still owns all destination policy.
//! No profile, privileged helper, address cache or socket-transfer protocol.
use crate::windows_security::Sid;
use socket2::{SockAddr, Socket};
use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::windows::io::{AsRawHandle, FromRawHandle, FromRawSocket, OwnedHandle};
use std::sync::OnceLock;
use windows_sys::Win32::Foundation::{CloseHandle, ERROR_NO_TOKEN, HANDLE};
use windows_sys::Win32::NetworkManagement::WindowsFirewall::NetworkIsolationGetAppContainerConfig;
use windows_sys::Win32::Networking::WinSock::*;
use windows_sys::Win32::Security::{
    EqualSid, ImpersonateLoggedOnUser, RevertToSelf, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
    TOKEN_DUPLICATE, TOKEN_QUERY, WinCapabilityInternetClientSid,
    WinCapabilityPrivateNetworkClientServerSid,
};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{GetProcessHeap, HeapFree};
use windows_sys::Win32::System::Services::*;
use windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows_sys::Win32::System::Threading::{
    ExitProcess, GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

struct NetworkIdentity {
    token: OwnedHandle,
    sid: Sid,
}
static IDENTITY: OnceLock<NetworkIdentity> = OnceLock::new();

// SAFETY: mandatory OS export with retained token, capability and output storage.
type CreateAppToken =
    unsafe extern "system" fn(HANDLE, *const SECURITY_CAPABILITIES, *mut HANDLE) -> i32;
// SAFETY: GetProcAddress's native representation, never called untyped.
type OsFunction = unsafe extern "system" fn() -> isize;

impl NetworkIdentity {
    fn create() -> io::Result<Self> {
        // Initialize Winsock outside the temporary security context. socket2
        // owns its process-wide startup reference, also used by the gateway.
        drop(Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?);
        let mut entropy = [0u8; 16];
        getrandom::getrandom(&mut entropy).map_err(io::Error::other)?;
        let name = format!(
            "snet-{}",
            entropy
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        );
        let sid = Sid::derive(&name)?;
        let internet = Sid::well_known(WinCapabilityInternetClientSid)?;
        let private = Sid::well_known(WinCapabilityPrivateNetworkClientServerSid)?;
        let mut capabilities = [
            SID_AND_ATTRIBUTES {
                Sid: internet.raw(),
                Attributes: SE_GROUP_ENABLED as u32,
            },
            SID_AND_ATTRIBUTES {
                Sid: private.raw(),
                Attributes: SE_GROUP_ENABLED as u32,
            },
        ];
        let security = SECURITY_CAPABILITIES {
            AppContainerSid: sid.raw(),
            Capabilities: capabilities.as_mut_ptr(),
            CapabilityCount: capabilities.len() as u32,
            Reserved: 0,
        };
        let module_name: Vec<u16> = "kernelbase.dll".encode_utf16().chain([0]).collect();
        // SAFETY: fixed already loaded OS module and fixed terminated export.
        let function = unsafe {
            let module = GetModuleHandleW(module_name.as_ptr());
            if module.is_null() {
                return Err(io::Error::last_os_error());
            }
            GetProcAddress(module, c"CreateAppContainerToken".as_ptr().cast())
        }
        .ok_or_else(|| unsupported("native AppContainer socket tokens are unavailable"))?;
        // SAFETY: this mandatory KernelBase export has the exact fixed ABI.
        let create = unsafe { std::mem::transmute::<OsFunction, CreateAppToken>(function) };
        let mut primary = std::ptr::null_mut();
        // SAFETY: self process only, read/duplicate rights, initialized output.
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE,
                &mut primary,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful allocation transfers sole ownership.
        let primary = unsafe { OwnedHandle::from_raw_handle(primary.cast()) };
        let mut restricted = std::ptr::null_mut();
        // SAFETY: original self token and retained immutable SID/capability inputs.
        if unsafe { create(primary.as_raw_handle().cast(), &security, &mut restricted) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if restricted.is_null() {
            return Err(unsupported("native socket token is absent"));
        }
        // SAFETY: successful token construction returned a new owned handle.
        let token = unsafe { OwnedHandle::from_raw_handle(restricted.cast()) };
        Ok(Self { token, sid })
    }

    fn socket(&self, ipv6: bool, udp: bool) -> io::Result<Socket> {
        let address = SockAddr::from(if ipv6 {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        });
        let mut ambient = std::ptr::null_mut();
        // SAFETY: original calling thread and a writable token handle output.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut ambient) } != 0 {
            // SAFETY: only the successful query allocated this handle.
            unsafe { CloseHandle(ambient) };
            return Err(unsupported(
                "socket admission requires an unimpersonated host thread",
            ));
        }
        if io::Error::last_os_error().raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
            return Err(io::Error::last_os_error());
        }
        // No Rust allocation, callbacks, filesystem access or error propagation
        // occurs between impersonation and restoration. Failure to restore is
        // fatal; no thread may continue with an unexpected security context.
        // SAFETY: retained self-derived token, fixed native socket role/bind.
        let (raw, error) = unsafe {
            if ImpersonateLoggedOnUser(self.token.as_raw_handle().cast()) == 0 {
                return Err(io::Error::last_os_error());
            }
            let raw = WSASocketW(
                if ipv6 { AF_INET6 } else { AF_INET } as i32,
                if udp { SOCK_DGRAM } else { SOCK_STREAM },
                if udp { IPPROTO_UDP } else { IPPROTO_TCP },
                std::ptr::null(),
                0,
                WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT,
            );
            let error = if raw == INVALID_SOCKET
                || bind(raw, address.as_ptr().cast(), address.len()) == SOCKET_ERROR
            {
                WSAGetLastError()
            } else {
                0
            };
            if RevertToSelf() == 0 {
                ExitProcess(70);
            }
            (raw, error)
        };
        if raw == INVALID_SOCKET {
            return Err(io::Error::from_raw_os_error(error));
        }
        // SAFETY: WSASocketW allocated exactly one unshared original socket.
        let socket = unsafe { Socket::from_raw_socket(raw as _) };
        if error != 0 {
            return Err(io::Error::from_raw_os_error(error));
        }
        socket.set_nonblocking(true)?;
        Ok(socket)
    }

    fn verify_boundary(&self) -> io::Result<()> {
        for name in ["BFE", "MpsSvc"] {
            require_service(name)?;
        }
        let mut count = 0;
        let mut entries = std::ptr::null_mut();
        // SAFETY: exact initialized native outputs; no host policy is modified.
        let status = unsafe { NetworkIsolationGetAppContainerConfig(&mut count, &mut entries) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let result = if count > 4096 || (count != 0 && entries.is_null()) {
            Err(unsupported(
                "native loopback exemption inventory exceeds bound",
            ))
        } else {
            let mut exempt = false;
            for index in 0..count as usize {
                // SAFETY: successful native API owns count initialized entries.
                let sid = unsafe { (*entries.add(index)).Sid };
                if sid.is_null() {
                    exempt = true;
                    break;
                }
                // SAFETY: both original SIDs remain retained for this comparison.
                exempt |= unsafe { EqualSid(sid, self.sid.raw()) } != 0;
            }
            if exempt {
                Err(unsupported(
                    "native socket identity has a loopback exemption",
                ))
            } else {
                Ok(())
            }
        };
        if !entries.is_null() {
            // SAFETY: this API allocates the native array and each SID from the
            // process heap. Free all OS-owned outputs, even on a rejected bound.
            unsafe {
                let heap = GetProcessHeap();
                for index in 0..count as usize {
                    HeapFree(heap, 0, (*entries.add(index)).Sid);
                }
                HeapFree(heap, 0, entries.cast());
            }
        }
        result
    }
}

struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        // SAFETY: uniquely owned successful SCM/service handle.
        unsafe { CloseServiceHandle(self.0) };
    }
}
fn require_service(name: &str) -> io::Result<()> {
    // SAFETY: local SCM, no database mutation or external input.
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(io::Error::last_os_error());
    }
    let manager = Service(manager);
    let name: Vec<u16> = name.encode_utf16().chain([0]).collect();
    // SAFETY: retained SCM and terminated fixed service name; query access only.
    let service = unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        return Err(io::Error::last_os_error());
    }
    let service = Service(service);
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut bytes = 0;
    // SAFETY: retained original service and exact initialized output structure.
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&raw mut status).cast(),
            size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut bytes,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if status.dwCurrentState != SERVICE_RUNNING {
        return Err(unsupported(
            "native firewall network-isolation service is not running",
        ));
    }
    Ok(())
}

/// Control-plane prerequisite check. Current firewall/exemption observations
/// are never cached as authority. Guest software cannot change host services.
pub fn probe() -> io::Result<()> {
    if IDENTITY.get().is_none() {
        let identity = NetworkIdentity::create()?;
        let _ = IDENTITY.set(identity);
    }
    IDENTITY
        .get()
        .expect("initialized original identity")
        .verify_boundary()
}

/// Same bounded admission contract as Unix, completed locally without an IPC
/// exchange. No service query or global configuration lookup is on this path.
pub struct SocketAdmission(Option<Socket>);
impl SocketAdmission {
    pub fn begin(ipv6: bool, udp: bool) -> io::Result<Self> {
        let identity = IDENTITY
            .get()
            .ok_or_else(|| unsupported("native socket boundary was not admitted"))?;
        Ok(Self(Some(identity.socket(ipv6, udp)?)))
    }
    pub fn poll(&mut self) -> io::Result<Option<Socket>> {
        self.0.take().map(Some).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "native receipt is already complete",
            )
        })
    }
}
fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
