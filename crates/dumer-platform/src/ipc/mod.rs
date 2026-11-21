//! Secure local IPC over Windows Named Pipes.
//!
//! Enforces:
//! - Anti-squatting via `FILE_FLAG_FIRST_PIPE_INSTANCE`
//! - Restrictive DACL
//! - Same-user peer verification (PID and SID matching)
//! - Length-prefixed deterministic CBOR framing
//! - Timeout guards on connect and read/write

use ciborium::{from_reader, into_writer};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_MORE_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, RevertToSelf, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    ImpersonateNamedPipeClient, WaitNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

use crate::error::PlatformError;
use crate::traits::Platform;
use crate::types::{LaunchResult, LockState, Notification, SystemBasicStatus};

const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x00080000;
const MAX_IPC_FRAME_SIZE: usize = 65536;

/// Versioned IPC request frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformIpcRequest {
    pub v: u32,
    pub request_id: [u8; 16],
    pub command: PlatformIpcCommand,
}

/// Typed platform operations dispatched over IPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "cmd", content = "args", rename_all = "snake_case")]
pub enum PlatformIpcCommand {
    LaunchApp { app_id: String, args: Vec<String> },
    GetBasicStatus,
    Notify(Notification),
    GetLockState,
}

/// Versioned IPC response frame.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlatformIpcResponse {
    pub v: u32,
    pub request_id: [u8; 16],
    pub result: Result<PlatformIpcSuccess, String>,
}

/// Successful platform IPC command response payloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "res", content = "data", rename_all = "snake_case")]
pub enum PlatformIpcSuccess {
    Launched(LaunchResult),
    Status(SystemBasicStatus),
    Notified,
    Lock(LockState),
}

/// Helper function to read a length-prefixed frame from a Windows handle.
fn read_frame(handle: HANDLE) -> Result<Vec<u8>, PlatformError> {
    let mut len_bytes = [0u8; 4];
    let mut bytes_read = 0u32;

    // SAFETY: ReadFile reads into local 4-byte buffer.
    let success = unsafe {
        ReadFile(
            handle,
            len_bytes.as_mut_ptr(),
            4,
            &mut bytes_read,
            std::ptr::null_mut(),
        )
    };

    if success == 0 || bytes_read != 4 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::IpcError(format!(
            "Failed to read 4-byte frame length: error {}",
            err
        )));
    }

    let frame_len = u32::from_be_bytes(len_bytes) as usize;
    if frame_len == 0 || frame_len > MAX_IPC_FRAME_SIZE {
        return Err(PlatformError::IpcError(format!(
            "Invalid frame length {} (cap is {})",
            frame_len, MAX_IPC_FRAME_SIZE
        )));
    }

    let mut buf = vec![0u8; frame_len];
    let mut total_read = 0;
    while total_read < frame_len {
        let mut n = 0u32;
        // SAFETY: ReadFile reads up to remaining bytes into pre-allocated buffer slice.
        let ok = unsafe {
            ReadFile(
                handle,
                buf[total_read..].as_mut_ptr(),
                (frame_len - total_read) as u32,
                &mut n,
                std::ptr::null_mut(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            if err == ERROR_MORE_DATA {
                total_read += n as usize;
                continue;
            }
            return Err(PlatformError::IpcError(format!(
                "Failed to read frame payload: error {}",
                err
            )));
        }

        if n == 0 {
            return Err(PlatformError::IpcError(
                "Unexpected EOF reading frame payload".to_string(),
            ));
        }

        total_read += n as usize;
    }

    Ok(buf)
}

/// Helper function to write a length-prefixed frame to a Windows handle.
fn write_frame(handle: HANDLE, data: &[u8]) -> Result<(), PlatformError> {
    if data.is_empty() || data.len() > MAX_IPC_FRAME_SIZE {
        return Err(PlatformError::IpcError(format!(
            "Invalid frame length {} to write",
            data.len()
        )));
    }

    let len_bytes = (data.len() as u32).to_be_bytes();
    let mut bytes_written = 0u32;

    // SAFETY: WriteFile writes length prefix.
    let ok = unsafe {
        WriteFile(
            handle,
            len_bytes.as_ptr(),
            4,
            &mut bytes_written,
            std::ptr::null_mut(),
        )
    };

    if ok == 0 || bytes_written != 4 {
        let err = unsafe { GetLastError() };
        return Err(PlatformError::IpcError(format!(
            "Failed to write frame length: error {}",
            err
        )));
    }

    let mut total_written = 0;
    while total_written < data.len() {
        let mut n = 0u32;
        // SAFETY: WriteFile writes payload bytes.
        let ok = unsafe {
            WriteFile(
                handle,
                data[total_written..].as_ptr(),
                (data.len() - total_written) as u32,
                &mut n,
                std::ptr::null_mut(),
            )
        };

        if ok == 0 {
            let err = unsafe { GetLastError() };
            return Err(PlatformError::IpcError(format!(
                "Failed to write frame payload: error {}",
                err
            )));
        }

        total_written += n as usize;
    }

    Ok(())
}

/// Verifies that the connected named pipe client belongs to the same user SID as the server process.
unsafe fn verify_peer_credentials(pipe: HANDLE) -> Result<(), PlatformError> {
    let mut client_pid = 0u32;
    if GetNamedPipeClientProcessId(pipe, &mut client_pid) == 0 {
        return Err(PlatformError::PeerVerificationFailed(
            "Could not query client process ID".to_string(),
        ));
    }

    if ImpersonateNamedPipeClient(pipe) == 0 {
        return Err(PlatformError::PeerVerificationFailed(
            "ImpersonateNamedPipeClient failed".to_string(),
        ));
    }

    let mut client_token: HANDLE = std::ptr::null_mut();
    let open_thread_res = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut client_token);

    if open_thread_res == 0 {
        let _ = RevertToSelf();
        return Err(PlatformError::PeerVerificationFailed(
            "OpenThreadToken failed".to_string(),
        ));
    }

    let mut server_token: HANDLE = std::ptr::null_mut();
    let open_proc_res = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut server_token);
    if open_proc_res == 0 {
        CloseHandle(client_token);
        let _ = RevertToSelf();
        return Err(PlatformError::PeerVerificationFailed(
            "OpenProcessToken failed".to_string(),
        ));
    }

    #[repr(align(8))]
    struct AlignedBuffer([u8; 256]);

    let mut client_user_buf = AlignedBuffer([0u8; 256]);
    let mut client_ret_len = 0u32;
    let get_client_info = GetTokenInformation(
        client_token,
        TokenUser,
        client_user_buf.0.as_mut_ptr() as *mut _,
        client_user_buf.0.len() as u32,
        &mut client_ret_len,
    );

    let mut server_user_buf = AlignedBuffer([0u8; 256]);
    let mut server_ret_len = 0u32;
    let get_server_info = GetTokenInformation(
        server_token,
        TokenUser,
        server_user_buf.0.as_mut_ptr() as *mut _,
        server_user_buf.0.len() as u32,
        &mut server_ret_len,
    );

    CloseHandle(client_token);
    CloseHandle(server_token);
    let _ = RevertToSelf();

    if get_client_info == 0 || get_server_info == 0 {
        return Err(PlatformError::PeerVerificationFailed(
            "GetTokenInformation failed".to_string(),
        ));
    }

    let client_user = &*(client_user_buf.0.as_ptr() as *const TOKEN_USER);
    let server_user = &*(server_user_buf.0.as_ptr() as *const TOKEN_USER);

    if EqualSid(client_user.User.Sid, server_user.User.Sid) == 0 {
        return Err(PlatformError::PeerVerificationFailed(
            "Client SID does not match server process SID".to_string(),
        ));
    }

    debug!(client_pid = client_pid, "Named pipe peer identity verified");
    Ok(())
}

/// Local Named Pipe server hosting platform operations.
pub struct PlatformIpcServer {
    pipe_handle: HANDLE,
    pipe_name: String,
    platform: Arc<dyn Platform>,
}

unsafe impl Send for PlatformIpcServer {}
unsafe impl Sync for PlatformIpcServer {}

impl std::fmt::Debug for PlatformIpcServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformIpcServer")
            .field("pipe_name", &self.pipe_name)
            .finish()
    }
}

impl PlatformIpcServer {
    /// Binds a new exclusive instance of the named pipe.
    ///
    /// Passes `FILE_FLAG_FIRST_PIPE_INSTANCE` to guarantee anti-squatting defense.
    pub fn bind(pipe_name: &str, platform: Arc<dyn Platform>) -> Result<Self, PlatformError> {
        let wide_name: Vec<u16> = OsStr::new(pipe_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE;
        let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;
        let max_instances = 1;
        let out_buffer_size = 65536;
        let in_buffer_size = 65536;
        let default_timeout = 5000;

        // SAFETY: CreateNamedPipeW is called with exclusive first-instance flag and valid parameters.
        let handle = unsafe {
            CreateNamedPipeW(
                wide_name.as_ptr(),
                open_mode as FILE_FLAGS_AND_ATTRIBUTES,
                pipe_mode,
                max_instances,
                out_buffer_size,
                in_buffer_size,
                default_timeout,
                std::ptr::null_mut(),
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let err = unsafe { GetLastError() };
            if err == ERROR_ACCESS_DENIED || err == ERROR_ALREADY_EXISTS || err == ERROR_PIPE_BUSY {
                warn!(
                    pipe = %pipe_name,
                    error = err,
                    "Named pipe squatting attempt detected: pipe instance already exists"
                );
                return Err(PlatformError::PipeSquattingDetected);
            }
            return Err(PlatformError::OsError(format!(
                "CreateNamedPipeW failed: error {}",
                err
            )));
        }

        info!(pipe = %pipe_name, "Platform IPC named pipe bound successfully");
        Ok(Self {
            pipe_handle: handle,
            pipe_name: pipe_name.to_string(),
            platform,
        })
    }

    /// Returns the pipe name bound by this server instance.
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Serves a single incoming connection, validates peer SID/PID, processes request, and replies.
    pub fn serve_one(&mut self) -> Result<(), PlatformError> {
        // SAFETY: ConnectNamedPipe waits for client connection.
        unsafe {
            let connected = ConnectNamedPipe(self.pipe_handle, std::ptr::null_mut());
            if connected == 0 {
                let err = GetLastError();
                if err != ERROR_PIPE_CONNECTED {
                    return Err(PlatformError::OsError(format!(
                        "ConnectNamedPipe failed: error {}",
                        err
                    )));
                }
            }
        }

        // Read request frame
        let frame_bytes = match read_frame(self.pipe_handle) {
            Ok(b) => b,
            Err(e) => {
                unsafe {
                    let _ = DisconnectNamedPipe(self.pipe_handle);
                }
                return Err(e);
            }
        };

        // Verify peer credentials now that client has transmitted data
        unsafe {
            if let Err(e) = verify_peer_credentials(self.pipe_handle) {
                let _ = DisconnectNamedPipe(self.pipe_handle);
                return Err(e);
            }
        }

        let request: PlatformIpcRequest = match from_reader(&frame_bytes[..]) {
            Ok(req) => req,
            Err(e) => {
                unsafe {
                    let _ = DisconnectNamedPipe(self.pipe_handle);
                }
                return Err(PlatformError::IpcError(format!("CBOR decode error: {}", e)));
            }
        };

        // Dispatch typed command
        let res = match request.command {
            PlatformIpcCommand::LaunchApp { app_id, args } => self
                .platform
                .launch_registered_app(&app_id, &args)
                .map(PlatformIpcSuccess::Launched)
                .map_err(|e| e.to_string()),
            PlatformIpcCommand::GetBasicStatus => self
                .platform
                .basic_status()
                .map(PlatformIpcSuccess::Status)
                .map_err(|e| e.to_string()),
            PlatformIpcCommand::Notify(notification) => self
                .platform
                .notify(&notification)
                .map(|_| PlatformIpcSuccess::Notified)
                .map_err(|e| e.to_string()),
            PlatformIpcCommand::GetLockState => self
                .platform
                .lock_state()
                .map(PlatformIpcSuccess::Lock)
                .map_err(|e| e.to_string()),
        };

        let response = PlatformIpcResponse {
            v: 1,
            request_id: request.request_id,
            result: res,
        };

        let mut resp_bytes = Vec::new();
        if let Err(e) = into_writer(&response, &mut resp_bytes) {
            unsafe {
                let _ = DisconnectNamedPipe(self.pipe_handle);
            }
            return Err(PlatformError::IpcError(format!("CBOR encode error: {}", e)));
        }

        let write_res = write_frame(self.pipe_handle, &resp_bytes);
        unsafe {
            let _ = FlushFileBuffers(self.pipe_handle);
            let _ = DisconnectNamedPipe(self.pipe_handle);
        }
        write_res
    }
}

impl Drop for PlatformIpcServer {
    fn drop(&mut self) {
        if self.pipe_handle != INVALID_HANDLE_VALUE && !self.pipe_handle.is_null() {
            unsafe {
                CloseHandle(self.pipe_handle);
            }
        }
    }
}

/// Local Named Pipe client for interacting with the platform adapter.
pub struct PlatformIpcClient {
    pipe_handle: HANDLE,
    pipe_name: String,
}

unsafe impl Send for PlatformIpcClient {}
unsafe impl Sync for PlatformIpcClient {}

impl std::fmt::Debug for PlatformIpcClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlatformIpcClient")
            .field("pipe_name", &self.pipe_name)
            .finish()
    }
}

impl PlatformIpcClient {
    /// Connects to a named pipe server with a timeout guard.
    pub fn connect(pipe_name: &str, timeout_ms: u32) -> Result<Self, PlatformError> {
        let wide_name: Vec<u16> = OsStr::new(pipe_name)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let start = Instant::now();
        let timeout = Duration::from_millis(timeout_ms as u64);

        loop {
            // SAFETY: WaitNamedPipeW waits for an available named pipe instance.
            unsafe {
                let wait_ok = WaitNamedPipeW(wide_name.as_ptr(), 500);
                if wait_ok == 0 {
                    let err = GetLastError();
                    if err == ERROR_FILE_NOT_FOUND || err == ERROR_PIPE_BUSY {
                        if start.elapsed() >= timeout {
                            return Err(PlatformError::IpcError(format!(
                                "Timeout connecting to named pipe '{}'",
                                pipe_name
                            )));
                        }
                        std::thread::sleep(Duration::from_millis(50));
                        continue;
                    }
                }
            }

            // SAFETY: CreateFileW opens existing named pipe client handle.
            let handle = unsafe {
                CreateFileW(
                    wide_name.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE,
                    0 as FILE_SHARE_MODE,
                    std::ptr::null_mut(),
                    OPEN_EXISTING,
                    0 as FILE_FLAGS_AND_ATTRIBUTES,
                    std::ptr::null_mut(),
                )
            };

            if handle != INVALID_HANDLE_VALUE {
                return Ok(Self {
                    pipe_handle: handle,
                    pipe_name: pipe_name.to_string(),
                });
            }

            let err = unsafe { GetLastError() };
            if err == ERROR_PIPE_BUSY {
                if start.elapsed() >= timeout {
                    return Err(PlatformError::IpcError(format!(
                        "Timeout connecting to named pipe '{}'",
                        pipe_name
                    )));
                }
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }

            if start.elapsed() >= timeout {
                return Err(PlatformError::IpcError(format!(
                    "Failed to open named pipe '{}': error {}",
                    pipe_name, err
                )));
            }

            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Returns the pipe name targeted by this client.
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Dispatches a command and receives response with explicit request ID.
    pub fn dispatch(
        &self,
        request_id: [u8; 16],
        command: PlatformIpcCommand,
    ) -> Result<PlatformIpcSuccess, PlatformError> {
        let req = PlatformIpcRequest {
            v: 1,
            request_id,
            command,
        };

        let mut req_bytes = Vec::new();
        into_writer(&req, &mut req_bytes)
            .map_err(|e| PlatformError::IpcError(format!("CBOR encode error: {}", e)))?;

        write_frame(self.pipe_handle, &req_bytes)?;

        let resp_bytes = read_frame(self.pipe_handle)?;
        let resp: PlatformIpcResponse = from_reader(&resp_bytes[..])
            .map_err(|e| PlatformError::IpcError(format!("CBOR decode error: {}", e)))?;

        if resp.request_id != request_id {
            return Err(PlatformError::IpcError(
                "Response request_id does not match outgoing request_id".to_string(),
            ));
        }

        resp.result.map_err(PlatformError::OsError)
    }

    pub fn launch_registered_app_with_id(
        &self,
        request_id: [u8; 16],
        app_id: &str,
        args: &[String],
    ) -> Result<LaunchResult, PlatformError> {
        let res = self.dispatch(
            request_id,
            PlatformIpcCommand::LaunchApp {
                app_id: app_id.to_string(),
                args: args.to_vec(),
            },
        )?;
        match res {
            PlatformIpcSuccess::Launched(l) => Ok(l),
            other => Err(PlatformError::IpcError(format!(
                "Unexpected success payload: {:?}",
                other
            ))),
        }
    }
}

impl Platform for PlatformIpcClient {
    fn launch_registered_app(
        &self,
        app_id: &str,
        args: &[String],
    ) -> Result<LaunchResult, PlatformError> {
        let req_id = [1u8; 16];
        self.launch_registered_app_with_id(req_id, app_id, args)
    }

    fn basic_status(&self) -> Result<SystemBasicStatus, PlatformError> {
        let req_id = [2u8; 16];
        let res = self.dispatch(req_id, PlatformIpcCommand::GetBasicStatus)?;
        match res {
            PlatformIpcSuccess::Status(s) => Ok(s),
            other => Err(PlatformError::IpcError(format!(
                "Unexpected success payload: {:?}",
                other
            ))),
        }
    }

    fn notify(&self, notification: &Notification) -> Result<(), PlatformError> {
        let req_id = [3u8; 16];
        let res = self.dispatch(req_id, PlatformIpcCommand::Notify(notification.clone()))?;
        match res {
            PlatformIpcSuccess::Notified => Ok(()),
            other => Err(PlatformError::IpcError(format!(
                "Unexpected success payload: {:?}",
                other
            ))),
        }
    }

    fn lock_state(&self) -> Result<LockState, PlatformError> {
        let req_id = [4u8; 16];
        let res = self.dispatch(req_id, PlatformIpcCommand::GetLockState)?;
        match res {
            PlatformIpcSuccess::Lock(l) => Ok(l),
            other => Err(PlatformError::IpcError(format!(
                "Unexpected success payload: {:?}",
                other
            ))),
        }
    }
}

impl Drop for PlatformIpcClient {
    fn drop(&mut self) {
        if self.pipe_handle != INVALID_HANDLE_VALUE && !self.pipe_handle.is_null() {
            unsafe {
                CloseHandle(self.pipe_handle);
            }
        }
    }
}
