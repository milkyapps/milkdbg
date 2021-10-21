use super::helpers::*;
use super::modules::Modules;
use super::w32::*;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

use log::debug;
use log::trace;

#[derive(Clone, Debug)]
enum KnowCallValue {
    U32(u32),
    String(String),
}

#[derive(Clone, Debug)]
struct KnowCall {
    name: String,
    args: Vec<KnowCallValue>,
}

#[derive(Clone, Debug)]
enum KnownApiArgLocation {
    Memory(iced_x86::Register, isize),
}

fn get_register_value(ctx: winapi::um::winnt::WOW64_CONTEXT, register: &iced_x86::Register) -> u32 {
    match register {
        iced_x86::Register::ESP => ctx.Esp,
        _ => todo!(),
    }
}

#[derive(Clone, Debug)]
pub enum KnownApiArgType {
    U32,
    String,
}

#[derive(Clone, Debug)]
struct KnownApiArg {
    pub location: KnownApiArgLocation,
    t: KnownApiArgType,
    name: String,
}

impl KnownApiArg {
    pub fn get_value(
        &self,
        process: winapi::um::winnt::HANDLE,
        ctx: winapi::um::winnt::WOW64_CONTEXT,
    ) -> KnowCallValue {
        let addr = match &self.location {
            KnownApiArgLocation::Memory(register, offset) => {
                let addr = get_register_value(ctx, register);
                ((addr as isize) - offset) as usize
            }
        };

        match self.t {
            KnownApiArgType::U32 => KnowCallValue::U32(parse_at(addr, process).unwrap()),
            KnownApiArgType::String => {
                let addr: u32 = parse_at(addr, process).unwrap();
                KnowCallValue::String(read_string_char_by_char_unchecked(process, addr as usize).unwrap())
            },
        }
    }
}

#[derive(Clone, Debug)]
struct KnownApi {
    name: String,
    args: Vec<KnownApiArg>,
}

impl KnownApi {
    pub fn parse_know_call(
        &self,
        process: winapi::um::winnt::HANDLE,
        thread: winapi::um::winnt::HANDLE,
    ) -> KnowCall {
        let ctx = super::wow64::get_thread_context(thread).unwrap();
        KnowCall {
            name: self.name.clone(),
            args: self
                .args
                .iter()
                .map(|x| x.get_value(process, ctx))
                .collect(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct UnresolvedBreakpoint {
    symbol: String,
}

#[derive(Clone, Debug)]
pub enum Breakpoint {
    Simple {
        location: usize,
        original_value: Vec<u8>,
    },
    KnowApi {
        location: usize,
        original_value: Vec<u8>,
        api: KnownApi,
    },
}

pub struct Debugger {
    process: winapi::um::winnt::HANDLE,
    pid: usize,
    tid: usize,
    last_debug_event: winapi::um::minwinbase::DEBUG_EVENT,
    modules: Modules,

    breakpoints_locations: HashMap<usize, usize>,
    breakpoints: Vec<Breakpoint>,
    unresolved_breakpoints: Vec<UnresolvedBreakpoint>,
}

impl Debugger {
    pub fn new() -> Self {
        Self {
            process: std::ptr::null_mut(),
            pid: 0,
            tid: 0,
            last_debug_event: winapi::um::minwinbase::DEBUG_EVENT::default(),
            modules: Modules::new(),
            breakpoints_locations: HashMap::new(),
            breakpoints: Vec::new(),
            unresolved_breakpoints: Vec::new(),
        }
    }

    fn set_cc(&self, location: usize) -> Vec<u8> {
        let opcode = vec![0xcc];

        let original_value = read_process_memory(self.process, location, 1).unwrap();
        write_process_memory(self.process, location, opcode.as_slice()).unwrap();
        original_value
    }

    pub fn add_breakpoint_simple(&mut self, location: usize) {
        let original_value = self.set_cc(location);
        self.breakpoints_locations
            .insert(location, self.breakpoints.len());
        self.breakpoints.push(Breakpoint::Simple {
            location,
            original_value,
        });
    }

    pub fn add_breakpoint_knownapi(&mut self, location: usize, api: KnownApi) {
        let original_value = self.set_cc(location);

        self.breakpoints_locations
            .insert(location, self.breakpoints.len());
        self.breakpoints.push(Breakpoint::KnowApi {
            location,
            original_value,
            api,
        });
    }

    pub fn add_breakpoint_symbol(&mut self, _module: &str, symbol: &str) {
        self.unresolved_breakpoints.push(UnresolvedBreakpoint {
            symbol: symbol.to_string(),
        });
        self.try_resolve_breakpoints();
    }

    pub fn start(&mut self, path: &str) {
        let pe = milk_pe_parser::PE::parse(path).unwrap();
        let entry_point = pe.optional.get_address_of_entry_point().to_va(0x400000);

        let path = PathBuf::from_str(path).unwrap();
        let parent = path.parent().unwrap();
        let parent = parent.to_str().unwrap();

        let path = path.to_str().unwrap();
        let mut path = path.to_string();
        path.push('\0');

        let mut parent = parent.to_string();
        parent.push('\0');

        debug!(target:"debugger", "path: {:?}", path);
        debug!(target:"debugger", "working directory: {:?}", parent);

        unsafe {
            let mut startup_info: winapi::um::processthreadsapi::STARTUPINFOA = Default::default();
            let mut process_info: winapi::um::processthreadsapi::PROCESS_INFORMATION =
                Default::default();
            let _ = winapi::um::processthreadsapi::CreateProcessA(
                path.as_ptr() as *mut i8,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
                winapi::um::winbase::CREATE_SUSPENDED | winapi::um::winbase::DEBUG_PROCESS,
                std::ptr::null_mut(),
                parent.as_ptr() as *mut i8,
                &mut startup_info,
                &mut process_info,
            );

            self.process = process_info.hProcess;
            self.pid = process_info.dwProcessId as usize;
            self.tid = process_info.dwThreadId as usize;

            debug!(target:"debugger", "pid: {}", process_info.dwProcessId);
            debug!(target:"debugger", "tid: {}", process_info.dwThreadId);
            debug!(target:"debugger", "entrypoint at: 0x{:X?}", entry_point);
            // self.add_breakpoint_addr(entry_point);

            self.attach(self.pid);
            self.resume_tread(process_info.hThread);
        }
    }

    fn resume_tread(&self, thread: winapi::um::winnt::HANDLE) {
        debug!(target:"debugger", "Resuming Thread: {:?}", thread);
        unsafe {
            winapi::um::processthreadsapi::ResumeThread(thread);
        }
    }

    pub fn attach(&mut self, pid: usize) {
        trace!(target:"debugger", "attach - begin");

        self.pid = pid;
        let r = debug_active_process(self.pid);

        trace!(target:"debugger", "attach - end");
    }

    fn get_debug_event() -> Result<winapi::um::minwinbase::DEBUG_EVENT, u32> {
        trace!(target:"debugger", "get_debug_event - begin");
        let v = unsafe {
            let mut e: winapi::um::minwinbase::DEBUG_EVENT = Default::default();
            let r = winapi::um::debugapi::WaitForDebugEvent(&mut e, winapi::um::winbase::INFINITE);
            if r != 0 {
                Ok(e)
            } else {
                Err(winapi::um::errhandlingapi::GetLastError())
            }
        };
        trace!(target:"debugger", "get_debug_event - end");
        v
    }

    pub fn continue_debug_event(&self, pid: usize, tid: usize) {
        trace!(target:"debugger", "continue_debug_event - begin");
        unsafe {
            winapi::um::debugapi::ContinueDebugEvent(
                pid as u32,
                tid as u32,
                winapi::shared::ntstatus::DBG_CONTINUE as u32,
            );
        }
        trace!(target:"debugger", "continue_debug_event - end");
    }

    pub fn go(&mut self) {
        trace!(target:"debugger", "go - begin");

        loop {
            if self.last_debug_event.dwProcessId != 0 {
                self.continue_debug_event(
                    self.last_debug_event.dwProcessId as usize,
                    self.last_debug_event.dwThreadId as usize,
                );
            }

            let e = Self::get_debug_event();
            match e {
                Ok(e) => {
                    self.last_debug_event = e;
                    let tid = self.last_debug_event.dwThreadId;

                    use winapi::um::minwinbase::*;
                    match e.dwDebugEventCode {
                        CREATE_PROCESS_DEBUG_EVENT => {
                            let info = unsafe { e.u.CreateProcessInfo() };
                            self.process = info.hProcess;
                            // TODO: get pid
                            // TODO: get tid

                            let mut module_name =
                                read_string_char_by_char(info.hProcess, info.lpImageName as usize)
                                    .unwrap();
                            let path = PathBuf::from(get_final_path_name_by_handle(info.hFile));
                            if module_name.len() == 0 {
                                module_name =
                                    path.file_name().unwrap().to_str().unwrap().to_string();
                            }
                            let size = std::fs::metadata(&path).unwrap().len();

                            debug!(target:"debugger", "Process: {} at {:?}", module_name, path);

                            self.modules.process = Some(info.hProcess);
                            self.modules.load_module(
                                info.lpBaseOfImage as usize,
                                size as usize,
                                module_name.as_str(),
                            );
                            self.try_resolve_breakpoints();
                        }
                        CREATE_THREAD_DEBUG_EVENT => {}
                        EXCEPTION_DEBUG_EVENT => {
                            let info = unsafe { e.u.Exception() };

                            let code = info.ExceptionRecord.ExceptionCode;
                            let addr = info.ExceptionRecord.ExceptionAddress as usize;

                            match code {
                                EXCEPTION_ACCESS_VIOLATION => {
                                    panic!();
                                }
                                EXCEPTION_ARRAY_BOUNDS_EXCEEDED => {
                                    println!("\tEXCEPTION_ARRAY_BOUNDS_EXCEEDED")
                                }
                                EXCEPTION_BREAKPOINT | 1073741855 => {
                                    debug!(target:"debugger", "Breakpoint hit at 0x{:08X}", addr);

                                    let thread_handle = open_thread(
                                        OpenThreadAccess::GET_CONTEXT
                                            | OpenThreadAccess::SET_CONTEXT,
                                        false,
                                        tid,
                                    )
                                    .unwrap();

                                    if let Some(b) = self
                                        .breakpoints_locations
                                        .get(&addr)
                                        .and_then(|i| self.breakpoints.get(*i))
                                    {
                                        match b {
                                            Breakpoint::KnowApi {
                                                location,
                                                original_value,
                                                api,
                                            } => {
                                                let call = api
                                                    .parse_know_call(self.process, thread_handle);
                                                println!("Know Call: {:?}", call);
                                            }
                                            _ => {}
                                        }
                                    }

                                    break;
                                }
                                EXCEPTION_DATATYPE_MISALIGNMENT => {
                                    println!("\tEXCEPTION_DATATYPE_MISALIGNMENT")
                                }
                                EXCEPTION_DEBUG_EVENT => println!("\tEXCEPTION_DEBUG_EVENT"),
                                EXCEPTION_FLT_DENORMAL_OPERAND => {
                                    println!("\tEXCEPTION_FLT_DENORMAL_OPERAND")
                                }
                                EXCEPTION_FLT_DIVIDE_BY_ZERO => {
                                    println!("\tEXCEPTION_FLT_DIVIDE_BY_ZERO")
                                }
                                EXCEPTION_FLT_INEXACT_RESULT => {
                                    println!("\tEXCEPTION_FLT_INEXACT_RESULT")
                                }
                                EXCEPTION_FLT_INVALID_OPERATION => {
                                    println!("\tEXCEPTION_FLT_INVALID_OPERATION")
                                }
                                EXCEPTION_FLT_OVERFLOW => println!("\tEXCEPTION_FLT_OVERFLOW"),
                                EXCEPTION_FLT_STACK_CHECK => {
                                    println!("\tEXCEPTION_FLT_STACK_CHECK")
                                }
                                EXCEPTION_FLT_UNDERFLOW => println!("\tEXCEPTION_FLT_UNDERFLOW"),
                                EXCEPTION_GUARD_PAGE => println!("\tEXCEPTION_GUARD_PAGE"),
                                EXCEPTION_ILLEGAL_INSTRUCTION => {
                                    println!("\tEXCEPTION_ILLEGAL_INSTRUCTION")
                                }
                                EXCEPTION_INT_DIVIDE_BY_ZERO => {
                                    println!("\tEXCEPTION_INT_DIVIDE_BY_ZERO")
                                }
                                EXCEPTION_INT_OVERFLOW => println!("\tEXCEPTION_INT_OVERFLOW"),
                                EXCEPTION_INVALID_DISPOSITION => {
                                    println!("\tEXCEPTION_INVALID_DISPOSITION")
                                }
                                EXCEPTION_INVALID_HANDLE => println!("\tEXCEPTION_INVALID_HANDLE"),
                                EXCEPTION_IN_PAGE_ERROR => println!("\tEXCEPTION_IN_PAGE_ERROR"),
                                EXCEPTION_NONCONTINUABLE_EXCEPTION => {
                                    println!("\tEXCEPTION_NONCONTINUABLE_EXCEPTION")
                                }
                                EXCEPTION_POSSIBLE_DEADLOCK => {
                                    println!("\tEXCEPTION_POSSIBLE_DEADLOCK")
                                }
                                EXCEPTION_PRIV_INSTRUCTION => {
                                    println!("\tEXCEPTION_PRIV_INSTRUCTION")
                                }
                                EXCEPTION_SINGLE_STEP | 1073741854 => {
                                    // println!("\tEXCEPTION_SINGLE_STEP");
                                }
                                EXCEPTION_STACK_OVERFLOW => println!("\tEXCEPTION_STACK_OVERFLOw"),
                                winapi::um::winnt::DBG_CONTROL_C => println!("\tDBG_CONTROL_C"),
                                e @ _ => {
                                    panic!("Unkown exception code: {}", e);
                                }
                            }
                        }
                        EXIT_PROCESS_DEBUG_EVENT => {
                            debug!(target:"debugger", "EXIT_PROCESS_DEBUG_EVENT");
                            break;
                        }
                        EXIT_THREAD_DEBUG_EVENT => {
                            debug!(target:"debugger", "EXIT_THREAD_DEBUG_EVENT");
                        }
                        LOAD_DLL_DEBUG_EVENT => {
                            let info = unsafe { e.u.LoadDll() };

                            let imagename = unsafe {
                                let mut buffer = vec![0u8; 1024];
                                let r = winapi::um::fileapi::GetFinalPathNameByHandleA(
                                    info.hFile,
                                    buffer.as_mut_ptr() as *mut i8,
                                    1024,
                                    0,
                                );
                                String::from_utf8(buffer).unwrap()
                            };
                            let filesize = unsafe {
                                let mut size = 0u32;
                                winapi::um::fileapi::GetFileSize(info.hFile, &mut size);
                                size
                            };
                            debug!(target:"debugger", "Loading @ {:X?}: {}", info.lpBaseOfDll, imagename.as_str());

                            self.modules.load_module(
                                info.lpBaseOfDll as usize,
                                filesize as usize,
                                imagename.as_str(),
                            );
                            self.try_resolve_breakpoints();
                        }
                        OUTPUT_DEBUG_STRING_EVENT => {
                            debug!(target:"debugger", "OUTPUT_DEBUG_STRING_EVENT");
                        }
                        RIP_EVENT => {
                            debug!(target:"debugger", "RIP_EVENT");
                        }
                        UNLOAD_DLL_DEBUG_EVENT => {}
                        _ => {
                            debug!(target:"debugger", "Unknown debug event");
                        }
                    };
                }
                Err(_) => {
                    todo!();
                }
            };
        }
        trace!(target:"debugger", "go - end");
    }

    fn get_knowapi(&self, name: &str) -> Option<KnownApi> {
        if name == "CreateFileA" {
            Some(KnownApi {
                name: name.to_string(),
                args: vec![KnownApiArg {
                    location: KnownApiArgLocation::Memory(iced_x86::Register::ESP, -4),
                    name: "lpFileName".to_string(),
                    t: KnownApiArgType::String
                }],
            })
        } else {
            None
        }
    }

    fn try_resolve_breakpoints(&mut self) {
        let mut still_unresolved = vec![];
        let mut f = self.unresolved_breakpoints.clone();

        for b in f.drain(..) {
            let resolved = match self.modules.get_function_addr("", &b.symbol) {
                Some(addr) => {
                    debug!(target:"debugger", "Breakpoint {:?} at 0x{:X}", b.symbol, addr);

                    if let Some(api) = self
                        .modules
                        .get_function_at(addr)
                        .and_then(|info| self.get_knowapi(&info.name))
                    {
                        self.add_breakpoint_knownapi(addr, api)
                    } else {
                        self.add_breakpoint_simple(addr);
                    }
                    true
                }
                None => false,
            };

            if !resolved {
                still_unresolved.push(b);
            }
        }

        self.unresolved_breakpoints = still_unresolved;
    }
}
