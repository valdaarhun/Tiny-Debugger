use nix::sys::{ptrace, signal::{kill, Signal::{SIGINT}}};
use nix::sys::{wait::waitpid};
use nix::sys::personality;
use nix::unistd::{execvp, fork, ForkResult, Pid};
use std::collections::HashMap;
use std::{env, mem};
use std::ffi::{c_void, CString};
use std::process::exit;
use linenoise;

const INT3: i64 = 0xcc;
const REGISTER_COUNT: i32 = 27;

// See: /usr/include/x86_64-linux-gnu/sys/user.h
#[allow(non_camel_case_types)]
enum Register{
    r15, r14, r13, r12,
    rbp, rbx, r11, r10,
    r9, r8, rax, rcx,
    rdx, rsi, rdi,
    orig_rax, rip, cs,
    eflags, rsp, ss,
    fs_base, gs_base,
    ds, es, fs, gs
}

struct RegDescriptor{
    reg: Register,
    dwarf_reg_no: i32,
    reg_name: &'static str,
}

// For DWARF register number mapping, see: https://www.uclibc.org/docs/psABI-x86_64.pdf
// -1 indicates the register has no register number
const REG_DWARF_MAP: [RegDescriptor; 27] = [
    RegDescriptor{reg: Register::r15, dwarf_reg_no: 15, reg_name: "r15"},
    RegDescriptor{reg: Register::r14, dwarf_reg_no: 14, reg_name: "r14"},
    RegDescriptor{reg: Register::r13, dwarf_reg_no: 13, reg_name: "r13"},
    RegDescriptor{reg: Register::r12, dwarf_reg_no: 12, reg_name: "r12"},
    RegDescriptor{reg: Register::rbp, dwarf_reg_no: 6, reg_name: "rbp"},
    RegDescriptor{reg: Register::rbx, dwarf_reg_no: 3, reg_name: "rbx"},
    RegDescriptor{reg: Register::r11, dwarf_reg_no: 11, reg_name: "r11"},
    RegDescriptor{reg: Register::r10, dwarf_reg_no: 10, reg_name: "r10"},
    RegDescriptor{reg: Register::r9, dwarf_reg_no: 9, reg_name: "r9"},
    RegDescriptor{reg: Register::r8, dwarf_reg_no: 8, reg_name: "r8"},
    RegDescriptor{reg: Register::rax, dwarf_reg_no: 0, reg_name: "rax"},
    RegDescriptor{reg: Register::rcx, dwarf_reg_no: 2, reg_name: "rcx"},
    RegDescriptor{reg: Register::rdx, dwarf_reg_no: 1, reg_name: "rdx"},
    RegDescriptor{reg: Register::rsi, dwarf_reg_no: 4, reg_name: "rsi"},
    RegDescriptor{reg: Register::rdi, dwarf_reg_no: 5, reg_name: "rdi"},
    RegDescriptor{reg: Register::orig_rax, dwarf_reg_no: -1, reg_name: "orig_rax"},
    RegDescriptor{reg: Register::rip, dwarf_reg_no: -1, reg_name: "rip"},
    RegDescriptor{reg: Register::cs, dwarf_reg_no: 51, reg_name: "cs"},
    RegDescriptor{reg: Register::eflags, dwarf_reg_no: -1, reg_name: "eflags"},
    RegDescriptor{reg: Register::rsp, dwarf_reg_no: 7, reg_name: "rsp"},
    RegDescriptor{reg: Register::ss, dwarf_reg_no: 52, reg_name: "ss"},
    RegDescriptor{reg: Register::fs_base, dwarf_reg_no: 58, reg_name: "fs_base"},
    RegDescriptor{reg: Register::gs_base, dwarf_reg_no: 59, reg_name: "gs_base"},
    RegDescriptor{reg: Register::ds, dwarf_reg_no: 53, reg_name: "ds"},
    RegDescriptor{reg: Register::es, dwarf_reg_no: 50, reg_name: "es"},
    RegDescriptor{reg: Register::fs, dwarf_reg_no: 54, reg_name: "fs"},
    RegDescriptor{reg: Register::gs, dwarf_reg_no: 55, reg_name: "gs"},
];

fn vector_of_string_to_vector_of_cstring(args: &Vec<String>) -> Vec<CString> {
    args.iter().map(|arg| CString::new(arg.clone()).unwrap()).collect::<Vec<CString>>()
}

struct Breakpoint{
    tracee_pid: Pid,
    addr: *mut c_void,
    saved_byte: u8,
    enabled: bool,
}

impl Breakpoint{
    fn create_new_breakpoint(tracee_pid: Pid, addr_ptr: *mut c_void) -> Breakpoint {
        let mut breakpoint = Breakpoint {
            tracee_pid: tracee_pid,
            addr: addr_ptr,
            saved_byte: 0,
            enabled: true,
        };
        breakpoint.enable();
        println!("{:?}", breakpoint.saved_byte);
        breakpoint
    }

    fn enable(&mut self){
        let word = ptrace::read(self.tracee_pid, self.addr).expect("Failed to peek data at address");
        self.saved_byte = (word & 0xff) as u8;
        let word_ptr = unsafe { mem::transmute::<i64, *mut c_void>((word & !0xff) | INT3) }; // 0xcc => trap for breakpoint
        unsafe { ptrace::write(self.tracee_pid, self.addr, word_ptr).expect("Failed to poke data at address") };
        self.enabled = true;
        println!("{:?}", self.saved_byte);
    }

    fn disable(&mut self){
        let word = ptrace::read(self.tracee_pid, self.addr).expect("Failed to peek data at address");
        let word_ptr = unsafe { mem::transmute::<i64, *mut c_void>((word & !0xff) | self.saved_byte as i64) };
        unsafe { ptrace::write(self.tracee_pid, self.addr, word_ptr).expect("Failed to poke data at address") };
        self.enabled = false;
        println!("{:?}", self.saved_byte);
    }

    fn toggle_breakpoint(&mut self){
        println!("Toggling");
        if self.enabled {
            self.disable();
        }
        else{
            self.enable();
        }
    }
}

struct Debugger{
    tracee_pid: Pid,
    prog_name: String, // Maybe change to reference to string later
    breakpoints: HashMap< *mut c_void, Breakpoint >,
}

impl Debugger{
    fn run(&mut self){
        waitpid(self.tracee_pid, None).unwrap();

        loop {
            let comm = linenoise::input("(dbg) >> ");
            match comm {
                Some(command) => self.handle_command(command),
                None => {}
            }
        }
    }

    fn handle_command(&mut self, command: String){
        let command = command.split(' ').collect::<Vec<&str>>();
        match command[0] {
            "break" => {
                match command.len() {
                    2 => self.handle_breakpoint(command[1]),
                    _ => eprintln!("USAGE: break [address in hex]"),                    
                }
            }
            "continue" => {
                match command.len() {
                    1 => self.continue_tracee(),
                    _ => eprintln!("USAGE: continue"),
                }
            }
            "exit" | "quit" => {
                match command.len() {
                    1 => self.quit(),
                    _ => {
                        eprintln!("USAGE: quit");
                        eprintln!("       exit");
                    }
                }
            }
            _ => eprintln!("Unknown command"),
        }
    }

    fn handle_breakpoint(&mut self, mut addr: &str) {
        addr = match addr.strip_prefix("0x") {
            Some(addr) => addr,
            None => addr,
        };

        let addr_ptr = unsafe{ mem::transmute::<u64, *mut c_void>(u64::from_str_radix(addr, 16).unwrap()) };

        match self.breakpoints.get(&addr_ptr){
            Some(_breakpoint) => println!("Breakpoint exists"),
            None => println!("Nothing"),
        }

        self.breakpoints.entry(addr_ptr)
                        .and_modify(|breakpoint| (*breakpoint).toggle_breakpoint())
                        .or_insert_with(|| Breakpoint::create_new_breakpoint(self.tracee_pid, addr_ptr));
    }

    fn continue_tracee(&self){
        ptrace::cont(self.tracee_pid, None).expect("Failed to resume execution of tracee");
        waitpid(self.tracee_pid, None).unwrap();
    }

    fn quit(&self){
        match kill(self.tracee_pid, SIGINT) {
            Ok(()) => {},
            Err(_) => {},
        }
        exit(0);
    }
}

fn disable_aslr(){
    let pers = personality::get().unwrap();
    personality::set(pers | personality::Persona::ADDR_NO_RANDOMIZE).unwrap();
}

fn main(){
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 0 {
        println!("USAGE: rustdbg [prog]");
        return;
    }

    match unsafe{ fork() } {
        Ok(ForkResult::Parent { child }) => {
            println!("Process with pid {} spawned!", child);

            let mut dbg = Debugger {
                tracee_pid: child,
                prog_name: args[0].clone(),
                breakpoints: HashMap::new(),
            };
            dbg.run();
        }
        Ok(ForkResult::Child) => {
            println!("Debugging {:?}", args[0]);
            disable_aslr();
            ptrace::traceme().expect("Can't trace prog");
            let args_cstr = vector_of_string_to_vector_of_cstring(&args);
            execvp(&args_cstr[0], &args_cstr).expect("Failed to execute \"{filename}\"");
        }
        Err(_) => println!("Error forking process")
    }
}
