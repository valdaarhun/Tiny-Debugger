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
            Some(breakpoint) => println!("Breakpoint exists"),
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
