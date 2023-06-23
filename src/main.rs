use nix::sys::{ptrace, signal::{kill, Signal::{SIGINT}}};
use nix::unistd::{execvp, fork, ForkResult, Pid};
use nix::wait::waitpid;
use std::collection::HashMap
use std::{env, mem};
use std::ffi::{c_void, CString};
use std::process::exit;
use linenoise;

fn vector_of_string_to_vector_of_cstring(args: &Vec<String>) -> Vec<CString> {
    args.iter().map(|arg| CString::new(arg.clone()).unwrap()).collect::<Vec<CString>>()
}

struct Debugger{
    tracee_pid: Pid,
    prog_name: String, // Maybe change to reference to string later
    // current_command: Vec<&str>
}

impl Debugger{
    fn run(&self){
        waitpid(self.tracee_pid, None).unwrap();

        loop {
            let comm = linenoise::input("(dbg) >> ");
            match comm {
                Some(command) => self.handle_command(command),
                None => {},
            }
        }
    }

    fn handle_command(&self, command: String){
        let command = command.split(' ').collect::<Vec<&str>>();
        match command[0] {
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

    fn continue_tracee(&self){
        ptrace::cont(self.tracee_pid, None).expect("Couldn't resume execution of tracee");
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

fn main(){
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() == 0 {
        println!("USAGE: rustdbg [prog]");
        return;
    }

    match unsafe{ fork() } {
        Ok(ForkResult::Parent { child }) => {
            println!("Process with pid {} spawned!", child);

            let dbg = Debugger {
                tracee_pid: child,
                prog_name: args[0].clone(),
            };
            dbg.run();
        }
        Ok(ForkResult::Child) => {
            println!("Debugging {:?}", args[0]);
            ptrace::traceme().expect("Can't trace prog");
            let args_cstr = vector_of_string_to_vector_of_cstring(&args);
            execvp(&args_cstr[0], &args_cstr).expect("Failed to execute \"{filename}\"");
        }
        Err(_) => println!("Error forking process")
    }
}
