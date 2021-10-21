mod debugger;
mod helpers;
mod modules;
mod w32;
mod wow64;

use flume::*;

#[derive(Debug)]
pub enum Commands {
    Init(String, Sender<()>),
    Go(Sender<()>),
    AddBreakpoint(String, Sender<()>),
}

pub fn spawn(cmds: Receiver<Commands>) {
    let (s, r) = unbounded();

    let _ = std::thread::spawn(move || -> ! {
        let mut dbg = debugger::Debugger::new();
        loop {
            let cmd = r.recv();
            match cmd {
                Ok(Commands::Init(path, callback)) => {
                    dbg.start(path.as_str());
                    dbg.go();
                    callback.send(());
                }
                Ok(Commands::Go(callback)) => {
                    dbg.go();
                    callback.send(());
                }
                Ok(Commands::AddBreakpoint(at, callback)) => {
                    if let Ok(addr) = usize::from_str_radix(at.as_str(), 16) {
                        dbg.add_breakpoint_simple(addr);
                    } else {
                        dbg.add_breakpoint_symbol("", at.as_str());
                    }

                    callback.send(());
                }
                Err(E) => todo!(),
            }
        }
    });

    let _ = std::thread::spawn(move || loop {
        let cmd = cmds.recv();
        match cmd {
            Ok(c) => {
                s.send(c);
            }
            x @ Err(_) => todo!("{:?}", x),
        }
    });
}
