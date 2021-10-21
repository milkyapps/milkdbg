#![feature(try_blocks)]
#![feature(concat_idents)]

mod debugger;
mod script;
use debugger::*;
use flume::*;
use log::debug;

async fn jsevent_to_dbgcmd(
    script: Sender<script::Commands>,
    script_events: Receiver<script::Events>,
    dbg: Sender<debugger::Commands>,
) {
    loop {
        let (s, r) = bounded(1);
        let msg = script_events.recv_async().await;
        debug!("jsevent_to_dbgcmd {:?}", msg);
        match msg {
            Ok(script::Events::NativeCode(resolver, f, arguments)) => {
                match f.as_str() {
                    "init" => {
                        let arg0 = arguments[0].to_string();
                        dbg.send(Commands::Init(arg0, s));
                    }
                    "go" => {
                        dbg.send(Commands::Go(s));
                    }
                    "addBreakpoint" => {
                        let arg0 = arguments[0].to_string();
                        dbg.send(Commands::AddBreakpoint(arg0, s));
                    }
                    _ => todo!(),
                }
                r.recv_async().await;
                script.send(script::Commands::Resolve(resolver, "hey!".to_string()));
            }
            Err(_) => todo!(),
        }
    }
}

#[async_std::main]
async fn main() {
    pretty_env_logger::init();

    let (jsevents_sender, jsevents_recv) = flume::unbounded();
    let (dbgcmd_sender, dbgcmd_recv) = flume::unbounded();

    debugger::spawn(dbgcmd_recv);
    let mut script = script::start(jsevents_sender);
    async_std::task::spawn(jsevent_to_dbgcmd(
        script.sender.clone(),
        jsevents_recv,
        dbgcmd_sender,
    ));

    let mut rl = rustyline::Editor::<()>::new();
    rl.load_history("history.txt");
    loop {
        let readline = rl.readline("> ");
        match readline {
            Ok(src) => {
                rl.add_history_entry(src.as_str());
                let (s, r) = bounded::<()>(1);
                script.send_async(script::Commands::Run(src, s)).await;
                r.recv_async().await;
            }
            Err(_) => break,
        }
    }
    rl.append_history("history.txt");
}
