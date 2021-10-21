use flume::Sender;

mod js;

#[derive(Debug)]
pub enum Value {
    String(String),
}

impl Value {
    pub fn to_string(&self) -> String {
        match self {
            Value::String(s) => s.clone(),
        }
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

pub enum Commands {
    Resolve(u32, String), //resolver, value
    Run(String, Sender<()>),
}

#[derive(Debug)]
pub enum Events {
    NativeCode(u32, String, Vec<Value>), // resolver, function, arguments
}

pub struct Script {
    pub sender: Sender<Commands>,
}

impl Script {
    pub async fn send_async(&mut self, cmd: Commands) {
        self.sender.send_async(cmd).await;
    }
}

pub fn start(sender: flume::Sender<Events>) -> Script {
    let sender = js::JavascriptEngine::spawn(sender);
    Script { sender }
}
