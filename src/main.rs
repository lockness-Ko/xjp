extern crate thrussh;
extern crate thrussh_keys;
extern crate futures;
extern crate tokio;
use dotenv::dotenv;
use serde_json::{Value};
use std::sync::{Mutex, Arc};
use chrono::{DateTime, Utc};
use thrussh::*;
use thrussh::server::{Auth, Session, Response};
use thrussh_keys::key::PublicKey;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

static mut INCIDENT_COUNTER: usize = 0;

#[tokio::main]
async fn main() {
    dotenv().ok();
    
    let client_key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();
    let _client_pubkey = Arc::new(client_key.clone_public_key());

    let mut config = thrussh::server::Config::default();
    config.server_id = String::from("SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1");
    config.connection_timeout = Some(std::time::Duration::from_secs(30));
    config.auth_rejection_time = std::time::Duration::from_secs(0);
    config.keys.push(thrussh_keys::key::KeyPair::generate_ed25519().unwrap());
    let config = Arc::new(config);

    let sh = Server{
        _client_pubkey,
        clients: Arc::new(Mutex::new(HashMap::new())),
        incident: Incident {
            hash: 0,
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
            user: String::new(),
            pass: String::new(),
            request_type: RequestType::None
        },
        id: 0
    };
    // tokio::time::timeout(
    //    std::time::Duration::from_secs(10),
       
    // ).await.unwrap_or(Ok(()));
    thrussh::server::run(config, "0.0.0.0:2222", sh).await.unwrap();
}

#[derive(Clone, Debug)]
enum RequestType {
    DirectTcpIp(String, u32, String, u32),
    TcpIpForward(String, u32),
    X11(bool, String, String, u32),
    Pty(String, u32, u32, u32, u32),
    Env(String, String),
    Shell,
    Exec(String),
    None,
}

impl std::fmt::Display for RequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestType::Exec(_) => write!(f, "Exec"),
            RequestType::DirectTcpIp(_, _, _, _) => write!(f, "Direct Tcp/Ip"),
            RequestType::TcpIpForward(_, _) => write!(f, "Tcp/Ip Reverse Forward"),
            RequestType::X11(_, _, _, _) => write!(f, "X11"),
            RequestType::Pty(_, _, _, _, _) => write!(f, "Pty"),
            RequestType::Env(_, _) => write!(f, "Environment Variables"),
            RequestType::Shell => write!(f, "Shell"),
            RequestType::None => write!(f, "None")
        }
    }
}

#[derive(Clone, Debug)]
struct Incident {
    hash: u16,
    ip: std::net::IpAddr,
    port: u16,
    user: String,
    pass: String,
    request_type: RequestType
}

impl Incident {
    fn post(&self) {
        let data = format!(r#"
{{
  "content": null,
  "embeds": [
    {{
      "title": "Incident #{} | {}",
      "description": "**Connection Duration**\n{}\n**Times Connected**\n{}\n**Ip Country**\n{}\n\n[greynoise](https://viz.greynoise.io/ip/{})\n[ipinfo](https://ipinfo.io/{})\n[virustotal](https://www.virustotal.com/gui/ip-address/{})",
      "color": 14302011,
      "fields": [
        {{
            "name": "Credentials",
            "value": "`{}`:`{}`"
        }},
        {{
          "name": "Ip Address",
          "value": "{}"
        }},
        {{
          "name": "Port",
          "value": "{}"
        }},
        {}
      ],
      "author": {{
        "name": "{}"
      }}
    }}
  ],
  "attachments": []
}}
            "#, 
            unsafe { INCIDENT_COUNTER }, //incident number
            self.request_type, // request type
            0, //connection duration
            0, //times connected before
            "Romania", //ip country
            self.ip, //greynoise
            self.ip, //ipinfo
            self.ip, //virustotal
            self.user, // credentials
            self.pass, // credentials
            self.ip, //ip address
            self.port, //port
            match &self.request_type {
                RequestType::Exec(command) => format!(r#"
                {{
                  "name": "Command",
                  "value": "```bash\n{}\n```"
                }}"#, command),
                RequestType::DirectTcpIp(host2con, port2con, org_ip, org_port) => format!(r#"
                {{
                    "name": "Remote Host",
                    "value": "`{}`:`{}`"
                }},
                {{
                    "name": "Origin Host",
                    "value": "`{}`:`{}`"
                }}
                "#, host2con, port2con, org_ip, org_port),
                RequestType::Pty(term, cols, rows, pix_width, pix_height) => format!(r#"
                {{
                    "name": "Terminal",
                    "value": "{}"
                }},
                {{
                    "name": "Pty Size",
                    "value": "**Pixel Dimensions**\n{}x{}\n**Dimensions**\n{}x{}"
                }}
                "#, term, cols, rows, pix_width, pix_height),
                _ => String::new()
            }, // request type stats
            {
                let current_utc: DateTime<Utc> = Utc::now();
                current_utc
            } // iso datetime
        );
        let data = data.as_str();
        // println!("{}", data);
        
        let map: Value = serde_json::from_str(&data).unwrap();
        
        tokio::task::spawn_blocking(move || { 
            let client = reqwest::blocking::Client::new();
            let _res = client.post(std::env::var("DISCORD_WEBHOOK").unwrap())
                            .json(&map)
                            .send().unwrap();
            // println!("{}", res.text().unwrap());
        });
        
        unsafe {
            INCIDENT_COUNTER += 1;
        }
    }
}

#[derive(Clone)]
struct Server {
    _client_pubkey: Arc<thrussh_keys::key::PublicKey>,
    clients: Arc<Mutex<HashMap<(usize, ChannelId), thrussh::server::Handle>>>,
    incident: Incident,
    id: usize,
}

impl server::Server for Server {
    type Handler = Self;
    fn new(&mut self, sockaddr: Option<std::net::SocketAddr>) -> Self {
        let mut s = self.clone();
        self.id += 1;
        let sockaddr = sockaddr.unwrap();
        s.incident.ip = sockaddr.ip();
        s.incident.port = sockaddr.port();
        s
    }
}

impl server::Handler for Server {
    type Error = anyhow::Error;
    type FutureAuth = futures::future::Ready<Result<(Self, server::Auth), anyhow::Error>>;
    type FutureUnit = futures::future::Ready<Result<(Self, Session), anyhow::Error>>;
    type FutureBool = futures::future::Ready<Result<(Self, Session, bool), anyhow::Error>>;

    fn finished_auth(self, auth: Auth) -> Self::FutureAuth {
        futures::future::ready(Ok((self, auth)))
    }
    fn finished_bool(self, b: bool, s: Session) -> Self::FutureBool {
        futures::future::ready(Ok((self, s, b)))
    }
    fn finished(self, s: Session) -> Self::FutureUnit {
        futures::future::ready(Ok((self, s)))
    }
    fn channel_open_session(self, channel: ChannelId, session: Session) -> Self::FutureUnit {
        {
            let mut clients = self.clients.lock().unwrap();
            clients.insert((self.id, channel), session.handle());
        }
        self.finished(session)
    }

    fn auth_password(mut self, user: &str, pass: &str) -> Self::FutureAuth {
        self.incident.user = String::from(user);
        self.incident.pass = String::from(pass);
        self.finished_auth(server::Auth::Accept)
    }
    fn auth_publickey(mut self, user: &str, pubkey: &PublicKey) -> Self::FutureAuth {
        self.incident.user = String::from(user);
        self.incident.pass = pubkey.fingerprint();
        self.finished_auth(server::Auth::Accept)
    }
    fn auth_keyboard_interactive(mut self, user: &str, _submethods: &str, _response: Option<Response<'_>>) -> Self::FutureAuth {
        self.incident.user = String::from(user);
        self.incident.pass = String::from("AUTH_KEYBOARD_INTERACTIVE");
        self.finished_auth(server::Auth::Accept)
    }

    fn pty_request(mut self, channel: ChannelId, term: &str, col_width: u32, row_height: u32, pix_width: u32, pix_height: u32, _modes: &[(Pty, u32)], mut session: Session) -> Self::FutureUnit {
        {
            self.incident.request_type = RequestType::Pty(String::from(term), col_width, row_height, pix_width, pix_height);
            self.incident.post();
        }
        
        session.data(channel, CryptoVec::from_slice(b"[user@backup-ci ~]$ "));
        self.finished(session)
    }
    fn channel_open_direct_tcpip(mut self, _: ChannelId, host2con: &str, port2con: u32, org_ip: &str, org_port: u32, session: Session) -> Self::FutureUnit {
        {
            self.incident.request_type = RequestType::DirectTcpIp(String::from(host2con), port2con, String::from(org_ip), org_port);
            self.incident.post();
        }
        
        self.finished(session)
    }
    fn exec_request(mut self, _: ChannelId, data: &[u8], session: Session) -> Self::FutureUnit {
        {
            let s = match std::str::from_utf8(data) {
                Ok(v) => v,
                Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
            };
            let s = String::from(s);
            self.incident.request_type = RequestType::Exec(s);
            
            self.incident.post();
        }
        self.finished(session)
    }

    fn data(self, channel: ChannelId, data: &[u8], mut session: Session) -> Self::FutureUnit {
        match self.incident.request_type {
            RequestType::Pty(_, _, _, _, _) => {
                match data {
                    [0x0d] => session.data(channel, CryptoVec::from_slice(b"\n[user@backup-ci ~]$ ")),
                    _ => session.data(channel, CryptoVec::from_slice(data)),
                }
            },
            _ => ()
        }
        
        self.finished(session)
    }
}
