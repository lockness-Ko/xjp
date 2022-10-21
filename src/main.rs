//! xjp
//! 
//! A multi-protocol honeypot
//! 
//! Currently supported (applicaiton layer) protocols are:
//! * HTTP/(1,2)
//! * SSH
//! * SMTP
//!
//! # Usage
//! 
//! Just build and run and you're good to go!
//! 
//! ```bash
//! cargo build --release && sudo ./target/release/xjp
//! ```
//! 
//! # How it works
//!
//! We listen for incoming SYN packets on the default interface and create a TCP connection starting from the SYN RCVD state in the following diagram from [rfc793](https://www.rfc-editor.org/rfc/rfc793)
//!
//! ```text
//!                              +---------+ ---------\      active OPEN
//!                              |  CLOSED |            \    -----------
//!                              +---------+<---------\   \   create TCB
//!                                |     ^              \   \  snd SYN
//!                   passive OPEN |     |   CLOSE        \   \
//!                   ------------ |     | ----------       \   \
//!                    create TCB  |     | delete TCB         \   \
//!                                V     |                      \   \
//!                              +---------+            CLOSE    |    \
//!                              |  LISTEN |          ---------- |     |
//!                              +---------+          delete TCB |     |
//!                   rcv SYN      |     |     SEND              |     |
//!                  -----------   |     |    -------            |     V
//! +---------+      snd SYN,ACK  /       \   snd SYN          +---------+
//! |         |<-----------------           ------------------>|         |
//! |   SYN   |                    rcv SYN                     |   SYN   |
//! |   RCVD  |<-----------------------------------------------|   SENT  |
//! |         |                    snd ACK                     |         |
//! |         |------------------           -------------------|         |
//! +---------+   rcv ACK of SYN  \       /  rcv SYN,ACK       +---------+
//!   |           --------------   |     |   -----------
//!   |                  x         |     |     snd ACK
//!   |                            V     V
//!   |  CLOSE                   +---------+
//!   | -------                  |  ESTAB  |
//!   | snd FIN                  +---------+
//!   |                   CLOSE    |     |    rcv FIN
//!   V                  -------   |     |    -------
//! +---------+          snd FIN  /       \   snd ACK          +---------+
//! |  FIN    |<-----------------           ------------------>|  CLOSE  |
//! | WAIT-1  |------------------                              |   WAIT  |
//! +---------+          rcv FIN  \                            +---------+
//!   | rcv ACK of FIN   -------   |                            CLOSE  |
//!   | --------------   snd ACK   |                           ------- |
//!   V        x                   V                           snd FIN V
//! +---------+                  +---------+                   +---------+
//! |FINWAIT-2|                  | CLOSING |                   | LAST-ACK|
//! +---------+                  +---------+                   +---------+
//!   |                rcv ACK of FIN |                 rcv ACK of FIN |
//!   |  rcv FIN       -------------- |    Timeout=2MSL -------------- |
//!   |  -------              x       V    ------------        x       V
//!    \ snd ACK                 +---------+delete TCB         +---------+
//!     ------------------------>|TIME WAIT|------------------>| CLOSED  |
//!                              +---------+                   +---------+
//! ```
//!
//! After that, we check if the client sends anything after their ACK and check if it matches any protocols we know.
//! If the client does not send anything, then we guess the protocol based on the port they're connecting to.
//!
//! ## Design goals for TCP handler
//! * Be able to 'hijack' connection from SynRcvd or Estab state
//! * No writes to heap
//! * Blazing fast
//!

use pcap::{Capture, Device, Active};
use etherparse::{SlicedPacket, TcpHeader, PacketBuilder, TransportSlice::Tcp};

///Enum for supported protocols
#[derive(Debug, PartialEq)]
enum Proto {
    ///HTTP/(1,2) procotol [https://www.rfc-editor.org/rfc/rfc2616](https://www.rfc-editor.org/rfc/rfc2616)
    Http,
    ///SSH protocol [https://www.rfc-editor.org/rfc/rfc4253](https://www.rfc-editor.org/rfc/rfc4253)
    Ssh,
    ///SMTP protocol [https://www.rfc-editor.org/rfc/rfc821](https://www.rfc-editor.org/rfc/rfc821)
    Smtp,
    ///In case we run into an unsupported protocol
    Unknown
}

///Parser and state manager for the xjp
struct Honeypot {}

impl Honeypot {
    pub fn new() -> Self {
        Self{}
    }
    
    ///Infers the layer 7 protocol based on a destination port and any data sent over the tcp connection
    pub fn infer_l7_proto(&self, port: u16, _banner: &[u8]) -> Proto {
        match port {
            80 => Proto::Http,
            22 => Proto::Ssh,
            25 => Proto::Smtp,
            _ => Proto::Unknown
        }
    }
}

///Implementation of TCP for 'hijacking connections'
struct XjpTcp {
    state: XjpTcpState,
    src_port: u16,
    dst_port: u16,
    seq: u32
}

///For keeping track of the current TCP state
#[derive(PartialEq)]
enum XjpTcpState {
    ///Wait for SYN packets
    _Listen,
    ///Sent SYN ACK, waiting for ACK
    SynRcvd,
    ///Received ACK, Send data, Wait for FIN or send FIN
    _Estab,
    ///We sent FIN
    FinWait1,
    ///Receive ACK of FIN
    FinWait2,
    ///Received FIN (instead of ACK of FIN)
    Closing,
    ///Received FIN or ACK of FIN
    TimeWait,
    ///Received FIN after ESTAB state
    CloseWait,
    ///Wait for ACK of FIN we sent
    LastAck,
    ///Self explanitory
    Closed
}

impl XjpTcp {
    ///New TCP connection in Listen state
    // pub fn new() -> Self {
    //     Self {
    //         state: XjpTcpState::_Listen,
    //         src_port: 0,
    //         dst_port: 0,
    //         seq: 0
    //     }
    // }
    
    ///'Hijack' a connection from a state
    pub fn from_state(state: XjpTcpState, src_port: u16, dst_port: u16, seq: u32) -> Self {
        Self {
            state,
            src_port,
            dst_port,
            seq
        }
    }
    
    ///Check if the state is closing
    fn past_estab(&self) -> bool {
        self.state == XjpTcpState::FinWait1 || self.state == XjpTcpState::FinWait2 || self.state == XjpTcpState::Closing || self.state == XjpTcpState::TimeWait || self.state == XjpTcpState::CloseWait || self.state == XjpTcpState::LastAck || self.state == XjpTcpState::Closed
    }
    
    ///Write data to the TCP connection
    ///
    ///Will return an error if the connection is closing, or closed    
    pub fn write(&mut self, data: &[u8], cap: &mut Capture<Active>) -> Result<(), &str> {
        if self.past_estab() {
            return Err("TCP Connection Closing!");
        }
        println!("Sending payload!");
        
        
        let builder = PacketBuilder::ethernet2([0x4c,0xd5,0x77,0xab,0x0e,0xaf], [0xff,0xff,0xff,0xff,0xff,0xff])
            .ipv4(
                [10,8,9,9], //source ip
                [10,8,9,100],     //desitination ip
                128,
            ) //time to live
            .tcp(
                self.src_port, // src port
                self.dst_port,                        // dst port
                match self.state {
                    XjpTcpState::SynRcvd => self.seq,
                    _ => self.seq
                },                           // seq number
                65160,                           // window size
            )
            .syn().ack(self.seq + 1);

        // self.seq += 1;

        let payload = [];
        let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
        builder.write(&mut result, &payload).unwrap();        

        match cap.sendpacket(result) {
            Ok(()) => {},
            Err(err) => panic!("Failed to send packet!"),
        };
        
        Ok(())
    }
    
    ///Read from the buffer
    ///
    ///Will return an error if the connection is closing, or closed
    pub fn read(&self) -> Result<&[u8], &str> {
        if self.past_estab() {
            return Err("TCP Connection Closing!");
        }
        Ok(&[0xbe, 0xef, 0xca, 0xfe])
    }
}

fn main() {
    let dev = Device::lookup().unwrap().unwrap();
    let mut cap = Capture::from_device(dev)
        .unwrap()
        .timeout(1)
        .open()
        .unwrap();
    cap.filter("tcp", true).unwrap();

    let pot = Honeypot::new();
    
    while let Ok(packet) = cap.next_packet() {
        match SlicedPacket::from_ethernet(&packet) {
            Err(value) => println!("Invalid packet! {:?}", value),
            Ok(parsed) => {
                match parsed.transport {
                    Some(Tcp(slice)) => {
                        let header = TcpHeader::from_slice(&slice.slice()).unwrap();
                        let proto = pot.infer_l7_proto(header.0.destination_port, &[0u8]);
                        
                        if header.0.syn && !header.0.ack && !header.0.fin && !header.0.psh && header.0.destination_port == 21 {
                            let seq = header.0.sequence_number;
                            let mut con = XjpTcp::from_state(XjpTcpState::SynRcvd, header.0.destination_port, header.0.source_port, seq);
                            
                            con.write(b"Hello, World!\n", &mut cap).unwrap();
                        }
                        
                        // if proto != Proto::Unknown {
                        //     println!("Protocol: {:?}", proto);
                        // }
                    }
                    _ => {}
                    
                }
            }
        }
    }
}
