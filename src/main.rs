use std::net::{IpAddr, SocketAddr};

use tokio::{net::TcpSocket};

use log::error;

mod socks5_server;
mod thread_pool;

#[warn(unused_must_use)]
async  fn run_socks5_server() -> ! {
    let ip = "0.0.0.0".parse::<IpAddr>().expect("ip error");
    let addr = SocketAddr::new(ip, 1010);

    let socket = TcpSocket::new_v4().expect("tcp socket error");
    #[cfg(unix)]{
        socket.set_reuseaddr(true).expect("reuse addr error");
        socket.set_reuseport(true).expect("reuse port error");
    }

    socket.bind(addr).expect("socket bind");
    let listener = socket.listen(1024).expect("socket listen");
    
    loop {
        match listener.accept().await {
            Err(e) => error!("listener.accept: {:?}",e),
            Ok((stream,_)) => {
                tokio::spawn(socks5_server::handle_socks5_stream(stream));
            }
        }
    }

}

#[tokio::main]
async fn main() {
    // let a:Option<i32> = None;
    run_socks5_server().await;
}
