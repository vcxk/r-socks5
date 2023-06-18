use anyhow::{ensure, Context,bail,anyhow};
use tokio::{io::{copy_bidirectional, self, AsyncReadExt,AsyncWriteExt, AsyncRead, AsyncWrite}, net::{self,TcpStream ,TcpSocket,UdpSocket,lookup_host}};
use log::{error,debug,warn};
use std::{net::{SocketAddr}, fmt::Error};

const VERSION: u8 = 0x05;

fn tcp_stream_addrs(s: &TcpStream, client: bool) -> String {
    let local_addr = match s.local_addr() {
        Ok(a) => a.to_string(),
        Err(e) => {
            error!("tcp stream local_addr: {e} - client: {client}");
            "ERROR".to_string()
        }
    };

    let peer_addr = match s.peer_addr() {
        Ok(a) => a.to_string(),
        Err(e) => {
            error!("tcp stream peer_addr: {e} - client: {client}");
            "ERROR".to_string()
        }
    };

    if client {
        format!("[{} => {}]",local_addr,peer_addr)
    } else {
        format!("[{} => {}]",peer_addr,local_addr)
    }
}

fn authentication_method_name(id: u8) -> String {
    match id {
        0x00 => "NO AUTHENTICATION REQUIRED".to_string(),
        0x01 => "GSSAPI".to_string(),
        0x02 => "USERNAME/PASSWORD".to_string(),
        0x03..=0x7f => format!("{id} (IANA ASSIGNED)"),
        0x80..=0xfe => format!("{id} (RESERVED FOR PRIVATE METHODS)"),
        0xff => format!("{id} (NO ACCEPTABLE METHODS)"),
    }
}

pub async fn handle_socks5_stream(mut s:TcpStream) {
    
    let addrs = tcp_stream_addrs(&s, false);
    debug!("{addrs}");

    match verify_socks5(&mut s).await {
        Ok(()) => println!("verify ok"),
        Err(e) => {
            error!("verify socks5 err : {e}");
            return;
        }
    }

    let mut s2 = match get_cmd_sock(&mut s).await {
        Ok(s2) => s2,
        Err(e) => {
            error!("verify socks5 err : {e}");
            return ;
        }
    };

    let num = copy_bidirectional(&mut s, &mut s2).await;
    match num {
        Ok((a,b)) => {
            println!("end bidirectional {} - {}",a,b);
        }
        _ => return
    }
}

async fn verify_socks5(s:&mut TcpStream) -> anyhow::Result<()> {
    let mut buf = [0;255];
    
    s
    .read_exact(&mut buf[..2])
    .await
    .context("authenticate read ver/nmethods")?;

    ensure!(buf[0] == VERSION,"authenticate: invalid version {}",buf[0]);

    let nmethods = buf[1] as usize;
    let methods = &mut buf[..nmethods];
    s.read_exact(methods).await.context("authenticate read methods")?;
    debug!("{} - methods - {:?}",
        tcp_stream_addrs(s, false),
        methods
            .iter()
            .map(|v| authentication_method_name(*v))
            .collect::<Vec<_>>()
        );
    
    ensure!(methods.contains(&0),"目前仅支持无验证模式！{:?}",methods);
    
    s.write(&[0x5,0x00]).await?;
    
    Ok(())
}

async fn get_cmd_sock(socket: &mut TcpStream) -> anyhow::Result<TcpStream> {
    
    let mut buf = [0;266];
    socket.read_exact(&mut buf[..4]).await.context("context")?;

    const CMD_CONNECT:u8 = 0x01;
    const CMD_UDP:u8 = 0x03;

    ensure!(buf[0] == VERSION,"invalid socks version!");
    ensure!([CMD_CONNECT,CMD_UDP].contains(&buf[1]), "only support connect and udp: {}", buf[1]);
    ensure!(buf[2] == 0x00, "connect: invalid RSV: {}", buf[2]);
    
    //请求的数据结构
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    let addr = read_target_address(socket, buf[3]).await?;

    let s2 = match buf[1] {
        CMD_CONNECT => {
            let socket2 = match addr {
                SocketAddr::V4(_) => TcpSocket::new_v4().context("context")?,
                SocketAddr::V6(_) => TcpSocket::new_v6().context("context")?,
            };
            let tcp = socket2.connect(addr).await.context("context")?;
            tcp
        },
        _ => bail!("invalid cmd {}",buf[1])
    };
    const ATYP_IP_V4: u8 = 0x01;
    // const ATYP_IP_V6: u8 = 0x04;
    let mut buf = [0;256];
    buf[0] = VERSION;
    let reply = match addr {
        SocketAddr::V4(a) => {
            buf[3] = ATYP_IP_V4;
            let ip = a.ip().octets();
            let port = a.port().to_ne_bytes();
            buf[4..8].copy_from_slice(&ip);
            buf[8..10].copy_from_slice(&port);
            &buf[..10]
        },
        SocketAddr::V6(a) => {
            buf[3] = ATYP_IP_V4;
            let ip = a.ip().octets();
            let port = a.port().to_ne_bytes();
            buf[4..20].copy_from_slice(&ip);
            buf[20..22].copy_from_slice(&port);
            &buf[..22]
        }
    };
    //回复的数据结构
    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    socket.write(reply).await?;
    println!("get connected socket");
    Ok(s2)
}

async fn read_target_address(socket: &mut TcpStream,atyp:u8) -> anyhow::Result<SocketAddr> {
    
    const ATYP_IP_V4: u8 = 0x01;
    const ATYP_IP_V6: u8 = 0x04;
    const ATYP_DOMAIN: u8 = 0x03;

    // let mut buf = [0; 255];
    let addr: SocketAddr = match atyp {
        ATYP_IP_V4 => {
            let mut ip = [0; 4];
            socket
                .read_exact(&mut ip)
                .await
                .context("connect: read ipv4 addr")?;

            let port = socket.read_u16().await.context("connect: read ipv4 port")?;
            let addr = (ip, port).into();

            addr
        },
        ATYP_IP_V6 => {
            let mut ip = [0; 16];
            socket.read_exact(&mut ip).await.context("connect: read ipv6 addr")?;

            let port = socket.read_u16().await.context("connect: read ipv6 port")?;
            let addr = (ip, port).into();
            
            addr
        }
        ATYP_DOMAIN => {
            let mut buf = [0;256];
            let n = socket
                .read_u8()
                .await
                .context("connect: read domainname length")? as usize;

            let domain_name = &mut buf[..n];

            socket.read_exact(domain_name).await.context("connect: read domainname")?;

            let domain_name =
                std::str::from_utf8(domain_name).context("connect: str::from_utf8(domain_name)")?;

            let port = socket.read_u16().await.context("connect: read domain_name port")?;

            debug!( "{} - connect to: {}:{}", tcp_stream_addrs(socket, false), domain_name, port );

            let iter = lookup_host((domain_name, port)).await.context("connect: lookup_host")?;
            
            //https 仅支持 ipv4 所以选择 ipv4 优先
            let mut addr = None;
            for a in iter {
                addr = Some(a);
                if a.is_ipv4() {
                    break;
                }
            };
            
            addr.ok_or_else(|| anyhow!("connect: lookup_host: empty: {}:{}", domain_name, port))?
        }
        _ => bail!("invalid atyp {}",atyp)
    };
    debug!( "{} - connect to: {}", tcp_stream_addrs(socket, false), addr );
    Ok(addr)
}
