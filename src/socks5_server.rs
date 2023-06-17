use anyhow::{ensure, Context,bail,anyhow, Ok};
use tokio::{io::{copy_bidirectional, self, AsyncReadExt,AsyncWriteExt}, net::{self,TcpStream, TcpSocket,lookup_host}};
use log::{error,debug,warn};
use std::net::SocketAddr;


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

pub async fn handle_socks5_stream(mut s:TcpStream) -> anyhow::Result<()> {

    verify_socks5(&mut s).await?;
    
    let addrs = tcp_stream_addrs(&s, false);

    // match verify_socks5(&mut s).await {
    //     Ok(_) => println!(""),
    //     Err(e) => {
    //         error!("verify socks5 err {e} and exit");
    //         return;
    //     }
    // }
    Ok(())
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
    
        


    return Ok(());
}

async fn get_target_stream(socket:&mut TcpStream) -> anyhow::Result<TcpStream> {
    // TODO minimize the number of system calls
    const CMD_CONNECT: u8 = 0x01;

    const ATYP_IP_V4_ADDR: u8 = 0x01;
    const ATYP_IP_V6_ADDR: u8 = 0x04;
    const ATYP_DOMAINNAME: u8 = 0x03;

    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    let mut buf = [0; 255];

    socket
        .read_exact(&mut buf[..4])
        .await
        .context("connect: read basics")?;

    ensure!(buf[0] == VERSION, "connect: invalid VERSION: {}", buf[0]);
    ensure!(buf[1] == CMD_CONNECT, "connect: invalid CMD: {}", buf[1]);
    ensure!(buf[2] == 0x00, "connect: invalid RSV: {}", buf[2]);

    let dst_addr = match buf[3] {
        ATYP_IP_V4_ADDR => {
            let mut ip = [0; 4];
            socket
                .read_exact(&mut ip)
                .await
                .context("connect: read ipv4 addr")?;

            let port = socket.read_u16().await.context("connect: read ipv4 port")?;
            let addr = (ip, port).into();
            debug!(
                "{} - connect to: {}",
                tcp_stream_addrs(socket, false),
                addr
            );
            addr
        }

        ATYP_IP_V6_ADDR => {
            let mut ip = [0; 16];
            socket
                .read_exact(&mut ip)
                .await
                .context("connect: read ipv6 addr")?;

            let port = socket.read_u16().await.context("connect: read ipv6 port")?;
            let addr = (ip, port).into();
            debug!(
                "{} - connect to: {}",
                tcp_stream_addrs(socket, false),
                addr
            );
            addr
        }

        ATYP_DOMAINNAME => {
            let n = socket
                .read_u8()
                .await
                .context("connect: read domainname length")? as usize;

            let domain_name = &mut buf[..n];

            socket
                .read_exact(domain_name)
                .await
                .context("connect: read domainname")?;

            let domain_name =
                std::str::from_utf8(domain_name).context("connect: str::from_utf8(domain_name)")?;

            let port = socket
                .read_u16()
                .await
                .context("connect: read domain_name port")?;

            debug!(
                "{} - connect to: {}:{}",
                tcp_stream_addrs(socket, false),
                domain_name,
                port
            );

            let iter = lookup_host((domain_name, port))
                .await
                .context("connect: lookup_host")?;

            let mut addr = None;
            for a in iter {
                addr = Some(a);
                if a.is_ipv4() {
                    break;
                }
            }
            addr.ok_or_else(|| anyhow!("connect: lookup_host: empty: {}:{}", domain_name, port))?
        }

        _ => bail!("connect: invalid ATYP: {}", buf[3]),
    };

    let socket2 = match dst_addr {
        SocketAddr::V4(_) => TcpSocket::new_v4().context("connect: TcpSocket::new_v4")?,
        SocketAddr::V6(_) => TcpSocket::new_v6().context("connect: TcpSocket::new_v6")?,
    };

    {
        // TODO
        // let mut local_addr = socket.local_addr().context("connect: socket.local_addr")?;
        // if dst_addr.is_ipv4() && local_addr.is_ipv4() || dst_addr.is_ipv6() && local_addr.is_ipv6()
        // {
        //     local_addr.set_port(0);
        //     socket2.bind(local_addr).context("connect: socket2.bind")?;
        // }
    }

    let socket2 = socket2
        .connect(dst_addr)
        .await
        .context("connect: socket2.connect")?;

    // +----+-----+-------+------+----------+----------+
    // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

    buf[0] = VERSION;
    buf[1] = 0x00;
    buf[2] = 0x00;

    let local_addr = socket2
        .local_addr()
        .context("connect: socket2.local_addr")?;

    let reply = match local_addr {
        SocketAddr::V4(a) => {
            let ip = a.ip().octets();
            let port = a.port().to_ne_bytes();

            buf[3] = ATYP_IP_V4_ADDR;
            buf[4..8].copy_from_slice(&ip);
            buf[8..10].copy_from_slice(&port);
            &buf[..10]
        }

        SocketAddr::V6(a) => {
            let ip = a.ip().octets();
            let port = a.port().to_ne_bytes();

            buf[3] = ATYP_IP_V6_ADDR;
            buf[4..20].copy_from_slice(&ip);
            buf[20..22].copy_from_slice(&port);
            &buf[..22]
        }
    };

    socket
        .write_all(reply)
        .await
        .context("connect: write replay")?;

    debug!(
        "{} - {}",
        tcp_stream_addrs(socket, false),
        tcp_stream_addrs(&socket2, true)
    );

    Ok(socket2)
}


