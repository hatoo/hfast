//! The socket calls, straight through libc
//!
//! There is no runtime under the TCP side of this server: one thread per core,
//! each with its own `SO_REUSEPORT` listener and its own io_uring, so
//! nothing is shared and nothing needs locking.

use std::os::fd::{AsRawFd, FromRawFd, RawFd};

// Linux doubles this request for bookkeeping, so the queue is at most 8 MiB
// per worker unless the host already supplies a larger default. This is a
// limit on queued packets, not an up-front allocation. Respect rmem_max.
pub const MAX_UDP_RECEIVE_BUFFER: libc::c_int = 4 * 1024 * 1024;

pub fn tcp_listener(port: u16) -> RawFd {
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
        set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR);
        set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT);
        bind(fd, port);
        assert!(libc::listen(fd, 4096) == 0, "listen");
        set_nonblocking(fd);
        fd
    }
}

unsafe fn set_opt(fd: RawFd, level: libc::c_int, name: libc::c_int) {
    let one: libc::c_int = 1;
    unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
}

/// A UDP socket sharing `port` with every other worker's, so the kernel spreads
/// clients across them by their address. QUIC connections are identified by
/// address here, not by connection id, which is fine for a client that does not
/// migrate mid-run - and a load generator does not.
pub fn udp_listener(port: u16, receive_buffer: libc::c_int) -> std::net::UdpSocket {
    let socket = udp_socket_with_buffer(receive_buffer);
    unsafe {
        let fd = socket.as_raw_fd();
        set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR);
        set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT);
        bind(fd, port);
    }
    socket
}

fn new_udp_socket() -> std::net::UdpSocket {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
    unsafe { std::net::UdpSocket::from_raw_fd(fd) }
}

fn receive_buffer(fd: RawFd) -> std::io::Result<libc::c_int> {
    let mut bytes: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&bytes) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut bytes as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(bytes)
}

fn udp_socket_with_buffer(requested: libc::c_int) -> std::net::UdpSocket {
    let socket = new_udp_socket();
    if requested == 0 {
        return socket;
    }
    let before = match receive_buffer(socket.as_raw_fd()) {
        Ok(bytes) => bytes,
        Err(error) => {
            eprintln!("hfast: could not read UDP receive buffer: {error}; using default");
            return socket;
        }
    };
    // Do not shrink a larger system default.
    if before >= requested.saturating_mul(2) {
        return socket;
    }
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &requested as *const _ as *const libc::c_void,
            std::mem::size_of_val(&requested) as libc::socklen_t,
        )
    };
    if result != 0 {
        eprintln!(
            "hfast: could not enlarge UDP receive buffer: {}; using default {before} bytes",
            std::io::Error::last_os_error()
        );
        return socket;
    }
    match receive_buffer(socket.as_raw_fd()) {
        Ok(bytes) if bytes >= before => {
            if bytes < requested.saturating_mul(2) {
                eprintln!("hfast: UDP receive buffer capped at {bytes} bytes by the host");
            }
            socket
        }
        result => {
            // rmem_max can be below rmem_default. Setting the old value again
            // would also be capped. Recreate this still-unbound socket instead.
            eprintln!(
                "hfast: UDP receive buffer did not grow ({result:?}); using default {before} bytes"
            );
            drop(socket);
            new_udp_socket()
        }
    }
}

pub fn set_nodelay(fd: RawFd) {
    unsafe { set_opt(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY) };
}

unsafe fn bind(fd: RawFd, port: u16) {
    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let r = unsafe {
        libc::bind(
            fd,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    };
    assert!(r == 0, "bind: {}", std::io::Error::last_os_error());
}

pub fn set_nonblocking(fd: RawFd) {
    unsafe {
        let f = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, f | libc::O_NONBLOCK);
    }
}

/// Steer an incoming connection to the listener whose worker runs on the CPU
/// the packet arrived on
///
/// Without this the kernel picks a listener by hashing the connection's
/// addresses, so the softirq that delivers a packet and the thread that reads
/// it are usually on different cores. Measured against a load generator, that
/// cost half again as much system time per request for exactly the same
/// packets. The program is classic BPF - load the CPU id, fold it into the
/// group - and applies to every socket in the group, so it is attached once.
pub fn attach_reuseport_cbpf(fd: RawFd, group: u32) {
    /// Offsets above this read ancillary data rather than packet bytes
    const SKF_AD_OFF: i32 = -0x1000;
    const SKF_AD_CPU: i32 = 36;
    let prog = [
        // A = raw_smp_processor_id()
        SockFilter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: (SKF_AD_OFF + SKF_AD_CPU) as u32,
        },
        // A %= group, so a machine with more cores than workers still lands
        SockFilter {
            code: (libc::BPF_ALU | libc::BPF_MOD | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: group,
        },
        SockFilter {
            code: (libc::BPF_RET | libc::BPF_A) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
    ];
    let fprog = SockFprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_REUSEPORT_CBPF,
            &fprog as *const _ as *const libc::c_void,
            std::mem::size_of::<SockFprog>() as libc::socklen_t,
        )
    };
    if r != 0 {
        eprintln!(
            "hfast: could not steer connections by CPU: {}",
            std::io::Error::last_os_error()
        );
    }
}

#[repr(C)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Run this thread on one core and stay there, so that the core the steering
/// above sends a connection to is the core that reads it
pub fn pin_to_cpu(cpu: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_SET(cpu, &mut set);
        libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
    }
}

/// `accept4` with `SOCK_NONBLOCK`, or a negative errno
pub fn accept(listener: RawFd) -> RawFd {
    unsafe {
        libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_NONBLOCK,
        )
    }
}

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn udp_receive_buffer_is_bounded_without_shrinking_the_default() {
        let default = receive_buffer(new_udp_socket().as_raw_fd()).unwrap();
        let socket = udp_listener(0, MAX_UDP_RECEIVE_BUFFER);
        let actual = receive_buffer(socket.as_raw_fd()).unwrap();
        assert!(actual >= default);
        assert!(actual <= default.max(MAX_UDP_RECEIVE_BUFFER * 2));
        assert_ne!(socket.local_addr().unwrap().port(), 0);
    }

    #[test]
    fn smaller_receive_buffer_request_keeps_the_system_default() {
        let default = receive_buffer(new_udp_socket().as_raw_fd()).unwrap();
        for requested in [0, 1] {
            let socket = udp_socket_with_buffer(requested);
            assert_eq!(receive_buffer(socket.as_raw_fd()).unwrap(), default);
            assert_eq!(socket.local_addr().unwrap().port(), 0);
        }
    }

    #[test]
    fn receive_buffer_reports_socket_errors() {
        assert_eq!(
            receive_buffer(-1).unwrap_err().raw_os_error(),
            Some(libc::EBADF)
        );
    }

    #[test]
    fn udp_workers_share_a_port_and_preserve_every_datagram() {
        let mut workers = vec![udp_listener(0, MAX_UDP_RECEIVE_BUFFER)];
        let port = workers[0].local_addr().unwrap().port();
        for _ in 1..4 {
            workers.push(udp_listener(port, MAX_UDP_RECEIVE_BUFFER));
        }
        let mut peers = Vec::new();
        for number in 0..64u8 {
            let peer = UdpSocket::bind("127.0.0.1:0").unwrap();
            peer.send_to(&[number], (std::net::Ipv4Addr::LOCALHOST, port))
                .unwrap();
            peers.push(peer);
        }
        let mut seen = [false; 64];
        for worker in workers {
            worker.set_nonblocking(true).unwrap();
            loop {
                let mut buf = [0; 2];
                match worker.recv_from(&mut buf) {
                    Ok((len, addr)) => {
                        assert_eq!(len, 1);
                        let number = buf[0] as usize;
                        assert!(!seen[number]);
                        assert_eq!(addr, peers[number].local_addr().unwrap());
                        seen[number] = true;
                    }
                    Err(error) => {
                        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                        break;
                    }
                }
            }
        }
        assert!(seen.into_iter().all(|value| value));
    }
}
