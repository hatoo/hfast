//! The socket and epoll calls, straight through libc
//!
//! There is no runtime under the TCP side of this server: one thread per core,
//! each with its own `SO_REUSEPORT` listener and its own epoll instance, so
//! nothing is shared and nothing needs locking.

use std::os::fd::RawFd;

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
pub fn udp_listener(port: u16) -> std::net::UdpSocket {
    use std::os::fd::FromRawFd;
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        assert!(fd >= 0, "socket: {}", std::io::Error::last_os_error());
        set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEADDR);
        set_opt(fd, libc::SOL_SOCKET, libc::SO_REUSEPORT);
        bind(fd, port);
        std::net::UdpSocket::from_raw_fd(fd)
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

pub fn epoll_create() -> RawFd {
    unsafe { libc::epoll_create1(0) }
}

pub fn epoll_add(ep: RawFd, fd: RawFd, events: u32, token: u64) {
    let mut ev = libc::epoll_event { events, u64: token };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) };
}

pub fn epoll_mod(ep: RawFd, fd: RawFd, events: u32, token: u64) {
    let mut ev = libc::epoll_event { events, u64: token };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, fd, &mut ev) };
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
