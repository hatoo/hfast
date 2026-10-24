//! Diagnostics for the fixture's own live socket, never its timed I/O loop.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{fs, net::UdpSocket, os::fd::AsRawFd, os::unix::fs::MetadataExt};

fn drops_for_inode(table: &str, inode: u64) -> Result<u64> {
    let mut lines = table.lines();
    let header = lines.next().context("missing UDP header")?;
    ensure!(
        header.split_whitespace().any(|f| f == "inode")
            && header.split_whitespace().any(|f| f == "drops"),
        "missing UDP columns"
    );
    let mut found = None;
    for line in lines {
        let fields: Vec<_> = line.split_whitespace().collect();
        ensure!(fields.len() == 13, "malformed UDP row");
        let row_inode: u64 = fields[9].parse()?;
        let drops: u32 = fields[12].parse()?;
        if row_inode == inode {
            ensure!(found.is_none(), "duplicate UDP inode");
            found = Some(u64::from(drops));
        }
    }
    found.context("socket inode absent from UDP table")
}

fn receive_capacity(socket: &UdpSocket) -> Result<i32> {
    let mut capacity: libc::c_int = 0;
    let mut length = size_of_val(&capacity) as libc::socklen_t;
    // SAFETY: socket stays alive, both output pointers have the stated size.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&mut capacity as *mut libc::c_int).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        length as usize == size_of_val(&capacity) && capacity > 0,
        "invalid SO_RCVBUF"
    );
    Ok(capacity)
}

pub fn snapshot(socket: &UdpSocket) -> Value {
    let mut row = json!({"status": "unavailable", "error": null,
        "inode": null, "rcvbuf": null, "drops": null});
    let result = (|| -> Result<()> {
        let inode = fs::metadata(format!("/proc/self/fd/{}", socket.as_raw_fd()))?.ino();
        row["inode"] = inode.into();
        row["rcvbuf"] = receive_capacity(socket)?.into();
        let family = if socket.local_addr()?.is_ipv4() {
            "udp"
        } else {
            "udp6"
        };
        row["drops"] = drops_for_inode(
            &fs::read_to_string(format!("/proc/self/net/{family}"))?,
            inode,
        )?
        .into();
        Ok(())
    })();
    match result {
        Ok(()) => row["status"] = "available".into(),
        Err(error) => row["error"] = format!("{error:#}").into(),
    }
    row
}

pub fn interval(before: &Value, socket: &UdpSocket) -> Value {
    // This exact UdpSocket has remained alive since `before`; an inode cannot
    // have been recycled underneath it. Remote-process snapshots use cookies.
    let after = snapshot(socket);
    let valid = before["status"] == "available"
        && after["status"] == "available"
        && before["inode"] == after["inode"]
        && before["rcvbuf"] == after["rcvbuf"];
    let drops = valid
        .then(|| {
            after["drops"]
                .as_u64()?
                .checked_sub(before["drops"].as_u64()?)
        })
        .flatten();
    json!({"status": if drops.is_some() {"available"} else {"unavailable"},
        "error": if drops.is_some() {None} else {Some("socket snapshots unavailable, changed or counter reset/wrapped")},
        "before": before, "after": after, "drops": drops})
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode ref pointer drops\n";
    const ROW: &str = "1: 0100007F:1234 00000000:0000 07 00000000:00000000 00:00000000 00000000 1000 0 12345 2 0000000000000000 7\n";

    #[test]
    fn selects_inode_and_rejects_ambiguous_or_missing_evidence() {
        let table = format!("{HEADER}{ROW}");
        assert_eq!(drops_for_inode(&table, 12345).unwrap(), 7);
        for text in [
            String::new(),
            HEADER.into(),
            format!("{table}{ROW}"),
            format!("{table}bad row\n"),
            table.replace(" 7\n", " -1\n"),
            table.replace(" 7\n", " 4294967296\n"),
        ] {
            assert!(drops_for_inode(&text, 12345).is_err(), "{text}");
        }
        assert!(drops_for_inode(&table, 54321).is_err());
        let ipv6 = table
            .replace("0100007F", "00000000000000000000000001000000")
            .replace("00000000:0000", "00000000000000000000000000000000:0000");
        assert_eq!(drops_for_inode(&ipv6, 12345).unwrap(), 7);
    }

    #[test]
    fn live_socket_capacity_and_zero_loss_are_observed() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let before = snapshot(&socket);
        assert_eq!(before["status"], "available", "{before}");
        assert!(before["rcvbuf"].as_i64().unwrap() > 0);
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        sender
            .send_to(b"exact body", socket.local_addr().unwrap())
            .unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let mut buf = [0; 32];
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"exact body");
        let report = interval(&before, &socket);
        assert_eq!(report["status"], "available", "{report}");
        assert_eq!(report["drops"], 0);
        let unavailable = interval(&json!({"status": "unavailable"}), &socket);
        assert_eq!(unavailable["status"], "unavailable");
        assert!(unavailable["drops"].is_null());
    }

    #[test]
    fn undrained_small_socket_reports_exact_kernel_overflow() {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let capacity: libc::c_int = 1024;
        // SAFETY: receiver and the correctly sized input value remain alive.
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    receiver.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&capacity as *const libc::c_int).cast(),
                    size_of_val(&capacity) as libc::socklen_t,
                )
            },
            0
        );
        receiver.set_nonblocking(true).unwrap();
        let before = snapshot(&receiver);
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let payload = [42; 512];
        for _ in 0..1024 {
            assert_eq!(
                sender
                    .send_to(&payload, receiver.local_addr().unwrap())
                    .unwrap(),
                payload.len()
            );
        }
        let mut received = 0;
        let mut buf = [0; 513];
        loop {
            match receiver.recv(&mut buf) {
                Ok(n) => {
                    assert_eq!(&buf[..n], &payload);
                    received += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("{error}"),
            }
        }
        assert!((1..1024).contains(&received));
        let report = interval(&before, &receiver);
        assert_eq!(report["status"], "available", "{report}");
        assert_eq!(report["drops"], 1024 - received);
        assert_eq!(snapshot(&sender)["drops"], 0);
    }
}
