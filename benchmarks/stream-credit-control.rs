//! Bounded parent barriers and clocks, outside the upload I/O loop.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::io::Write;
use std::os::fd::RawFd;
use std::time::{Duration, Instant};

fn clock_ns(id: libc::clockid_t) -> Result<u64> {
    let mut value = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: value is a valid, writable timespec for the duration of the call.
    if unsafe { libc::clock_gettime(id, &mut value) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    ensure!(
        value.tv_sec >= 0 && (0..1_000_000_000).contains(&value.tv_nsec),
        "invalid clock"
    );
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|n| n.checked_add(value.tv_nsec as u64))
        .context("clock overflow")
}

pub struct Start {
    monotonic_ns: u64,
    cpu_ns: u64,
}
impl Start {
    pub fn now() -> Result<Self> {
        // CPU brackets the monotonic interval by only these clock reads.
        let cpu_ns = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID)?;
        Ok(Self {
            monotonic_ns: clock_ns(libc::CLOCK_MONOTONIC)?,
            cpu_ns,
        })
    }
    pub fn finish(self) -> Result<Value> {
        let end = clock_ns(libc::CLOCK_MONOTONIC)?;
        let cpu_end = clock_ns(libc::CLOCK_PROCESS_CPUTIME_ID)?;
        Ok(
            json!({"start_monotonic_ns": self.monotonic_ns, "end_monotonic_ns": end,
            "elapsed_ns": end.checked_sub(self.monotonic_ns).context("monotonic clock reset")?,
            "cpu_elapsed_ns": cpu_end.checked_sub(self.cpu_ns).context("CPU clock reset")?}),
        )
    }
}

pub fn emit(row: Value) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{row}")?;
    stdout.flush()?;
    Ok(())
}

pub fn command(fd: RawFd, expected: &str, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(
            !remaining.is_zero(),
            "controller timeout waiting for {expected}"
        );
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let milliseconds = remaining.as_millis().clamp(1, 100) as i32;
        // SAFETY: pollfd is one valid pollfd; fd remains owned by the caller.
        let ready = unsafe { libc::poll(&mut pollfd, 1, milliseconds) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if ready == 0 {
            continue;
        }
        let mut byte = 0u8;
        // SAFETY: byte is writable and the buffer length is exactly one.
        let count = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if count < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        ensure!(count == 1, "controller disconnected waiting for {expected}");
        if byte == b'\n' {
            ensure!(
                bytes == expected.as_bytes(),
                "wrong controller command, expected {expected}"
            );
            return Ok(());
        }
        bytes.push(byte);
        ensure!(bytes.len() <= 32, "oversized controller command");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::{fd::AsRawFd, unix::net::UnixStream};

    #[test]
    fn commands_preserve_phase_boundaries() {
        let (input, mut output) = UnixStream::pair().unwrap();
        output.write_all(b"start\nexit\n").unwrap();
        command(input.as_raw_fd(), "start", Duration::from_secs(1)).unwrap();
        command(input.as_raw_fd(), "exit", Duration::from_secs(1)).unwrap();
    }
    #[test]
    fn malformed_oversized_and_disconnected_commands_fail() {
        for bytes in [
            b"exit\n".as_slice(),
            b"start extra\n",
            &[b'x'; 33],
            b"sta",
            b"",
        ] {
            let (input, mut output) = UnixStream::pair().unwrap();
            output.write_all(bytes).unwrap();
            drop(output);
            assert!(command(input.as_raw_fd(), "start", Duration::from_secs(1)).is_err());
        }
    }
    #[test]
    fn stalled_controller_is_bounded() {
        let (input, _output) = UnixStream::pair().unwrap();
        assert!(
            command(input.as_raw_fd(), "start", Duration::from_millis(2))
                .unwrap_err()
                .to_string()
                .contains("timeout")
        );
    }
    #[test]
    fn interval_reports_common_monotonic_clock_and_cpu() {
        let before = clock_ns(libc::CLOCK_MONOTONIC).unwrap();
        let start = Start::now().unwrap();
        std::thread::sleep(Duration::from_millis(2));
        let row = start.finish().unwrap();
        let after = clock_ns(libc::CLOCK_MONOTONIC).unwrap();
        let lo = row["start_monotonic_ns"].as_u64().unwrap();
        let hi = row["end_monotonic_ns"].as_u64().unwrap();
        assert!(before <= lo && lo < hi && hi <= after);
        assert_eq!(row["elapsed_ns"], hi - lo);
        assert!(row["cpu_elapsed_ns"].as_u64().is_some());
    }
}
