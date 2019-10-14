use std::env;
use std::process;
use std::os::unix::io::RawFd;
//use std::io::Result;
use std::io::{Error, ErrorKind};
use std::convert::TryFrom;

use nix::sys::stat::fstat;
use nix::sys::socket::SockAddr;
use nix::mqueue::mq_getattr;
use nix::sys::socket::getsockname;

pub const SD_LISTEN_FDS_START: i32 = 3;

#[derive(Debug)]
/// https://www.freedesktop.org/software/systemd/man/systemd.socket.html
pub enum SocketType {
    Fifo(RawFd),
    Special(RawFd),
    Inet(RawFd),
    Unix(RawFd),
    Mq(RawFd),
}

impl TryFrom<RawFd> for SocketType {
    type Error = &'static str;

    fn try_from(value: RawFd) -> Result<Self, Self::Error> {
        if fd_is_fifo(value) {
            return Ok(SocketType::Fifo(value));
        } else if fd_is_special(value) {
            return Ok(SocketType::Special(value));
        } else if fd_is_inet(value) {
            return Ok(SocketType::Inet(value));
        } else if fd_is_unix(value) {
            return Ok(SocketType::Unix(value));
        } else if fd_is_mq(value) {
            return Ok(SocketType::Mq(value));
        }

        return Err("Invalid FD");
    }
}

pub fn sd_booted() -> bool {
    unimplemented!();
}

pub fn sd_listen_fds(unset_env: bool) -> Result<Vec<SocketType>, Error> {
    let pid = env::var("LISTEN_PID").unwrap();
    let pid = pid.parse::<u32>().unwrap();
    if process::id() != pid {
        return Err(Error::new(ErrorKind::InvalidData, "Pid mismatch"));
    }

    let fds = env::var("LISTEN_FDS").unwrap();
    let fds = fds.parse::<i32>().unwrap();

    if unset_env {
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
        env::remove_var("LISTEN_FDNAMES");
    }

    let vec = socks_from_fds(fds);
    Ok(vec)
}

fn socks_from_fds(fds: RawFd) -> Vec<SocketType> {
    let mut vec = Vec::new();
    for fd in SD_LISTEN_FDS_START..SD_LISTEN_FDS_START+fds {
        let sock = SocketType::try_from(fd).unwrap();
        vec.push(sock);
    }

    vec
}

pub fn fd_is_fifo(fd: RawFd) -> bool {
    let stat = fstat(fd).unwrap();
    (stat.st_mode & 0170000) == 0010000
}

pub fn fd_is_special(fd: RawFd) -> bool {
    let stat = fstat(fd).unwrap();
    (stat.st_mode & 0170000) == 0100000
}

pub fn fd_is_inet(fd: RawFd) -> bool {
    let addr = getsockname(fd).unwrap();
    if let SockAddr::Inet(unix_addr) = addr {
        return true;
    }
    return false;
}

pub fn fd_is_unix(fd: RawFd) -> bool {
    let addr = getsockname(fd).unwrap();
    if let SockAddr::Unix(unix_addr) = addr {
        return true;
    }
    return false;
}

pub fn fd_is_mq(fd: RawFd) -> bool {
    let attr = mq_getattr(fd);

    attr.is_ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
