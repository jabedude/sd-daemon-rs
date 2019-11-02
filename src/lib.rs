use std::env;
use std::process;
use std::os::unix::io::RawFd;
use std::io::{Error, ErrorKind};
use std::convert::TryFrom;

use nix::sys::stat::fstat;
use nix::sys::socket::SockAddr;
use nix::mqueue::mq_getattr;
use nix::sys::socket::getsockname;

pub const SD_LISTEN_FDS_START: RawFd = 3;

#[derive(Debug, Clone)]
/// https://www.freedesktop.org/software/systemd/man/systemd.socket.html
pub enum SocketType {
    Fifo(RawFd),
    Special(RawFd),
    Inet(RawFd),
    Unix(RawFd),
    Mq(RawFd),
}

impl SocketType {
    pub fn is_unix(&self) -> bool {
        match self {
            SocketType::Unix(_) => true,
            _ => false,
        }
    }

    pub fn is_inet(&self) -> bool {
        match self {
            SocketType::Inet(_) => true,
            _ => false,
        }
    }
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
    let pid = env::var("LISTEN_PID").expect("LISTEN_PID");
    let pid = pid.parse::<u32>().unwrap();
    if process::id() != pid {
        return Err(Error::new(ErrorKind::InvalidData, "Pid mismatch"));
    }

    let fds = env::var("LISTEN_FDS").expect("LISTEN_FDS");
    let fds = fds.parse::<i32>().unwrap();

    let names = env::var("LISTEN_FDNAMES").expect("LISTEN_FDNAMES");

    if unset_env {
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
        env::remove_var("LISTEN_FDNAMES");
    }

    let vec = socks_from_fds(fds);
    Ok(vec)
}

pub fn sd_listen_fds_with_names(unset_env: bool) -> Result<Vec<(SocketType, String)>, Error> {
    let pid = env::var("LISTEN_PID").expect("LISTEN_PID");
    let pid = pid.parse::<u32>().unwrap();
    if process::id() != pid {
        return Err(Error::new(ErrorKind::InvalidData, "Pid mismatch"));
    }

    let fds = env::var("LISTEN_FDS").expect("LISTEN_FDS");
    let fds = fds.parse::<i32>().unwrap();

    let names = env::var("LISTEN_FDNAMES").expect("LISTEN_FDNAMES");

    let names: Vec<String> = names.split(":").map(String::from).collect();
    let vec = socks_from_fds(fds);

    let out = vec.into_iter().zip(names.into_iter()).collect();

    if unset_env {
        env::remove_var("LISTEN_PID");
        env::remove_var("LISTEN_FDS");
        env::remove_var("LISTEN_FDNAMES");
    }

    Ok(out)
}

fn socks_from_fds(fds: RawFd) -> Vec<SocketType> {
    let mut vec = Vec::new();
    for fd in SD_LISTEN_FDS_START..SD_LISTEN_FDS_START+fds {
        let sock = SocketType::try_from(fd).expect("Socket type conversion");
        vec.push(sock);
    }

    vec
}

pub fn fd_is_fifo(fd: RawFd) -> bool {
    let stat = fstat(fd);
    if stat.is_err() {
        return false;
    } else {
        (stat.unwrap().st_mode & 0170000) == 0010000
    }
}

pub fn fd_is_special(fd: RawFd) -> bool {
    let stat = fstat(fd);
    if stat.is_err() {
        return false;
    } else {
        (stat.unwrap().st_mode & 0170000) == 0100000
    }
}

pub fn fd_is_inet(fd: RawFd) -> bool {
    let addr = getsockname(fd);
    if addr.is_ok() {
        if let SockAddr::Inet(unix_addr) = addr.unwrap() {
            return true;
        }
    }
    return false;
}

pub fn fd_is_unix(fd: RawFd) -> bool {
    let addr = getsockname(fd);
    if addr.is_ok() {
        if let SockAddr::Unix(unix_addr) = addr.unwrap() {
            return true;
        }
    }
    return false;
}

pub fn fd_is_mq(fd: RawFd) -> bool {
    let attr = mq_getattr(fd);

    attr.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::os::unix::net::UnixListener;
    use std::os::unix::io::AsRawFd;
    use nix::unistd::dup2;
    use nix::unistd::{fork, ForkResult};
    use nix::sys::wait::waitpid;
    use std::{thread, time};
    use std::net::TcpListener;

    #[test]
    fn test_unix_socket_no_names() {
        let path = "./socket";
        match fork() {
            Ok(ForkResult::Parent { child, .. }) => {
                println!("Continuing execution in parent process, new child has pid: {}", child);
                let ten_millis = time::Duration::from_millis(10);
                thread::sleep(ten_millis);
                Command::new("ncat")
                        .args(&["-U", path])
                        .output()
                        .expect("failed to execute process");
                waitpid(child, None);
            }
            Ok(ForkResult::Child) => {
                std::fs::remove_file(path);
                let (stream, _) = UnixListener::bind(path).expect("UNIXSTREAM").accept().unwrap();
                let stream = stream.as_raw_fd();
                dup2(stream, 3);
                eprintln!("stream {}", stream);
                let pid = process::id();
                env::set_var("LISTEN_PID", pid.to_string());
                env::set_var("LISTEN_FDS", "1");
                env::set_var("LISTEN_FDNAMES", "");

                let fds = sd_listen_fds(false);
                eprintln!("{:?}", fds);
                assert!(fds.is_ok());
                assert!(fds.unwrap()[0].is_unix());
            }
            Err(_) => panic!("fork failed"),
        }
    }

    #[test]
    fn test_tcp_socket_no_names() {
        match fork() {
            Ok(ForkResult::Parent { child, .. }) => {
                println!("Continuing execution in parent process, new child has pid: {}", child);
                let ten_millis = time::Duration::from_millis(50);
                thread::sleep(ten_millis);
                let out = Command::new("ncat")
                        .args(&["-z", "127.0.0.1", "7878"])
                        .output()
                        .expect("failed to execute process");
                eprintln!("parent ret: {} output: {}", out.status, std::str::from_utf8(&out.stdout).unwrap());
                waitpid(child, None);
            }
            Ok(ForkResult::Child) => {
                let (stream, _) = TcpListener::bind("127.0.0.1:7878").expect("TCPLISTENER").accept().unwrap();
                let stream = stream.as_raw_fd();
                dup2(stream, 3);
                eprintln!("stream {}", stream);
                let pid = process::id();
                env::set_var("LISTEN_PID", pid.to_string());
                env::set_var("LISTEN_FDS", "1");
                env::set_var("LISTEN_FDNAMES", "");

                let fds = sd_listen_fds(false);
                eprintln!("{:?}", fds);
                assert!(fds.is_ok());
                assert!(fds.unwrap()[0].is_inet());
            }
            Err(_) => panic!("fork failed"),
        }
    }
}
