use sd_daemon::*;
use std::os::unix::net::UnixStream;
use std::os::unix::io::FromRawFd;
use std::os::unix::fs::FileTypeExt;

fn main() {
    eprintln!("hello");
    let fds = sd_listen_fds(false).unwrap();
    eprintln!("{:?}", fds);
}
