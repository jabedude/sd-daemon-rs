use sd_daemon::*;

fn main() {
    eprintln!("hello");
    let fds = sd_listen_fds_with_names(false).unwrap();
    eprintln!("{:?}", fds);
}
