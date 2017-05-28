#[cfg(windows)]
mod acl;
mod appcontainer;
mod winffi;

#[cfg(windows)]
fn main() {}

#[cfg(not(windows))]
fn main() {
    println!("Build target is not supported!");
}
