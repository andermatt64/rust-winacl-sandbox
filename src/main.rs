#[cfg(windows)]
mod acl;
mod appcontainer;
mod winffi;

#[cfg(windows)]
fn main() {
    println!("Wilkommen!");
}

#[cfg(not(windows))]
fn main() {
    println!("Build target is not supported!");
}
