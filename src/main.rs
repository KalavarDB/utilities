use clap::{App, Arg};

mod management;
mod utilities;

#[cfg(test)]
pub mod tests;

pub const VERSION: &str = "0.2.0";
#[tokio::main]
async fn main() {
    let matches = App::new("Version Checker")
        .version(VERSION)
        .author("Thomas B. <tom.b.2k2@gmail.com>")
        .about("Combs your Cargo.toml for dependencies, and checks their versions whilst also looking for potential security advisories")
        .arg(Arg::with_name("manifest")
            .short("m")
            .long("manifest")
            .takes_value(true)
            .required(false)
            .help("The path to a Cargo.toml file, if missing, the program will attempt to auto-locate the Cargo.toml")
        )
        .arg(Arg::with_name("no-update")
            .short("N")
            .long("no-update")
            .takes_value(false)
            .required(false)
            .help("Disables the \"Update Available\" message until next use")
        )
        .arg(Arg::with_name("deep")
            .short("d")
            .long("deep")
            .takes_value(false)
            .required(false)
            .help("Checks the dependencies of each of your dependencies, deepens search by 1 level")
        )
        .arg(Arg::with_name("transient")
            .short("t")
            .long("transient")
            .takes_value(false)
            .required(false)
            .help("Checks all dependencies right down to the roots of the tree")
        )
        .get_matches();

    let mut recursion = 0;
    let mut updates = true;

    if matches.is_present("deep") {
        recursion = 1;
    }

    if matches.is_present("transient") {
        recursion = 2;
    }

    if matches.is_present("no-update") {
        updates = false;
    }

    let manifest = matches.value_of("manifest");

    utilities::terminal::input::parse_args(manifest, recursion, updates).await;
}
