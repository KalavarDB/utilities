use clap::{App, Arg};

pub mod management;
pub mod utilities;

#[cfg(test)]
pub mod tests;

pub const VERSION: &str = "0.1.1";

fn main() {
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
        // Temporarily disabled flag, Disabled because it hasn't been implemented
        // .arg(Arg::with_name("deep")
        //     .short("d")
        //     .long("deep")
        //     .takes_value(false)
        //     .required(false)
        //     .help("Checks the dependencies of each of your dependencies, deepens search by 1 level")
        // )
        .get_matches();

    let mut recursion = 0;
    let mut updates = true;

    if matches.is_present("deep") {
        recursion = 1;
    }

    if matches.is_present("no-update") {
        updates = false;
    }

    let manifest = matches.value_of("manifest");

    utilities::terminal::input::parse_args(manifest, recursion, updates)
}
