use crate::utilities::terminal::output::OutputDisplayMode::{Table, Tree};
use crate::utilities::errors::VerificationError;
use std::process::exit;
use crate::VERSION;
use crate::utilities::serial::api::{Crate, filter_wildcards};
use crate::management::api::ApiManager;

#[derive(Debug, Clone)]
pub enum OutputDisplayType {
    Blank,
    Entry,
    DepEntry,
    Title,
    Header,
    Guide,
    End,
}

#[derive(Debug, Clone)]
pub struct DisplayLine {
    pub display_type: OutputDisplayType,
    pub cells: Vec<DisplayCell>,
}

#[derive(Debug, Clone)]
pub struct DisplayCell {
    pub text: String,
    pub width: usize,
    pub color: String,
}

pub struct OutputManager {
    pub display_mode: OutputDisplayMode,
    pub display_width: usize,
}

pub enum OutputDisplayMode {
    Tree,
    Table,
}

impl OutputManager {
    pub fn new(mode: u8, width: usize) -> OutputManager {
        let mut man = OutputManager {
            display_mode: OutputDisplayMode::Table,
            display_width: width,
        };

        match mode {
            0 => {
                man.display_mode = Table;
            }
            1 => {
                man.display_mode = Tree;
            }
            _ => {
                man.display_mode = Table;
            }
        };

        man
    }

    pub async fn check_update(&self) {
        let remote_result: Result<Crate, VerificationError> = (ApiManager::new()).get_crate("version-checker", VERSION).await;
        if let Ok(version_checker) = remote_result {
            if version_checker.is_current() || version_checker.is_current_unstable() {
                let message = format!("A new update is available to install\n{} -> {}\nUse cargo install version-checker to install", filter_wildcards(version_checker.version.unwrap()), filter_wildcards(version_checker.latest_stable.unwrap()));
                print!(" \x1b[90;1m╔");
                for _ in 0..50 {
                    print!("═")
                }
                println!("╗");

                for line in message.split("\n") {
                    print!(" ║");
                    for _ in 0..(25 - line.len() / 2) {
                        print!(" ");
                    }
                    if line.contains(" -> ") {
                        let halves: Vec<&str> = line.split(" -> ").collect();
                        print!("\x1b[31m{}\x1b[35m -> \x1b[32m{}\x1b[90;1m", halves[0], halves[1]);
                    } else if line.contains("cargo install version-checker") {
                        let halves: Vec<&str> = line.split(" cargo install version-checker ").collect();
                        print!("\x1b[35m{}\x1b[33m cargo install version-checker \x1b[35m{}\x1b[90;1m", halves[0], halves[1]);
                    } else {
                        print!("\x1b[35m{}\x1b[90;1m", line);
                    }
                    for _ in 0..(25 - line.len() / 2) {
                        print!(" ");
                    }
                    println!("║");
                }

                print!(" ╚");
                for _ in 0..50 {
                    print!("═")
                }
                println!("╝\x1b[0m");
                println!();
            }
        }
    }


    pub fn render(&self, content: DisplayLine) {
        match content.display_type {
            OutputDisplayType::Blank => {
                println!();
            }
            OutputDisplayType::Entry => {
                let mut index = 0;
                for mut cell in content.cells {
                    match index {
                        0 => {
                            while cell.text.len() < cell.width {
                                cell.text = format!(" {}", cell.text);
                            }
                            print!(" \x1b[90;1m║\x1b[0m {}{}\x1b[0m \x1b[90;1m│\x1b[0m ", cell.color, cell.text)
                        }
                        3 => {
                            let mut border = "".to_string();

                            while (border.len() + (cell.text.len() + 4)) < cell.width {
                                border = format!("{} ", border);
                            }

                            print!("{}{}\x1b[0m{} \x1b[90;1m║\x1b[0m ", cell.color, cell.text, border);
                        }
                        2 => {
                            let mut border = "".to_string();

                            while (border.len() + (cell.text.len() + 4)) < cell.width {
                                border = format!("{} ", border);
                            }

                            print!("{}{}\x1b[0m{} \x1b[90;1m│\x1b[0m ", cell.color, cell.text, border);
                        }
                        1 => {
                            let mut border = "".to_string();

                            while (border.len() + (cell.text.len() + 4)) < cell.width {
                                border = format!("{} ", border);
                            }

                            print!("{}{}\x1b[0m{} \x1b[90;1m│\x1b[0m ", cell.color, cell.text, border);
                        }
                        _ => {}
                    }
                    index += 1;
                }
                println!()
            }
            OutputDisplayType::DepEntry => {
                let mut index = 0;
                for mut cell in content.cells {
                    match index {
                        0 => {
                            while cell.text.len() < cell.width {
                                cell.text = format!(" {}", cell.text);
                            }
                            print!(" \x1b[90;1m║\x1b[0m {}{}\x1b[0m \x1b[90;1m│\x1b[0m ", cell.color, cell.text)
                        }
                        3 => {
                            let mut border = "".to_string();

                            while (border.len() + (cell.text.len() + 4)) < cell.width + 6 {
                                border = format!("{} ", border);
                            }

                            print!("{}{}\x1b[0m{} \x1b[90;1m║\x1b[0m ", cell.color, cell.text, border);
                        }
                        2 => {
                            let mut border = "".to_string();

                            while (border.len() + (cell.text.len() + 4)) < cell.width {
                                border = format!("{} ", border);
                            }

                            print!("{}{}\x1b[0m{} \x1b[90;1m│\x1b[0m ", cell.color, cell.text, border);
                        }
                        1 => {
                            let mut border = "".to_string();

                            while (border.len() + (cell.text.len() + 4)) < cell.width {
                                border = format!("{} ", border);
                            }

                            print!("{}{}\x1b[0m{} \x1b[90;1m│\x1b[0m ", cell.color, cell.text, border);
                        }
                        _ => {}
                    }
                    index += 1;
                }
                println!()
            }
            OutputDisplayType::Title => {
                let mut line = "".to_string();
                let _ = line.clone();
                line = format!("╔");
                for _ in 0..((self.display_width - (content.cells[0].text.len() + 4)) / 2) - 1 {
                    line = format!("{}═", line);
                }

                line = format!("{}╡ {} ╞", line, content.cells[0].text);

                for _ in 0..((self.display_width - (content.cells[0].text.len() + 4)) / 2) - 1 {
                    line = format!("{}═", line);
                }

                if content.cells[0].text.len() % 2 > 0 {
                    line = format!("{}═", line);
                }

                line = format!("{}╗", line);
                println!(" \x1b[90;1m{}\x1b[0m", line);
            }
            OutputDisplayType::Guide => {
                print!(" \x1b[90;1m╟");
                for index in 0..self.display_width - 2 {
                    if index == 13 || index == 37 || index == 61 {
                        print!("┼");
                    } else {
                        print!("─");
                    }
                }
                println!("╢\x1b[0m");
            }
            OutputDisplayType::Header => {}
            OutputDisplayType::End => {
                let text = format!("Kalavar Version Checker v{}", VERSION);
                let mut line = "".to_string();
                let _ = line.clone();
                line = format!("╚");
                for _ in 0..((self.display_width - (text.len() + 4)) / 2) - 2 {
                    line = format!("{}═", line);
                }

                line = format!("{}╡ {} ╞", line, text);

                for _ in 0..((self.display_width - (text.len() + 4)) / 2) {
                    line = format!("{}═", line);
                }

                if text.len() % 2 > 0 {
                    line = format!("{}═", line);
                }

                line = format!("{}╝", line);
                println!(" \x1b[90;1m{}\x1b[0m", line);
            }
        }
    }

    pub fn debug_error(&self, content: VerificationError) {
        println!("{:?}", content);
    }

    pub fn error(content: VerificationError) {
        println!("{:?}", content);
        exit(1)
    }
}


impl DisplayLine {
    pub fn new_guide() -> DisplayLine {
        DisplayLine {
            display_type: OutputDisplayType::Guide,
            cells: vec![],
        }
    }

    pub fn new_table_end() -> DisplayLine {
        DisplayLine {
            display_type: OutputDisplayType::End,
            cells: vec![],
        }
    }

    pub fn new_title(title: &str) -> DisplayLine {
        DisplayLine {
            display_type: OutputDisplayType::Title,
            cells: vec![DisplayCell {
                text: title.to_string(),
                width: 0,
                color: "\x1b[36m".to_string(),
            }],
        }
    }

    pub fn new_crate(name: String, local: String, remote: String, advisories: u16) -> DisplayLine {
        DisplayLine {
            display_type: OutputDisplayType::Entry,
            cells: vec![
                DisplayCell {
                    text: format!("{}", advisories),
                    width: 11,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: filter_wildcards(local).to_string(),
                    width: 25,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: filter_wildcards(remote).to_string(),
                    width: 25,
                    color: "\x1b[32m".to_string(),
                },
                DisplayCell {
                    text: name,
                    width: 50,
                    color: "\x1b[36m".to_string(),
                },
            ],
        }
    }

    pub fn new_crate_dep(name: String, local: String, remote: String, advisories: u16, indenter: &str) -> DisplayLine {
        DisplayLine {
            display_type: OutputDisplayType::DepEntry,
            cells: vec![
                DisplayCell {
                    text: format!("{}", advisories),
                    width: 11,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: filter_wildcards(local).to_string(),
                    width: 25,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: filter_wildcards(remote).to_string(),
                    width: 25,
                    color: "\x1b[32m".to_string(),
                },
                DisplayCell {
                    text: format!("{} {}", indenter, name),
                    width: 50,
                    color: "\x1b[36m".to_string(),
                },
            ],
        }
    }

    pub fn new_header() -> DisplayLine {
        DisplayLine {
            display_type: OutputDisplayType::Entry,
            cells: vec![
                DisplayCell {
                    text: "Advisories".to_string(),
                    width: 11,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: "Version".to_string(),
                    width: 25,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: "Latest".to_string(),
                    width: 25,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: "Dependency".to_string(),
                    width: 50,
                    color: "\x1b[36m".to_string(),
                },
            ],
        }
    }

    pub fn new_footer() -> DisplayLine {
        DisplayLine {
            display_type: OutputDisplayType::Entry,
            cells: vec![
                DisplayCell {
                    text: "Advisories".to_string(),
                    width: 11,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: "Up To Date".to_string(),
                    width: 25,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: "Out Of Date".to_string(),
                    width: 25,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: "Total Dependencies".to_string(),
                    width: 50,
                    color: "\x1b[36m".to_string(),
                }
            ],
        }
    }

    pub fn new_footer_content(utd: u32, ood: u32, advisories: u32, warn: u32) -> DisplayLine {
        let mut d = DisplayLine {
            display_type: OutputDisplayType::Entry,
            cells: vec![
                DisplayCell {
                    text: format!("{}", advisories),
                    width: 11,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: format!("{}", utd),
                    width: 25,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: format!("{}", ood),
                    width: 25,
                    color: "\x1b[36m".to_string(),
                },
                DisplayCell {
                    text: format!("{}", utd + ood + warn),
                    width: 50,
                    color: "\x1b[36m".to_string(),
                },
            ],
        };

        if advisories > 0 {
            d.cells[0].color = "\x1b[31m".to_string();
        } else {
            d.cells[0].color = "\x1b[32m".to_string();
        }

        if utd > 0 {
            d.cells[2].color = "\x1b[32m".to_string();
        }

        if ood > 0 {
            d.cells[3].color = "\x1b[31m".to_string();
        }

        d
    }
}