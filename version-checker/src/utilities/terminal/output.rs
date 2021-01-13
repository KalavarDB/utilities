use crate::utilities::terminal::output::OutputDisplayMode::{Table, Tree};

pub struct OutputManager {
    pub display_mode: OutputDisplayMode,
    pub lines: Vec<String>,
}

pub enum OutputDisplayMode {
    Tree,
    Table,
}

impl OutputManager {
    pub fn new(mode: u8) -> OutputManager {
        let mut man = OutputManager {
            display_mode: OutputDisplayMode::Table,
            lines: vec!(),
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

    pub fn render(&mut self, content: &str) {
        self.lines.push(content.to_string());

        for line in self.lines {
            println!("{}", line)
        }
    }


}