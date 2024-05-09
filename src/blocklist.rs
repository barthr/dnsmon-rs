use std::{
    fs::read_to_string,
    io::{self},
    path::Path,
};

#[derive(Debug, Clone)]
pub struct BlockRule {
    value: String,
}

impl BlockRule {
    fn parse_from_string(string: &str) -> Self {
        Self {
            value: string.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct HostnameMatch<'a> {
    hostname: BlockRule,
    blocklist: &'a Blocklist,
}

#[derive(Debug)]
pub struct Blocklist {
    name: String,
    hostnames: Vec<BlockRule>,
}

impl Blocklist {
    pub fn new(name: &str, hostnames: Vec<BlockRule>) -> Self {
        Self {
            name: name.to_string(),
            hostnames,
        }
    }

    pub fn match_hostname(&self, hostname_to_find: &str) -> Option<HostnameMatch> {
        self.hostnames
            .iter()
            .find(|hostname| hostname.value.eq_ignore_ascii_case(hostname_to_find))
            .map(|hostname| HostnameMatch {
                hostname: hostname.clone(),
                blocklist: &self,
            })
    }

    pub fn from_file(file_path: &Path) -> Result<Self, io::Error> {
        // TODO: fix error handling
        let rules = read_blocklist_rules(&read_to_string(file_path)?);

        let filename = file_path
            .file_name()
            .expect("Expected a file name on path")
            .to_str()
            .unwrap();

        Ok(Self::new(filename, rules))
    }

    pub fn from_url(url: &str) -> Result<Self, reqwest::Error> {
        // TODO: fix this ugly unwrapping (PANIC)
        let response = reqwest::blocking::get(url).unwrap().text()?;
        let rules = read_blocklist_rules(&response);

        Ok(Self::new(url, rules))
    }
}

fn read_blocklist_rules(buffer: &str) -> Vec<BlockRule> {
    buffer
        .lines()
        .map(String::from)
        .map(|rule| BlockRule::parse_from_string(&rule))
        .collect()
}
