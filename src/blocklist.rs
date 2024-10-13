use crate::hash;
use libbpf_rs::{Error, Map, MapFlags};
use once_cell::sync::Lazy;
use regex::Regex;
use std::{collections::HashSet, fs::read_to_string, hash::Hash, io, path::Path};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct Domain {
    hostname: String,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidDomain,
}

// Use Lazy to ensure the regex is only compiled once
static DOMAIN_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$").unwrap());

impl Domain {
    pub fn parse(domain: &str) -> Result<Self, ParseError> {
        if DOMAIN_REGEX.is_match(domain) {
            Ok(Self {
                hostname: domain.to_string(),
            })
        } else {
            Err(ParseError::InvalidDomain)
        }
    }

    fn hash(&self) -> [u8; 4] {
        hash::fnv1a_32(self.hostname.as_bytes()).to_le_bytes()
    }

    pub fn add_to_dataplane(&self, map: &Map) -> Result<(), Error> {
        map.update(&[], &self.hash(), MapFlags::ANY)
    }
}

#[derive(Debug)]
pub struct Blocklist {
    name: String,
    hostnames: HashSet<Domain>,
}

impl Blocklist {
    pub fn new(name: &str, hostnames: HashSet<Domain>) -> Self {
        Self {
            name: name.to_string(),
            hostnames,
        }
    }

    pub fn match_hostname(&self, hostname_to_find: &str) -> bool {
        Domain::parse(hostname_to_find)
            .map(|domain| self.hostnames.contains(&domain))
            .is_ok()
    }

    pub fn add_to_dataplane(&self, map: &Map) -> Result<(), Error> {
        println!(
            "Adding {} hostnames from {} to dataplane",
            self.hostnames.len(),
            self.name
        );

        for ele in &self.hostnames {
            ele.add_to_dataplane(map)?
        }
        Ok(())
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

fn read_blocklist_rules(buffer: &str) -> HashSet<Domain> {
    buffer
        .lines()
        .map(String::from)
        .map(|rule| Domain::parse(&rule).unwrap()) // Ugly unwrap here (should handle error)
        .into_iter()
        .collect()
}
