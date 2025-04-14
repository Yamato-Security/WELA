use csv::ReaderBuilder;
use serde_json::{Value, json};
use std::collections::HashSet;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fs::write;
use std::{env, fs};
use walkdir::WalkDir;
use yaml_rust2::{Yaml, YamlLoader};

enum Channel {
    Security,
    PowerShell,
    Other(String),
}

impl Display for Channel {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Channel::Security => write!(f, "sec"),
            Channel::PowerShell => write!(f, "pwsh"),
            Channel::Other(name) => write!(f, "{}", name),
        }
    }
}

fn list_yml_files(dir: &str) -> Vec<String> {
    let mut yml_files = Vec::new();
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("yml") {
            if let Some(path_str) = path.to_str() {
                yml_files.push(path_str.to_string());
            }
        }
    }

    yml_files
}

fn extract_event_ids(yaml: &Yaml, event_ids: &mut HashSet<String>) {
    match yaml {
        Yaml::Hash(hash) => {
            for (key, value) in hash {
                if key.as_str() == Some("EventID") {
                    match value {
                        Yaml::Array(ids) => {
                            for id in ids {
                                if let Some(id) = id.as_i64() {
                                    event_ids.insert(id.to_string());
                                } else if let Some(id) = id.as_str() {
                                    event_ids.insert(id.to_string());
                                }
                            }
                        }
                        Yaml::String(id) => {
                            event_ids.insert(id.clone());
                        }
                        Yaml::Integer(id) => {
                            event_ids.insert(id.to_string());
                        }
                        _ => {}
                    }
                } else {
                    extract_event_ids(value, event_ids);
                }
            }
        }
        Yaml::Array(array) => {
            for item in array {
                extract_event_ids(item, event_ids);
            }
        }
        _ => {}
    }
}

fn contains_builtin_channel(yaml: &Yaml) -> Option<Vec<Channel>> {
    fn check_channel(value: &Yaml) -> Option<Channel> {
        match value.as_str() {
            Some("Security") => Some(Channel::Security),
            Some("Microsoft-Windows-PowerShell/Operational")
            | Some("PowerShellCore/Operational")
            | Some("Windows PowerShell") => Some(Channel::PowerShell),
            val => Some(Channel::Other(val?.to_string())),
        }
    }

    match yaml {
        Yaml::Hash(hash) => {
            for (key, value) in hash {
                if key.as_str() == Some("Channel") {
                    match value {
                        Yaml::Array(array) => {
                            let mut channels = Vec::new();
                            for item in array {
                                if let Some(channel) = check_channel(item) {
                                    channels.push(channel);
                                }
                            }
                            if !channels.is_empty() {
                                return Some(channels);
                            }
                        }
                        Yaml::String(_) => {
                            if let Some(channel) = check_channel(value) {
                                return Some(vec![channel]);
                            }
                        }
                        _ => {}
                    }
                } else if let Some(channel) = contains_builtin_channel(value) {
                    return Some(channel);
                }
            }
        }
        Yaml::Array(array) => {
            for item in array {
                if let Some(channel) = contains_builtin_channel(item) {
                    return Some(channel);
                }
            }
        }
        _ => {}
    }
    None
}

fn parse_yaml(doc: Yaml, eid_subcategory_pair: &Vec<(String, String)>) -> Option<Value> {
    let sysmon_tag = doc["tags"].as_vec().map_or(false, |tags| tags.iter().any(|tag| tag.as_str() == Some("sysmon")));
    if sysmon_tag {
        return None;
    }
    if let Some(ch) = contains_builtin_channel(&doc["detection"]) {
        let uuid = doc["id"].as_str().unwrap_or("");
        let title = doc["title"].as_str().unwrap_or("");
        let level = doc["level"].as_str().unwrap_or("");
        let mut event_ids = HashSet::new();
        let mut subcategories = HashSet::new();
        extract_event_ids(&doc, &mut event_ids);
        for event_id in &event_ids {
            for (eid, subcategory) in eid_subcategory_pair {
                if eid == event_id {
                    subcategories.insert(subcategory.clone());
                }
            }
        }
        let event_ids: Vec<String> = event_ids.into_iter().collect();
        let subcategories: Vec<String> = subcategories.into_iter().collect();
        return Some(json!({
            "id": uuid,
            "title": title,
            "channel": ch.iter().map(|c| c.to_string()).collect::<Vec<String>>(),
            "level": level,
            "event_ids": event_ids,
            "subcategory_guids": subcategories
        }));
    }
    None
}

fn load_event_id_guid_pairs(file_path: &str) -> Result<Vec<(String, String)>, Box<dyn Error>> {
    let mut rdr = ReaderBuilder::new()
        .has_headers(true)
        .from_path(file_path)?;

    let mut pairs = Vec::new();
    for result in rdr.records() {
        let record = result?;
        let event_id = record.get(0).unwrap_or("").to_string();
        let guid = record.get(3).unwrap_or("").to_string();
        if !event_id.is_empty() && !guid.is_empty() {
            pairs.push((event_id, guid));
        }
    }
    Ok(pairs)
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <file_path> <dir>", args[0]);
        std::process::exit(1);
    }

    let dir = &args[1];
    let yml_files = list_yml_files(dir);
    let mut results = Vec::new();

    let file_path = &args[2];
    let eid_subcategory_pair = load_event_id_guid_pairs(file_path)?;

    let out = &args[3];

    for file in yml_files {
        let contents = fs::read_to_string(&file).expect("Unable to read file");
        let docs = YamlLoader::load_from_str(&contents).expect("Unable to parse YAML");
        for doc in docs {
            if let Some(res) = parse_yaml(doc, &eid_subcategory_pair) {
                results.push(res);
            }
        }
    }

    let json_output = serde_json::to_string_pretty(&results)?;
    println!("{}", json_output);
    write(out, json_output)?;
    Ok(())
}
