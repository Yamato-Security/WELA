use csv::ReaderBuilder;
use std::error::Error;
use std::{env, fs};
use std::fs::write;
use serde_json::{json, Value};
use walkdir::WalkDir;
use yaml_rust2::{Yaml, YamlLoader};

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

fn extract_event_ids(yaml: &Yaml, event_ids: &mut Vec<String>) {
    match yaml {
        Yaml::Hash(hash) => {
            for (key, value) in hash {
                if key.as_str() == Some("EventID") {
                    match value {
                        Yaml::Array(ids) => {
                            for id in ids {
                                if let Some(id) = id.as_i64() {
                                    event_ids.push(id.to_string());
                                } else if let Some(id) = id.as_str() {
                                    event_ids.push(id.to_string());
                                }
                            }
                        }
                        Yaml::String(id) => {
                            event_ids.push(id.clone());
                        }
                        Yaml::Integer(id) => {
                            event_ids.push(id.to_string());
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

fn parse_yaml(doc: Yaml, eid_subcategory_pair: &Vec<(String, String)>) -> Option<Value> {
    if let Some(logsource) = doc["logsource"].as_hash() {
        if let Some(service) = logsource.get(&Yaml::from_str("service")) {
            if service.as_str() == Some("security") {
                let uuid = doc["id"].as_str().unwrap_or("No UUID");
                let title = doc["title"].as_str().unwrap_or("No title");
                let desc = doc["description"].as_str().unwrap_or("No description");
                let level = doc["level"].as_str().unwrap_or("No level");
                let mut event_ids = Vec::new();
                extract_event_ids(&doc, &mut event_ids);
                let mut subcategories = Vec::new();
                for event_id in &event_ids {
                    for (eid, subcategory) in eid_subcategory_pair {
                        if eid == event_id {
                            subcategories.push(subcategory.clone());
                        }
                    }
                }
                return Some(json!({
                    "id": uuid,
                    "title": title,
                    "description": desc,
                    "level": level,
                    "event_ids": event_ids,
                    "subcategory_guids": subcategories
                }));
            }
        }
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
    if args.len() != 3 {
        eprintln!("Usage: {} <file_path> <dir>", args[0]);
        std::process::exit(1);
    }

    let file_path = &args[1];
    let eid_subcategory_pair = load_event_id_guid_pairs(file_path).unwrap();

    let dir = &args[2];
    let yml_files = list_yml_files(dir);
    let mut results = Vec::new();

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
    write("../config/hayabusa_rules_meta.json", json_output)?;
    Ok(())
}
