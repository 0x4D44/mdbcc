use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

fn explicit_bins(manifest: &str) -> BTreeMap<String, String> {
    let mut bins = BTreeMap::new();
    let mut in_bin = false;
    let mut name: Option<String> = None;
    let mut path: Option<String> = None;

    for raw_line in manifest.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') {
            if in_bin
                && let (Some(name), Some(path)) = (name.take(), path.take())
            {
                bins.insert(name, path);
            }
            in_bin = line == "[[bin]]";
            name = None;
            path = None;
            continue;
        }

        if !in_bin {
            continue;
        }

        if let Some(value) = line.strip_prefix("name = ") {
            name = quoted_value(value);
        } else if let Some(value) = line.strip_prefix("path = ") {
            path = quoted_value(value);
        }
    }

    if in_bin
        && let (Some(name), Some(path)) = (name, path)
    {
        bins.insert(name, path);
    }

    bins
}

fn quoted_value(value: &str) -> Option<String> {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .map(str::to_owned)
}

#[test]
fn src_bin_tools_are_declared_explicitly_in_cargo_toml() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = fs::read_to_string(root.join("Cargo.toml")).expect("read Cargo.toml");
    let bins = explicit_bins(&manifest);

    for entry in fs::read_dir(root.join("src/bin")).expect("read src/bin") {
        let entry = entry.expect("read src/bin entry");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }

        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .expect("utf-8 tool name");
        let relative_path = format!("src/bin/{stem}.rs");

        assert_eq!(
            bins.get(stem).map(String::as_str),
            Some(relative_path.as_str()),
            "{stem} must have an explicit [[bin]] entry in Cargo.toml"
        );
    }
}
