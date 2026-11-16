use std::{env, fs, path::Path};

fn collect(root: &Path, path: &Path, output: &mut String) {
    let mut entries = fs::read_dir(path)
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        if entry.file_type().unwrap().is_dir() {
            collect(root, &path, output);
        } else if path.extension().is_some_and(|ext| ext == "yaml") {
            let relative = path
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            output.push_str(&format!(
                "({relative:?}, include_str!({:?})),\n",
                path.to_str().unwrap()
            ));
        }
    }
}

fn main() {
    let root = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../collection")
        .canonicalize()
        .unwrap();
    println!("cargo:rerun-if-changed={}", root.display());
    let mut output = String::from("pub const ASSETS: &[(&str, &str)] = &[\n");
    collect(&root, &root, &mut output);
    output.push_str("];\n");
    fs::write(
        Path::new(&env::var("OUT_DIR").unwrap()).join("assets.rs"),
        output,
    )
    .unwrap();
}
