//! Turns user input (files, folders, list files) into a sorted, de-duplicated list of evidence items.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq)]
pub struct Item {
    pub index: u64,
    pub path: PathBuf,
    pub size: u64,
}

/// `inputs`: files or folders. `list_file`: a text file with one path per line (# comments allowed).
/// Folders are read one level deep unless `recursive`. Symbolic links are not followed.
pub fn collect(
    inputs: &[PathBuf],
    list_file: Option<&Path>,
    recursive: bool,
) -> Result<Vec<Item>, String> {
    let mut paths: Vec<PathBuf> = inputs.to_vec();
    if let Some(list) = list_file {
        let text = std::fs::read_to_string(list)
            .map_err(|e| format!("cannot read list file {}: {}", list.display(), e))?;
        let base = list.parent().unwrap_or(Path::new("."));
        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            let p = PathBuf::from(line);
            paths.push(if p.is_absolute() { p } else { base.join(p) });
        }
    }
    if paths.is_empty() {
        return Err("no input given: use --input FILE|FOLDER or --input-list FILE".into());
    }
    let mut files = BTreeSet::new();
    for p in &paths {
        let meta = std::fs::symlink_metadata(p)
            .map_err(|e| format!("cannot access {}: {}", p.display(), e))?;
        if meta.is_file() {
            files.insert(p.clone());
        } else if meta.is_dir() {
            let walker = walkdir::WalkDir::new(p)
                .follow_links(false)
                .max_depth(if recursive { usize::MAX } else { 1 });
            for entry in walker {
                let entry =
                    entry.map_err(|e| format!("cannot read folder {}: {}", p.display(), e))?;
                if entry.file_type().is_file() {
                    files.insert(entry.into_path());
                }
            }
        } else {
            return Err(format!(
                "{} is neither a file nor a folder (symbolic links are not followed)",
                p.display()
            ));
        }
    }
    let mut items = Vec::with_capacity(files.len());
    for (i, path) in files.into_iter().enumerate() {
        // Absolute paths in every record (no \\?\ prefix on Windows, symlinks not resolved).
        let path = std::path::absolute(&path).unwrap_or(path);
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        items.push(Item {
            index: i as u64 + 1,
            path,
            size,
        });
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_folders_lists_and_recursion() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("b.txt"), "b").unwrap();
        std::fs::write(d.path().join("a.txt"), "a").unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/c.txt"), "c").unwrap();
        std::fs::write(
            d.path().join("list.txt"),
            "# evidence\na.txt\n\nsub/c.txt\n",
        )
        .unwrap();

        let flat = collect(&[d.path().to_path_buf()], None, false).unwrap();
        assert_eq!(flat.len(), 3); // a, b, list.txt
        assert_eq!(flat[0].path.file_name().unwrap(), "a.txt");
        assert_eq!(flat[0].index, 1);

        let deep = collect(&[d.path().to_path_buf()], None, true).unwrap();
        assert_eq!(deep.len(), 4);

        let listed = collect(&[], Some(&d.path().join("list.txt")), false).unwrap();
        assert_eq!(listed.len(), 2);

        assert!(collect(&[], None, false).is_err());
        assert!(collect(&[d.path().join("missing")], None, false).is_err());
    }
}
