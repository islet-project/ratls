use async_trait::async_trait;
use log::debug;
use serde::Serialize;
use std::{os::unix::fs::MetadataExt, path::Path};
use tokio::fs;

use crate::GenericResult;

#[derive(Debug)]
pub struct Payload
{
    pub file: fs::File,
    pub size: u64,
    pub media_type: String,
}

#[derive(Debug, Default, Serialize)]
pub struct Listing
{
    pub dirs: Vec<String>,
    pub files: Vec<String>,
}

#[async_trait]
pub trait FilesProvider: Send + Sync
{
    fn get_root(&self) -> &str;
    async fn get_payload(&self, address: &str) -> GenericResult<Payload>;
    async fn get_listing(&self, address: &str) -> GenericResult<Listing>;
}

pub struct SimpleFiles
{
    root: String,
}

impl SimpleFiles
{
    pub fn new(root: &str) -> Self
    {
        Self {
            root: root.to_string(),
        }
    }
}

#[async_trait]
impl FilesProvider for SimpleFiles
{
    fn get_root(&self) -> &str
    {
        &self.root
    }

    async fn get_payload(&self, address: &str) -> GenericResult<Payload>
    {
        let path = Path::new(&self.root).join(address);

        if path.is_absolute() {
            return Err("Absolute file paths are forbidden!".into());
        }

        if !path.is_file() {
            return Err("Path is not a file".into());
        }

        let file = fs::File::open(&path)
            .await
            .map_err(|err| format!("Error opening \"{}\": {}", path.display(), err))?;

        let metadata = file
            .metadata()
            .await
            .map_err(|err| format!("Error reading metadata for \"{}\": {}", path.display(), err))?;

        let media_type = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();

        let payload = Payload {
            file,
            size: metadata.size(),
            media_type,
        };

        debug!("Payload to serve prepared: {:#?}", payload);

        Ok(payload)
    }

    async fn get_listing(&self, address: &str) -> GenericResult<Listing>
    {
        let path = Path::new(&self.root).join(address);

        if path.is_absolute() {
            return Err("Absolute file paths are forbidden!".into());
        }

        if !path.is_dir() {
            return Err("Path is not a directory".into());
        }

        let mut dir_state = fs::read_dir(&path)
            .await
            .map_err(|err| format!("Error reading directory \"{}\": {}", path.display(), err))?;

        let mut listing = Listing::default();
        while let Some(dir_entry) = dir_state.next_entry().await? {
            let file_name = dir_entry.file_name().to_string_lossy().into_owned();
            let file_type = dir_entry.file_type().await.map_err(|err| {
                format!("Cannot get file_type of \"{}\": {}", path.display(), err)
            })?;
            if file_type.is_dir() {
                listing.dirs.push(file_name);
            } else if file_type.is_file() {
                listing.files.push(file_name);
            }
        }

        debug!("Listing to serve prepared: {:#?}", listing);

        Ok(listing)
    }
}
