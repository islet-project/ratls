use async_trait::async_trait;
use log::{debug, error};
use std::{os::unix::fs::MetadataExt, path::Path};
use tokio::fs;

#[derive(Debug)]
pub struct Payload
{
    pub file: fs::File,
    pub size: u64,
    pub media_type: String,
}

#[async_trait]
pub trait FilesProvider: Send + Sync
{
    fn get_root(&self) -> &str;
    async fn get_payload(&self, address: &str) -> Option<Payload>;
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

    async fn get_payload(&self, address: &str) -> Option<Payload>
    {
        let path = Path::new(&self.root).join(address);
        let filename = match path.file_name() {
            Some(filename) => filename.to_string_lossy().into_owned(),
            None => {
                error!("The address: {} didn't yield a proper filename", address);
                return None;
            }
        };

        let file = match fs::File::open(&path).await {
            Ok(file) => file,
            Err(err) => {
                error!("Error opening \"{}\": {}", path.display(), err);
                return None;
            }
        };

        let metadata = match file.metadata().await {
            Ok(metadata) => metadata,
            Err(err) => {
                error!("Error reading metadata for \"{}\": {}", path.display(), err);
                return None;
            }
        };

        let media_type = mime_guess::from_path(filename)
            .first_or_octet_stream()
            .to_string();

        let payload = Payload {
            file,
            size: metadata.size(),
            media_type,
        };

        debug!("Payload to serve prepared: {:#?}", payload);

        Some(payload)
    }
}
