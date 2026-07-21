use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::VsockStream;

#[derive(Serialize)]
pub struct ProxyRequest
{
    pub command: String,
    pub server_addr: String,
}

#[derive(Deserialize)]
pub struct ProxyResponse
{
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

async fn send_request(
    stream: &mut VsockStream,
    request: &ProxyRequest,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let mut req_str = serde_json::to_string(&request)?;
    req_str.push('\n');
    stream.write_all(req_str.as_bytes()).await?;
    stream.flush().await?;

    Ok(())
}

async fn receive_response(
    stream: &mut VsockStream,
) -> Result<ProxyResponse, Box<dyn std::error::Error + Send + Sync>>
{
    let mut response_str = String::new();
    let mut buf = [0u8; 1024];

    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err("Connection closed before proxy response".into());
        }

        if let Some(pos) = buf[..n].iter().position(|&b| b == b'\n') {
            response_str.push_str(std::str::from_utf8(&buf[..pos])?);
            break;
        }

        response_str.push_str(std::str::from_utf8(&buf[..n])?);
    }

    let response: ProxyResponse = serde_json::from_str(&response_str)
        .map_err(|e| format!("Failed to parse proxy response: {}", e))?;

    Ok(response)
}

pub async fn connect(
    stream: &mut VsockStream,
    hostname: &str,
    dest_port: u16,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
{
    let server_addr = format!("{}:{}", hostname, dest_port);

    let request = ProxyRequest {
        command: "CONNECT".to_string(),
        server_addr,
    };

    send_request(stream, &request).await?;
    let response = receive_response(stream).await?;

    if response.status != "SUCCESS" {
        return Err(format!("Proxy connection failed: {:?}", response.reason).into());
    }

    Ok(())
}
