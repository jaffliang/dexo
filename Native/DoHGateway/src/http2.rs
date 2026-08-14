//! One-shot HTTP/2 request over an already-handshaked tokio-rustls stream.

use bytes::Bytes;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use crate::http::MAX_BODY_BYTES;

pub async fn exchange(
    tls: TlsStream<TcpStream>,
    method: &str,
    authority: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), String> {
    let (sender, connection) = h2::client::handshake(tls)
        .await
        .map_err(|error| format!("h2 handshake: {error}"))?;
    tokio::spawn(async move {
        if let Err(error) = connection.await {
            eprintln!("[DoHGateway] h2 connection: {error}");
        }
    });
    let mut sender = sender
        .ready()
        .await
        .map_err(|error| format!("h2 ready: {error}"))?;

    let uri = http::Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(path)
        .build()
        .map_err(|error| format!("h2 uri: {error}"))?;
    let mut builder = http::Request::builder()
        .method(
            http::Method::from_bytes(method.as_bytes())
                .map_err(|error| format!("h2 method: {error}"))?,
        )
        .uri(uri)
        .version(http::Version::HTTP_2);
    for (name, value) in headers {
        if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("connection") {
            continue;
        }
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder
        .body(())
        .map_err(|error| format!("h2 request: {error}"))?;
    let end_stream = body.is_empty();
    let (response, mut send_stream) = sender
        .send_request(request, end_stream)
        .map_err(|error| format!("h2 send: {error}"))?;
    if !end_stream {
        send_stream
            .send_data(Bytes::copy_from_slice(body), true)
            .map_err(|error| format!("h2 body: {error}"))?;
    }

    let response = response
        .await
        .map_err(|error| format!("h2 response: {error}"))?;
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect();

    let mut body_out = Vec::new();
    let mut incoming = response.into_body();
    while let Some(chunk) = incoming.data().await {
        let chunk = chunk.map_err(|error| format!("h2 read: {error}"))?;
        let len = chunk.len();
        body_out.extend_from_slice(&chunk);
        let _ = incoming.flow_control().release_capacity(len);
        if body_out.len() > MAX_BODY_BYTES {
            return Err("response too large".into());
        }
    }
    Ok((status, headers, body_out))
}
