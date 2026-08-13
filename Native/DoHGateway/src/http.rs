//! HTTP/1.1 response framing so the gateway can stop reading when the body
//! is complete instead of waiting for the origin to close the TLS stream.

use tokio::io::AsyncReadExt;

pub const MAX_HEADER_BYTES: usize = 64 * 1024;
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;

const DELIM: &[u8] = b"\r\n\r\n";

/// Reads one complete HTTP/1 response. Stops at Content-Length or the last
/// chunked chunk. Connection-close bodies are accepted only on EOF.
pub async fn read_http_response<S>(stream: &mut S) -> Result<Vec<u8>, String>
where
    S: AsyncReadExt + Unpin,
{
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("read: {error}"))?;
        if n == 0 {
            return match complete_response_len(&buffer, true)? {
                Some(len) if len > 0 => {
                    buffer.truncate(len);
                    Ok(buffer)
                }
                _ => {
                    if buffer.is_empty() {
                        Err("empty response".into())
                    } else {
                        Err("closed before complete response".into())
                    }
                }
            };
        }
        buffer.extend_from_slice(&chunk[..n]);
        if buffer.len() > MAX_HEADER_BYTES + MAX_BODY_BYTES {
            return Err("response too large".into());
        }
        if let Some(len) = complete_response_len(&buffer, false)? {
            buffer.truncate(len);
            return Ok(buffer);
        }
    }
}

pub fn complete_response_len(buffer: &[u8], connection_closed: bool) -> Result<Option<usize>, String> {
    let Some(header_end) = find_delim(buffer) else {
        if buffer.len() > MAX_HEADER_BYTES {
            return Err("response headers too large".into());
        }
        return Ok(None);
    };
    if header_end > MAX_HEADER_BYTES {
        return Err("response headers too large".into());
    }
    let headers_end = header_end + DELIM.len();
    let head = parse_head(&buffer[..header_end])?;
    if head.no_body {
        return Ok(Some(headers_end));
    }
    if head.chunked {
        return match chunked_encoded_len(&buffer[headers_end..])? {
            Some(body_len) => Ok(Some(headers_end + body_len)),
            None => Ok(None),
        };
    }
    if let Some(len) = head.content_length {
        if len > MAX_BODY_BYTES {
            return Err("response body too large".into());
        }
        let total = headers_end + len;
        if buffer.len() >= total {
            return Ok(Some(total));
        }
        return Ok(None);
    }
    if connection_closed && headers_end <= buffer.len() {
        return Ok(Some(buffer.len()));
    }
    Ok(None)
}

pub fn status_and_decoded_body(message: &[u8]) -> Result<(u16, Vec<u8>), String> {
    let header_end = find_delim(message).ok_or_else(|| "HTTP response missing header delimiter".to_string())?;
    let headers_end = header_end + DELIM.len();
    let head = parse_head(&message[..header_end])?;
    let raw_body = if headers_end <= message.len() {
        &message[headers_end..]
    } else {
        &[]
    };
    if head.no_body {
        return Ok((head.status, Vec::new()));
    }
    let body = if head.chunked {
        decode_chunked(raw_body)?
    } else if let Some(len) = head.content_length {
        if raw_body.len() < len {
            return Err("truncated HTTP body".into());
        }
        raw_body[..len].to_vec()
    } else {
        raw_body.to_vec()
    };
    Ok((head.status, body))
}

struct Head {
    status: u16,
    chunked: bool,
    content_length: Option<usize>,
    no_body: bool,
}

fn parse_head(header_bytes: &[u8]) -> Result<Head, String> {
    let header_text = std::str::from_utf8(header_bytes).map_err(|_| "HTTP headers not utf8")?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let mut chunked = false;
    let mut content_length = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"));
        }
        if name.eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse()
                    .map_err(|_| "invalid content-length".to_string())?,
            );
        }
    }
    let no_body = status / 100 == 1 || status == 204 || status == 304;
    Ok(Head {
        status,
        chunked,
        content_length,
        no_body,
    })
}

fn find_delim(buffer: &[u8]) -> Option<usize> {
    buffer.windows(DELIM.len()).position(|window| window == DELIM)
}

fn find_crlf(buffer: &[u8], from: usize) -> Option<usize> {
    buffer[from..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| from + index)
}

fn chunked_encoded_len(body: &[u8]) -> Result<Option<usize>, String> {
    let mut offset = 0usize;
    loop {
        let Some(line_end) = find_crlf(body, offset) else {
            return Ok(None);
        };
        let size_line = std::str::from_utf8(&body[offset..line_end]).map_err(|_| "chunk size not utf8")?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| "invalid chunk size".to_string())?;
        if size > MAX_BODY_BYTES {
            return Err("chunk too large".into());
        }
        let data_start = line_end + 2;
        if size == 0 {
            let mut trailer = data_start;
            loop {
                let Some(end) = find_crlf(body, trailer) else {
                    return Ok(None);
                };
                if end == trailer {
                    return Ok(Some(end + 2));
                }
                trailer = end + 2;
            }
        }
        let data_end = data_start.saturating_add(size);
        if body.len() < data_end.saturating_add(2) {
            return Ok(None);
        }
        if &body[data_end..data_end + 2] != b"\r\n" {
            return Err("malformed chunk".into());
        }
        offset = data_end + 2;
    }
}

fn decode_chunked(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut offset = 0usize;
    let mut decoded = Vec::new();
    loop {
        let line_end = find_crlf(body, offset).ok_or_else(|| "truncated chunk size".to_string())?;
        let size_line = std::str::from_utf8(&body[offset..line_end]).map_err(|_| "chunk size not utf8")?;
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|_| "invalid chunk size".to_string())?;
        let data_start = line_end + 2;
        if size == 0 {
            return Ok(decoded);
        }
        let data_end = data_start.saturating_add(size);
        if body.len() < data_end {
            return Err("truncated chunk".into());
        }
        decoded.extend_from_slice(&body[data_start..data_end]);
        offset = data_end + 2;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_stops_before_extra_bytes() {
        let complete = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nABCD";
        let mut response = complete.to_vec();
        response.extend_from_slice(b"TRAILING");
        assert_eq!(complete_response_len(&response, false).unwrap(), Some(complete.len()));
        let (_, body) = status_and_decoded_body(complete).unwrap();
        assert_eq!(body, b"ABCD");
    }

    #[test]
    fn chunked_response_is_complete_after_last_chunk() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let len = complete_response_len(response, false).unwrap().unwrap();
        assert_eq!(len, response.len());
        let (status, body) = status_and_decoded_body(response).unwrap();
        assert_eq!(status, 200);
        assert_eq!(body, b"hello");
    }

    #[test]
    fn incomplete_content_length_waits() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nABCD";
        assert_eq!(complete_response_len(response, false).unwrap(), None);
    }

    #[test]
    fn no_length_completes_on_close() {
        let response = b"HTTP/1.1 200 OK\r\n\r\nxyz";
        assert_eq!(complete_response_len(response, false).unwrap(), None);
        assert_eq!(complete_response_len(response, true).unwrap(), Some(response.len()));
    }
}
