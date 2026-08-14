//! HTTP/1.1 response framing so the gateway can stop reading when the body
//! is complete instead of waiting for the origin to close the TLS stream.

use std::io::Read;

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
    let decoded = decode_response(message)?;
    Ok((decoded.status, decoded.body))
}

/// Unchunk, gunzip/inflate if needed, and refuse Cloudflare HTML so the iOS
/// client never JSON-decodes an interstitial or compressed bytes.
pub fn process_upstream_response(message: &[u8], alpn: &str) -> Result<Vec<u8>, String> {
    let decoded = decode_response(message)?;
    process_upstream_parts(decoded.status, &decoded.headers, decoded.body, alpn)
}

pub fn process_upstream_parts(
    status: u16,
    headers: &[(String, String)],
    mut body: Vec<u8>,
    alpn: &str,
) -> Result<Vec<u8>, String> {
    let encoding = header_value(headers, "content-encoding")
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("identity"));
    if let Some(encoding) = encoding {
        body = decode_content_encoding(encoding, body)?;
    }
    if let Some(reason) = html_challenge_reason(headers, &body, status, alpn) {
        return Err(reason);
    }
    let reason = if (200..300).contains(&status) {
        "OK"
    } else {
        "Error"
    };
    Ok(encode_identity_response(&DecodedResponse {
        status,
        reason: reason.to_string(),
        headers: headers.to_vec(),
        body,
    }))
}

struct DecodedResponse {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

fn decode_response(message: &[u8]) -> Result<DecodedResponse, String> {
    let header_end = find_delim(message).ok_or_else(|| "HTTP response missing header delimiter".to_string())?;
    let headers_end = header_end + DELIM.len();
    let head = parse_head(&message[..header_end])?;
    let raw_body = if headers_end <= message.len() {
        &message[headers_end..]
    } else {
        &[]
    };
    let body = decode_body(&head, raw_body)?;
    Ok(DecodedResponse {
        status: head.status,
        reason: head.reason,
        headers: head.headers,
        body,
    })
}

fn decode_body(head: &Head, raw_body: &[u8]) -> Result<Vec<u8>, String> {
    if head.no_body {
        return Ok(Vec::new());
    }
    if head.chunked {
        decode_chunked(raw_body)
    } else if let Some(len) = head.content_length {
        if raw_body.len() < len {
            return Err("truncated HTTP body".into());
        }
        Ok(raw_body[..len].to_vec())
    } else {
        Ok(raw_body.to_vec())
    }
}

fn decode_content_encoding(encoding: &str, body: Vec<u8>) -> Result<Vec<u8>, String> {
    if body.is_empty() {
        return Ok(body);
    }
    let first = encoding
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match first.as_str() {
        "" | "identity" => Ok(body),
        "gzip" | "x-gzip" => gunzip(&body),
        "deflate" => inflate(&body),
        "br" | "brotli" => brotli_decode(&body),
        other => Err(format!("unsupported Content-Encoding: {other}")),
    }
}

fn gunzip(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = flate2::read::GzDecoder::new(body);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|error| format!("gzip decompress failed: {error}"))?;
    if out.len() > MAX_BODY_BYTES {
        return Err("gzip body too large".into());
    }
    Ok(out)
}

fn brotli_decode(body: &[u8]) -> Result<Vec<u8>, String> {
    let mut decoder = brotli_decompressor::Decompressor::new(body, 4096);
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        match decoder.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if out.len().saturating_add(n) > MAX_BODY_BYTES {
                    return Err("brotli body too large".into());
                }
                out.extend_from_slice(&buf[..n]);
            }
            Err(error) => return Err(format!("brotli decompress failed: {error}")),
        }
    }
    Ok(out)
}

fn inflate(body: &[u8]) -> Result<Vec<u8>, String> {
    let zlib = {
        let mut decoder = flate2::read::ZlibDecoder::new(body);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out).ok().map(|_| out)
    };
    if let Some(out) = zlib {
        if out.len() > MAX_BODY_BYTES {
            return Err("deflate body too large".into());
        }
        return Ok(out);
    }
    let mut decoder = flate2::read::DeflateDecoder::new(body);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|error| format!("deflate decompress failed: {error}"))?;
    if out.len() > MAX_BODY_BYTES {
        return Err("deflate body too large".into());
    }
    Ok(out)
}

fn html_challenge_reason(
    headers: &[(String, String)],
    body: &[u8],
    status: u16,
    alpn: &str,
) -> Option<String> {
    if !is_cloudflare_html(headers, body) {
        return None;
    }
    let title = html_title_or_snippet(body);
    Some(format!(
        "Cloudflare HTML {status} alpn={alpn} title={title}"
    ))
}

fn is_cloudflare_html(headers: &[(String, String)], body: &[u8]) -> bool {
    if header_value(headers, "cf-mitigated").is_some() {
        return true;
    }
    if header_value(headers, "content-type")
        .map(|value| value.to_ascii_lowercase().contains("html"))
        .unwrap_or(false)
    {
        return true;
    }
    let start = body
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(body.len());
    body.get(start) == Some(&b'<')
}

fn html_title_or_snippet(body: &[u8]) -> String {
    let text = String::from_utf8_lossy(body);
    let lower = text.to_ascii_lowercase();
    let raw = if let Some(start) = lower.find("<title>") {
        let rest = &text[start + 7..];
        let rest_lower = rest.to_ascii_lowercase();
        let end = rest_lower.find("</title>").unwrap_or(rest.len());
        rest[..end].to_string()
    } else {
        let start = body
            .iter()
            .position(|byte| !byte.is_ascii_whitespace())
            .unwrap_or(0);
        String::from_utf8_lossy(&body[start..]).into_owned()
    };
    one_line_prefix(&raw, 40)
}

fn one_line_prefix(value: &str, max_chars: usize) -> String {
    let flat: String = value
        .chars()
        .map(|ch| if ch == '\n' || ch == '\r' || ch == '\t' { ' ' } else { ch })
        .collect();
    let collapsed = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    collapsed.chars().take(max_chars).collect()
}

fn encode_identity_response(decoded: &DecodedResponse) -> Vec<u8> {
    let reason = if decoded.reason.is_empty() {
        "OK"
    } else {
        decoded.reason.as_str()
    };
    let mut out = format!("HTTP/1.1 {} {reason}\r\n", decoded.status).into_bytes();
    for (name, value) in &decoded.headers {
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
            || name.eq_ignore_ascii_case("content-encoding")
            || name.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(
        format!(
            "Content-Length: {}\r\nConnection: close\r\n\r\n",
            decoded.body.len()
        )
        .as_bytes(),
    );
    out.extend_from_slice(&decoded.body);
    out
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers.iter().find_map(|(key, value)| {
        if key.eq_ignore_ascii_case(name) {
            Some(value.as_str())
        } else {
            None
        }
    })
}

struct Head {
    status: u16,
    reason: String,
    chunked: bool,
    content_length: Option<usize>,
    no_body: bool,
    headers: Vec<(String, String)>,
}

fn parse_head(header_bytes: &[u8]) -> Result<Head, String> {
    let header_text = std::str::from_utf8(header_bytes).map_err(|_| "HTTP headers not utf8")?;
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next();
    let status = parts
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    let reason = parts.next().unwrap_or("").to_string();
    let mut chunked = false;
    let mut content_length = None;
    let mut headers = Vec::new();
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
        headers.push((name.to_string(), value.to_string()));
    }
    let no_body = status / 100 == 1 || status == 204 || status == 304;
    Ok(Head {
        status,
        reason,
        chunked,
        content_length,
        no_body,
        headers,
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

    #[test]
    fn html_body_is_not_forwarded() {
        let response = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: 19\r\n\r\n<!DOCTYPE html>nope";
        let error = process_upstream_response(response, "http/1.1").unwrap_err();
        assert_eq!(
            error,
            "Cloudflare HTML 403 alpn=http/1.1 title=<!DOCTYPE html>nope"
        );
        assert!(!error.contains('\n'));
    }

    #[test]
    fn html_error_includes_status_alpn_and_title() {
        let body = b"<html><title>Just a moment...</title><body>ok</body></html>";
        let mut response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        let error = process_upstream_response(&response, "h2").unwrap_err();
        assert_eq!(error, "Cloudflare HTML 403 alpn=h2 title=Just a moment...");
        assert!(!error.contains('\n'));
    }

    #[test]
    fn cf_mitigated_header_is_not_forwarded() {
        let response = b"HTTP/1.1 403 Forbidden\r\ncf-mitigated: challenge\r\nContent-Length: 2\r\n\r\n{}";
        let error = process_upstream_response(response, "h2").unwrap_err();
        assert_eq!(error, "Cloudflare HTML 403 alpn=h2 title={}");
    }

    #[test]
    fn gzip_json_is_decompressed_to_identity() {
        use std::io::Write;
        let json = br#"{"topic_list":[]}"#;
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(json).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {}\r\n\r\n",
            compressed.len()
        )
        .into_bytes();
        response.extend_from_slice(&compressed);
        let rewritten = process_upstream_response(&response, "http/1.1").unwrap();
        let text = String::from_utf8(rewritten).unwrap();
        assert!(text.contains("Content-Length: 17"));
        assert!(!text.to_ascii_lowercase().contains("content-encoding"));
        assert!(text.ends_with(r#"{"topic_list":[]}"#));
    }

    fn brotli_compress(plain: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut compressed = Vec::new();
        {
            let mut encoder = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
            encoder.write_all(plain).unwrap();
            encoder.flush().unwrap();
        }
        compressed
    }

    #[test]
    fn brotli_json_is_decompressed_to_identity() {
        let json = br#"{"topic_list":[]}"#;
        let compressed = brotli_compress(json);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Encoding: br\r\nContent-Length: {}\r\n\r\n",
            compressed.len()
        )
        .into_bytes();
        response.extend_from_slice(&compressed);
        let rewritten = process_upstream_response(&response, "h2").unwrap();
        let text = String::from_utf8(rewritten).unwrap();
        assert!(text.contains("Content-Length: 17"));
        assert!(!text.to_ascii_lowercase().contains("content-encoding"));
        assert!(text.ends_with(r#"{"topic_list":[]}"#));
    }

    #[test]
    fn brotli_html_challenge_is_detected_after_decode() {
        let html = b"<html><title>Just a moment...</title></html>";
        let compressed = brotli_compress(html);
        let mut response = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nContent-Encoding: brotli\r\nContent-Length: {}\r\n\r\n",
            compressed.len()
        )
        .into_bytes();
        response.extend_from_slice(&compressed);
        let error = process_upstream_response(&response, "h2").unwrap_err();
        assert_eq!(error, "Cloudflare HTML 403 alpn=h2 title=Just a moment...");
        assert!(!error.contains("unsupported Content-Encoding"));
    }
}
