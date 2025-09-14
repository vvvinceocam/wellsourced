use reqwest::{Response, header::ToStrError};

/// Collects all headers with the given name from the response. Returns a vector of lowercase strings.
///
/// ## Errors
///
/// Returns an error if any header value is not a valid utf-8 string.
pub fn collect_headers(response: &Response, header_name: &str) -> Result<Vec<String>, ToStrError> {
    response
        .headers()
        .get_all(header_name)
        .iter()
        .map(|header| header.to_str().map(|str| str.to_lowercase()))
        .collect::<Result<Vec<_>, _>>()
}
