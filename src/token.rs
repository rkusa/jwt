use base64;
use chrono::prelude::*;
use chrono::serde::ts_seconds;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    #[serde(with = "ts_seconds")]
    pub exp: DateTime<Utc>,
    pub sub: String,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Token {
    claims: Claims,
}

#[derive(Serialize, Deserialize)]
struct Header<'a> {
    alg: &'a str,
    typ: &'a str,
}

impl Token {
    pub fn new(claims: Claims) -> Token {
        Token { claims }
    }

    pub fn encode<S: AsRef<[u8]>>(&self, secret: S) -> Result<String, TokenError> {
        let header = serde_json::to_string(&Header {
            alg: "HS256",
            typ: "JWT",
        })?;
        let header = base64::encode_config(header.as_bytes(), base64::URL_SAFE_NO_PAD);

        let body = serde_json::to_string(&self.claims)?;
        let body = base64::encode_config(body.as_bytes(), base64::URL_SAFE_NO_PAD);

        let header_body = header + "." + &body;
        let signature = sign(&header_body, secret.as_ref())?;

        Ok(header_body + "." + &signature)
    }

    #[allow(unused)]
    pub fn decode<S: AsRef<[u8]>>(s: &str, secret: S) -> Result<Self, TokenError> {
        let mut parts = s.split('.');

        let header_part = parts.next().ok_or(TokenError::MissingHeader)?;
        let header = base64::decode_config(header_part, base64::URL_SAFE_NO_PAD)?;
        let header: Header = serde_json::from_slice(&header)?;

        if header.typ != "JWT" {
            return Err(TokenError::InvalidType);
        }

        if header.alg != "HS256" {
            return Err(TokenError::UnsupportedAlgorithm);
        }

        let claims_part = parts.next().ok_or(TokenError::MissingBody)?;
        let claims = base64::decode_config(claims_part, base64::URL_SAFE_NO_PAD)?;
        let claims: Claims = serde_json::from_slice(&claims)?;

        if claims.exp < Utc::now() {
            return Err(TokenError::Expired);
        }

        let signature_part = parts.next().ok_or(TokenError::MissingSignature)?;

        let header_body = header_part.to_string() + "." + &claims_part;
        let signature = sign(&header_body, secret.as_ref())?;

        let is_valid = signature_part
            .as_bytes()
            .ct_eq(signature.as_bytes())
            .unwrap_u8()
            == 1;
        if !is_valid {
            return Err(TokenError::InvalidSignature);
        }

        if parts.next().is_some() {
            return Err(TokenError::TooManyParts);
        }

        Ok(Token { claims })
    }
}

fn sign<S>(data: &str, secret: S) -> Result<String, TokenError>
where
    S: AsRef<[u8]>,
{
    let mut mac = Hmac::<Sha256>::new_varkey(secret.as_ref())?;
    mac.input(data.as_bytes());
    let digest = mac.result().code();
    Ok(base64::encode_config(
        digest.as_ref(),
        base64::URL_SAFE_NO_PAD,
    ))
}

#[derive(Debug, Error)]
pub enum TokenError {
    #[error("failed to deserialize JSON")]
    Json(#[from] serde_json::Error),
    #[error("failed to decode base64")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid key length")]
    InvalidKeyLength(hmac::crypto_mac::InvalidKeyLength),
    #[error("token header is missing")]
    MissingHeader,
    #[error("token body is missing")]
    MissingBody,
    #[error("token signature is missing")]
    MissingSignature,
    #[error("invalid typ")]
    InvalidType,
    #[error("unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("token expired")]
    Expired,
    #[error("too many parts")]
    TooManyParts,
    #[error("InvalidSignature")]
    InvalidSignature,
}

impl From<hmac::crypto_mac::InvalidKeyLength> for TokenError {
    fn from(err: hmac::crypto_mac::InvalidKeyLength) -> Self {
        TokenError::InvalidKeyLength(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn encode_token() {
        let token = Token::new(Claims {
            exp: Utc.ymd(2020, 1, 17).and_hms(9, 32, 0),
            sub: "foobar".to_string(),
        });
        assert_eq!(token.encode("secret").unwrap(), "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NzkyNTM1MjAsInN1YiI6ImZvb2JhciJ9.VRedh0qKIquLPcX2EJNkddJu7ACc29K5aofe8Io3_h8");
    }

    #[test]
    fn decode_token() {
        let original_token = Token::new(Claims {
            exp: (Utc::now() + Duration::seconds(60)).trunc_subsecs(0),
            sub: "foobar".to_string(),
        });
        let token = original_token.encode("secret").unwrap();
        let token = Token::decode(&token, "secret").unwrap();
        assert_eq!(original_token, token);
    }

    #[test]
    fn invalid_signature() {
        let original_token = Token::new(Claims {
            exp: (Utc::now() + Duration::seconds(60)).trunc_subsecs(0),
            sub: "foobar".to_string(),
        });
        let token = original_token.encode("secret").unwrap();
        match Token::decode(&token, "other") {
            Err(TokenError::InvalidSignature) => {}
            _ => panic!("expected invalid signature"),
        }
    }

    #[test]
    fn expired() {
        let original_token = Token::new(Claims {
            exp: (Utc::now() - Duration::seconds(60)).trunc_subsecs(0),
            sub: "foobar".to_string(),
        });
        let token = original_token.encode("secret").unwrap();
        match Token::decode(&token, "secret") {
            Err(TokenError::Expired) => {}
            _ => panic!("expected to be expired"),
        }
    }
}
