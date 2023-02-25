use std::{
    fmt::Display,
    io,
    time::{SystemTime, UNIX_EPOCH},
};

use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::utils::{encode, encode_b64};

const BASE_URL: &str = "https://api.twitter.com/1.1";
const SIGNATURE_METHOD: &str = "HMAC-SHA1";

pub type URLValues = Vec<(String, String)>;

fn stringify(values: URLValues) -> String {
    values
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join("&")
}

// #[derive(Clone)]
pub struct Client {
    access_token: String,
    access_token_secret: String,
    consumer_key: String,
    consumer_secret: String,
    nonce: u64,
    agent: ureq::Agent,
}

#[derive(Debug, Error)]
pub enum TwitterApiError {
    #[error("HTTP request error: {0}")]
    RequestError(#[from] ureq::Error),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("JSON parsing error: {0}")]
    IOError(#[from] io::Error),
}

enum RelationType {
    Followers,
    Friends,
}

impl Display for RelationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Friends => write!(f, "friends"),
            Self::Followers => write!(f, "followers"),
        }
    }
}

enum ScreenNameOrUserId {
    ScreenName,
    UserId,
}

impl Display for ScreenNameOrUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScreenName => write!(f, "screen_name"),
            Self::UserId => write!(f, "user_id"),
        }
    }
}

impl Client {
    pub fn new(
        access_token: String,
        access_token_secret: String,
        consumer_key: String,
        consumer_secret: String,
    ) -> Self {
        return Self {
            access_token,
            access_token_secret,
            consumer_key,
            consumer_secret,
            nonce: rand::random(),
            agent: ureq::agent(),
        };
    }

    pub fn get_follower_ids_by_id(self, id: &str) -> Result<Response<u64>, TwitterApiError> {
        return self.get_follower_or_friends(
            RelationType::Followers,
            ScreenNameOrUserId::UserId,
            id,
        );
    }

    pub fn get_follower_ids_by_screen_name(
        self,
        screen_name: &str,
    ) -> Result<Response<u64>, TwitterApiError> {
        return self.get_follower_or_friends(
            RelationType::Followers,
            ScreenNameOrUserId::ScreenName,
            screen_name,
        );
    }

    pub fn get_friends_ids_by_id(self, id: &str) -> Result<Response<u64>, TwitterApiError> {
        return self.get_follower_or_friends(RelationType::Friends, ScreenNameOrUserId::UserId, id);
    }

    pub fn get_friends_ids_by_screen_name(
        self,
        screen_name: &str,
    ) -> Result<Response<u64>, TwitterApiError> {
        return self.get_follower_or_friends(
            RelationType::Friends,
            ScreenNameOrUserId::ScreenName,
            screen_name,
        );
    }

    fn get_follower_or_friends(
        mut self,
        rel: RelationType,
        by: ScreenNameOrUserId,
        val: &str,
    ) -> Result<Response<u64>, TwitterApiError> {
        let url = format!("{}/{}/ids.json", BASE_URL, rel);
        let res = self
            .agent
            .get(url.as_str())
            .set(
                "Authorization",
                self.generate_oauth_header("GET", url, vec![(by.to_string(), val.to_string())])
                    .as_str(),
            )
            .query(by.to_string().as_str(), val)
            .call()?;

        return Ok(res.into_json()?);
    }

    fn generate_oauth_header(&mut self, method: &str, url: String, params: URLValues) -> String {
        let ts = Client::timestamp();
        let mut values: URLValues = vec![
            ("oauth_consumer_key".to_string(), self.consumer_key.clone()),
            ("oauth_nonce".to_string(), self.nonce()),
            (
                "oauth_signature_method".to_string(),
                SIGNATURE_METHOD.to_string(),
            ),
            ("oauth_timestamp".to_string(), ts.clone()),
            ("oauth_token".to_string(), self.access_token.clone()),
            ("oauth_version".to_string(), "1.0".to_string()),
        ];

        values.extend(params);

        values.iter_mut().for_each(|v| {
            *v = (encode(v.0.as_str()), encode(v.1.as_str()));
        });

        values.sort();
        let signature_str = format!(
            "{}&{}&{}",
            method,
            encode(url.as_str()),
            encode(stringify(values).as_str())
        );

        //TODO may be calculate in new and have signer as a struct variable?
        let signing_key = format!(
            "{}&{}",
            encode(self.consumer_secret.as_str()),
            encode(self.access_token_secret.as_str())
        );

        let mut signer = Hmac::new(Sha1::new(), signing_key.as_bytes());
        signer.input(signature_str.as_bytes());
        let res = signer.result();
        let sign = res.code();

        let signature = encode_b64(sign);
        return format!(
            r#"OAuth oauth_consumer_key="{}", oauth_nonce="{}", oauth_signature="{}", oauth_signature_method="{}", oauth_timestamp="{}", oauth_token="{}", oauth_version="1.0""#,
            self.consumer_key,
            self.nonce,
            encode(signature.as_str()),
            SIGNATURE_METHOD,
            ts,
            self.access_token
        );
    }

    fn nonce(&mut self) -> String {
        self.nonce += 1;
        self.nonce.to_string()
    }

    fn timestamp() -> String {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }
}

#[derive(Serialize, Deserialize)]
pub struct Response<T> {
    #[serde(rename = "ids")]
    pub ids: Vec<T>,

    #[serde(rename = "next_cursor")]
    next_cursor: i64,

    #[serde(rename = "next_cursor_str")]
    next_cursor_str: String,

    #[serde(rename = "previous_cursor")]
    previous_cursor: i64,

    #[serde(rename = "previous_cursor_str")]
    previous_cursor_str: String,
}

#[test]
fn test_stringify() {
    let mut values: Vec<(String, String)> =
        vec![("hello", "world"), ("status", "dying"), ("A", "B")]
            .iter()
            .map(|c| (c.0.to_string(), c.1.to_string()))
            .collect();
    values.sort();
    assert_eq!(stringify(values), "A=B&hello=world&status=dying")
}

#[test]
fn test_hmac_sha1() {
    //https://developer.twitter.com/en/docs/authentication/oauth-1-0a/creating-a-signature#Calculating%20the%20signature
    let sk =
        "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw&LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";
    let sm ="POST&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fstatuses%2Fupdate.json&include_entities%3Dtrue%26oauth_consumer_key%3Dxvz1evFS4wEEPTGEFPHBog%26oauth_nonce%3DkYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1318622958%26oauth_token%3D370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb%26oauth_version%3D1.0%26status%3DHello%2520Ladies%2520%252B%2520Gentlemen%252C%2520a%2520signed%2520OAuth%2520request%2521";
    let mut signer = Hmac::new(Sha1::new(), sk.as_bytes());
    signer.input(sm.as_bytes());
    let res = signer.result();
    let sign = res.code();
    assert_eq!(encode_b64(sign), "hCtSmYh+iHYCEqBWrE7C7hYmtUk=")
}
