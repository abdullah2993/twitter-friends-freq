use std::{
    cell::RefMut,
    fmt::Display,
    io,
    ops::Add,
    rc::Rc,
    sync::Arc,
    thread::{self},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crypto::{hmac::Hmac, mac::Mac, sha1::Sha1};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ureq::Request;

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

struct RateLimit {
    total: u64,
    remaining: u64,
    reset_at: SystemTime,
}

impl TryFrom<ureq::Response> for RateLimit {
    type Error = &'static str;

    fn try_from(response: ureq::Response) -> Result<Self, Self::Error> {
        let total = response
            .header("x-rate-limit-limit")
            .ok_or("Missing total rate limit header")?
            .parse()
            .map_err(|_| "Failed to parse total rate limit header")?;

        let remaining = response
            .header("x-rate-limit-remaining")
            .ok_or("Missing remaining rate limit header")?
            .parse()
            .map_err(|_| "Failed to parse remaining rate limit header")?;

        let reset_epoch = response
            .header("x-rate-limit-reset")
            .ok_or("Missing reset rate limit header")?
            .parse::<u64>()
            .map_err(|_| "Failed to parse reset rate limit header")?;

        let reset_at = UNIX_EPOCH + std::time::Duration::from_secs(reset_epoch);

        Ok(Self {
            total,
            remaining,
            reset_at,
        })
    }
}

impl RateLimit {
    fn is_rate_limit_error(err: &ureq::Error) -> bool {
        match *err {
            ureq::Error::Status(code, _) => code == 429,
            _ => false,
        }
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
enum ScreenNameOrUserId {
    ScreenName(String),
    UserId(String),
}

impl Display for ScreenNameOrUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScreenName(_) => write!(f, "screen_name"),
            Self::UserId(_) => write!(f, "user_id"),
        }
    }
}

impl Into<(String, String)> for ScreenNameOrUserId {
    fn into(self) -> (String, String) {
        return (self.to_string(), self.value());
    }
}

pub struct ResponseIter {
    client: Client,
    cursor: String,
    by: ScreenNameOrUserId,
    rel: RelationType,
    wait_rate_limit: bool,
}

impl<'a> Iterator for ResponseIter {
    type Item = Response;

    fn next(&mut self) -> Option<Self::Item> {
        let res = self.client.get_follower_or_friends(
            self.rel.clone(),
            self.by.clone(),
            Some(self.cursor.clone()),
        );

        return match res {
            Ok(res) => {
                self.cursor = res.next_cursor_str.clone();
                return Some(res);
            }
            Err(TwitterApiError::RequestError(err))
                if self.wait_rate_limit && RateLimit::is_rate_limit_error(&err) =>
            {
                let res = err.into_response().unwrap();
                let rate_limit = RateLimit::try_from(res).unwrap();

                thread::sleep(
                    rate_limit
                        .reset_at
                        .duration_since(SystemTime::now())
                        .unwrap()
                        .add(Duration::from_secs(60)),
                );
                return self.next();
            }
            _ => None,
        };
    }
}

impl ScreenNameOrUserId {
    fn value(&self) -> String {
        match self {
            Self::ScreenName(screen_name) => screen_name.clone(),
            Self::UserId(user_id) => user_id.clone(),
        }
    }
}

#[test]
fn test_screen_name_or_user_id() {
    let v = ScreenNameOrUserId::ScreenName("tuna".to_string());
    assert_eq!(v.to_string(), "screen_name");
    assert_eq!(v.value(), "tuna");
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

    pub fn get_follower_ids_by_id(self, id: &str) -> Result<Response, TwitterApiError> {
        return self.get_follower_or_friends(
            RelationType::Followers,
            ScreenNameOrUserId::UserId(id.to_string()),
            None,
        );
    }

    pub fn get_follower_ids_by_screen_name(
        self,
        screen_name: &str,
    ) -> Result<Response, TwitterApiError> {
        return self.get_follower_or_friends(
            RelationType::Followers,
            ScreenNameOrUserId::ScreenName(screen_name.to_string()),
            None,
        );
    }

    pub fn get_friends_ids_by_id(self, id: &str) -> Result<Response, TwitterApiError> {
        return self.get_follower_or_friends(
            RelationType::Friends,
            ScreenNameOrUserId::UserId(id.to_string()),
            None,
        );
    }

    pub fn get_friends_ids_by_screen_name(
        self,
        screen_name: &str,
    ) -> Result<Response, TwitterApiError> {
        return self.get_follower_or_friends(
            RelationType::Friends,
            ScreenNameOrUserId::ScreenName(screen_name.to_string()),
            None,
        );
    }

    pub fn get_friends_ids_by_screen_name_iter(
        self,
        screen_name: &str,
        waitRateLimit: bool,
    ) -> ResponseIter {
        let r = ResponseIter {
            client: self,
            cursor: "-1".to_string(),
            by: ScreenNameOrUserId::ScreenName(screen_name.to_string()),
            rel: RelationType::Friends,
            wait_rate_limit: waitRateLimit,
        };
        return r;
    }

    fn get_follower_or_friends(
        mut self,
        rel: RelationType,
        by: ScreenNameOrUserId,
        cursor: Option<String>,
    ) -> Result<Response, TwitterApiError> {
        let cursor_val = cursor.unwrap_or_else(|| "-1".to_string());
        let url = format!("{}/{}/ids.json", BASE_URL, rel);
        let res = self
            .agent
            .get(url.as_str())
            .set(
                "Authorization",
                self.generate_oauth_header("GET", url, vec![by.clone().into()])
                    .as_str(),
            )
            .query(by.to_string().as_str(), by.value().as_str())
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
pub struct Response {
    #[serde(rename = "ids")]
    pub ids: Vec<u64>,

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
