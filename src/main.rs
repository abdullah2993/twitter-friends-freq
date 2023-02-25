use std::{env, io, os};

use dotenv::dotenv;
use twitter_friends_freq::twitter;

fn main() {
    dotenv().ok();
    let client = twitter::client::Client::new(
        env::var("access_token").unwrap(),
        env::var("access_token_secret").unwrap(),
        env::var("consumer_key").unwrap(),
        env::var("consumer_secret").unwrap(),
    );

    let followers = client
        .get_follower_ids_by_screen_name("abdullah2993")
        .unwrap();
    print!("{:?}", followers.ids)
}
