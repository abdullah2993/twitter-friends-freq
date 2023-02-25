const BASE64_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
pub fn encode_b64(data: &[u8]) -> String {
    let mut bytes = data.to_vec();
    let padding = (3 - (bytes.len() % 3)) % 3;
    for _ in 0..padding {
        bytes.push(0);
    }
    let mut res = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk[1];
        let b2 = chunk[2];

        res.push(BASE64_ALPHABET[(b0 >> 2 as u8) as usize] as char);
        res.push(BASE64_ALPHABET[(((b0 & 3 as u8) << 4 as u8) | (b1 >> 4 as u8)) as usize] as char);
        res.push(
            BASE64_ALPHABET[(((b1 & 15 as u8) << 2 as u8) | (b2 >> 6 as u8)) as usize] as char,
        );
        res.push(BASE64_ALPHABET[(b2 & 63) as usize] as char);
    }

    for _ in 0..padding {
        res.pop();
    }

    for _ in 0..padding {
        res.push('=');
    }
    return res;
}

const HEX: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

pub fn encode(s: &str) -> String {
    let mut res = String::new();
    for c in s.bytes() {
        match c as char {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '.' | '_' | '~' => res.push(c as char),
            _ => {
                res.push('%');
                res.push(HEX[((c as u8) >> 4) as usize]);
                res.push(HEX[((c as u8) & 15) as usize]);
            }
        }
    }
    res
}

#[test]
fn test_encode() {
    //https://web.archive.org/web/20200925061238/https://developer.twitter.com/en/docs/authentication/oauth-1-0a/percent-encoding-parameters
    let values: Vec<(&str, &str)> = vec![
        ("Ladies + Gentlemen", "Ladies%20%2B%20Gentlemen"),
        ("An encoded string!", "An%20encoded%20string%21"),
        ("Dogs, Cats & Mice", "Dogs%2C%20Cats%20%26%20Mice"),
        ("☃", "%E2%98%83"),
        (
            "Hello Ladies + Gentlemen, a signed OAuth request!",
            "Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21",
        ),
    ];
    for (input, expected) in values {
        assert_eq!(encode(input), expected);
    }
}

#[test]
fn test_encode_b64() {
    //https://en.wikipedia.org/wiki/Base64#Output_padding
    assert_eq!(encode_b64("light work.".as_bytes()), "bGlnaHQgd29yay4=");
    assert_eq!(encode_b64("light work".as_bytes()), "bGlnaHQgd29yaw==");
    assert_eq!(encode_b64("light wor".as_bytes()), "bGlnaHQgd29y");
    assert_eq!(encode_b64("light wo".as_bytes()), "bGlnaHQgd28=");
    assert_eq!(encode_b64("light w".as_bytes()), "bGlnaHQgdw==");
}
