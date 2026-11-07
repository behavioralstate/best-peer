//! The images a prompt shows its model (behavioralstate/spec#266). A prompt names each by its address and the SHA-256
//! of its bytes, never the bytes: the peer fetches it under the rule a job's inputs follow (https, or plain http on
//! this host's loopback where its operator allows it, no redirect followed), checks the digest, and hands the engine
//! the bytes with what they are. An image whose bytes are not the ones named is never shown.

use std::io::Read;
use std::time::Duration;

use best_peer_door::BestError;
use best_peer_engine::Image;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// The most images one prompt may show.
pub const MOST: usize = 4;

/// The most bytes one image may have: 8 MiB.
pub const MOST_BYTES: u64 = 8 << 20;

/// How long the image's address may take to start answering, and to send it all.
const ASKING: Duration = Duration::from_secs(30);
const WITHIN: Duration = Duration::from_secs(60);

/// An image as a prompt names it: where it is and the digest of its bytes, lowercase hex.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct At {
    pub url: String,
    pub sha256: String,
}

/// The images a prompt's data names, in the order the model is shown them.
pub fn named(data: &Value) -> Vec<At> {
    data["messages"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|m| m["images"].as_array().into_iter().flatten())
        .filter_map(|i| serde_json::from_value(i.clone()).ok())
        .collect()
}

/// Refuses at ingest, naming the field, a prompt that shows more than [`MOST`] images or names one at an address a
/// peer may not fetch from, as [`crate::store::allowed`] says with `cleartext_loopback`.
pub fn admit(data: &Value, cleartext_loopback: bool) -> Result<(), BestError> {
    let bad = |code: &'static str, field: String, message: String| {
        Err(BestError::bad_request(code, message).with_details(json!({ "field": field })))
    };
    if named(data).len() > MOST {
        return bad(
            "TOO_MANY_IMAGES",
            "messages".into(),
            format!("a prompt shows the model at most {MOST} images: send fewer"),
        );
    }
    for (n, m) in data["messages"].as_array().into_iter().flatten().enumerate() {
        for (k, i) in m["images"].as_array().into_iter().flatten().enumerate() {
            if !crate::store::allowed(i["url"].as_str().unwrap_or_default(), cleartext_loopback) {
                return bad(
                    "INVALID_IMAGE_URL",
                    format!("messages/{n}/images/{k}/url"),
                    "an image is fetched over https, or over plain http on the peer's own loopback where its operator allows it: send its address there".into(),
                );
            }
        }
    }
    Ok(())
}

/// A prompt's outcome with the images it showed named, as the prompt named them; one of text alone is unchanged.
pub fn on(mut outcome: Value, named: &[At]) -> Value {
    if !named.is_empty() {
        outcome["images"] = json!(named);
    }
    outcome
}

/// Fetches the image at `at`: its bytes and what they are, when they are the bytes its digest names and an image
/// the engines read; otherwise why not, in words.
pub fn fetch(at: &At) -> Result<Image, String> {
    let agent = crate::store::agent(|c| c.timeout_recv_response(Some(ASKING)).timeout_global(Some(WITHIN)));
    let mut response = agent.get(&at.url).call().map_err(|e| match e {
        ureq::Error::StatusCode(code) => format!("the image's address answered {code}"),
        e => format!("the image's address did not answer: {e}"),
    })?;
    let mut bytes = Vec::new();
    response
        .body_mut()
        .as_reader()
        .take(MOST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("the image could not be read: {e}"))?;
    shown(at, bytes)
}

/// The image `bytes` are, when they are what `at` names.
fn shown(at: &At, bytes: Vec<u8>) -> Result<Image, String> {
    if bytes.len() as u64 > MOST_BYTES {
        return Err(format!("the image is larger than {MOST_BYTES} bytes"));
    }
    // What the address served is not told back: a digest that does not match says only that.
    let digest: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    if digest != at.sha256 {
        return Err("its bytes are not the ones the prompt names: their SHA-256 differs".into());
    }
    let media_type = match bytes.as_slice() {
        [0xff, 0xd8, 0xff, ..] => "image/jpeg",
        [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, ..] => "image/png",
        _ => return Err("the image is neither JPEG nor PNG".into()),
    };
    Ok(Image {
        media_type: media_type.into(),
        bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(bytes: &[u8]) -> At {
        At {
            url: "http://127.0.0.1/frame".into(),
            sha256: Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect(),
        }
    }

    #[test]
    fn an_image_is_shown_only_when_its_bytes_are_the_named_ones_and_a_jpeg_or_a_png() {
        let jpeg = [0xff, 0xd8, 0xff, 0xe0, 1, 2];
        assert_eq!(shown(&at(&jpeg), jpeg.to_vec()).unwrap().media_type, "image/jpeg");
        let png = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0];
        assert_eq!(shown(&at(&png), png.to_vec()).unwrap().media_type, "image/png");
        let other = jpeg.map(|b| b ^ 1);
        let err = shown(&at(&jpeg), other.to_vec()).unwrap_err();
        assert!(err.contains("not the ones the prompt names"), "{err}");
        assert!(!err.contains(&at(&other).sha256), "what was served is not told: {err}");
        let text = b"not an image";
        assert_eq!(
            shown(&at(text), text.to_vec()).unwrap_err(),
            "the image is neither JPEG nor PNG"
        );
        let big = vec![0xff; MOST_BYTES as usize + 1];
        assert!(shown(&at(&big), big).unwrap_err().contains("larger than"));
    }
}
