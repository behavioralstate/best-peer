//! The images a prompt shows its model (behavioralstate/spec#266). A prompt names each by its address and the SHA-256
//! of its bytes, never the bytes: the peer fetches it under the rule a job's inputs follow (https, or plain http on
//! this host's loopback where its operator allows it, no redirect followed), checks the digest, and hands the engine
//! the bytes with what they are. An image whose bytes are not the ones named is never shown.

use std::io::Read;
use std::time::Duration;

use best_peer_engine::Image;
use serde::{Deserialize, Serialize};
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
    let digest: String = Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect();
    if digest != at.sha256 {
        return Err(format!(
            "the image's bytes have the digest {digest}, not the one the prompt names"
        ));
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
        assert!(err.contains("not the one the prompt names"), "{err}");
        let text = b"not an image";
        assert_eq!(
            shown(&at(text), text.to_vec()).unwrap_err(),
            "the image is neither JPEG nor PNG"
        );
        let big = vec![0xff; MOST_BYTES as usize + 1];
        assert!(shown(&at(&big), big).unwrap_err().contains("larger than"));
    }
}
