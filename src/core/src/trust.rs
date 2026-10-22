//! Trust features: RFC 3161 timestamps of the audit chain and digital signatures on PDF reports.
//!
//! Timestamp: the head of the audit chain (the last entry_hash, itself a SHA-256) is sent to a
//! time-stamping authority. The token proves the log — and every evidence hash, finding and report
//! digest recorded before it — existed at that time. Stored next to the log:
//!   timestamp-<seq>.tsr   DER response (verify: openssl ts -verify -digest <head> -in … -CAfile …)
//!   timestamp-<seq>.json  tsa, gen_time, covers_seq, head, token_sha256
//! Offline: the run completes, `timestamp_pending` is logged, `<tool> timestamp <log-dir>` adds it later.
//!
//! PDF signature: CMS detached signature (adbe.pkcs7.detached) with the examiner's .p12/.pfx (RSA keys).
//! The password is never logged.

use crate::hash::{HashAlgo, hash_bytes};
use cms::builder::{SignedDataBuilder, SignerInfoBuilder, create_signing_time_attribute};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignedData, SignerIdentifier};
use der::asn1::{Int, OctetString};
use der::{Any, Decode, Encode};
use rsa::pkcs1v15::{Signature, SigningKey};
use rsa::pkcs8::DecodePrivateKey;
use serde_json::{Value, json};
use sha2_legacy::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use std::collections::BTreeMap;
use std::path::Path;
use x509_cert::Certificate;
use x509_tsp::{MessageImprint, TimeStampReq, TimeStampResp, TspVersion};

pub const DEFAULT_TSA: &str = "http://timestamp.digicert.com";

#[derive(Clone, Debug, PartialEq)]
pub struct Timestamp {
    pub tsa: String,
    pub gen_time: String,
    pub covers_seq: u64,
    pub head: String,
    pub token_sha256: String,
    pub file: String,
}

impl Timestamp {
    pub fn to_json(&self) -> Value {
        json!({"tsa": self.tsa, "gen_time": self.gen_time, "covers_seq": self.covers_seq, "head": self.head,
               "token_sha256": self.token_sha256, "file": self.file})
    }
}

fn sha256_alg() -> spki::AlgorithmIdentifier<Any> {
    spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::ID_SHA_256,
        parameters: Some(Any::null()),
    }
}

fn nonce() -> Vec<u8> {
    let seed = format!("{:?}-{}", std::time::SystemTime::now(), std::process::id());
    let mut n = crate::hash::hex_decode(&hash_bytes(seed.as_bytes(), HashAlgo::Sha256)[..16])
        .unwrap_or_default();
    n[0] &= 0x7f; // positive INTEGER
    n
}

pub fn build_request(digest: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let req = TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: sha256_alg(),
            hashed_message: OctetString::new(digest).map_err(|e| e.to_string())?,
        },
        req_policy: None,
        nonce: Some(Int::new(nonce).map_err(|e| e.to_string())?),
        cert_req: true,
        extensions: None,
    };
    req.to_der().map_err(|e| e.to_string())
}

/// Checks a TSA response; returns gen_time (UTC, ISO 8601).
pub fn parse_response(der: &[u8], digest: &[u8], nonce: Option<&[u8]>) -> Result<String, String> {
    let resp =
        TimeStampResp::from_der(der).map_err(|e| format!("not a time-stamp response: {}", e))?;
    let status = format!("{:?}", resp.status.status);
    if !(status == "Accepted" || status == "GrantedWithMods") {
        return Err(format!("TSA refused the request: {}", status));
    }
    let token = resp.time_stamp_token.ok_or("TSA response has no token")?;
    let sd: SignedData = token
        .content
        .decode_as()
        .map_err(|e| format!("bad token: {}", e))?;
    let econtent = sd
        .encap_content_info
        .econtent
        .ok_or("token without TSTInfo")?;
    let octets: OctetString = econtent
        .decode_as()
        .map_err(|e| format!("bad TSTInfo: {}", e))?;
    let info = parse_tst_info(octets.as_bytes())?;
    if info.imprint != digest {
        return Err("the token does not cover the requested digest".into());
    }
    if let (Some(want), Some(got)) = (nonce, info.nonce.as_ref()) {
        let want = Int::new(want).map_err(|e| e.to_string())?;
        if got.as_slice() != want.as_bytes() {
            return Err("nonce mismatch (possible replay)".into());
        }
    }
    Ok(info.gen_time)
}

struct TstFields {
    imprint: Vec<u8>,
    gen_time: String,
    nonce: Option<Vec<u8>>,
}

/// Minimal DER walk over TSTInfo. Done by hand on purpose: many TSAs put fractional seconds in
/// genTime ("20261020182422.123Z"), which strict GeneralizedTime decoders reject.
fn parse_tst_info(der: &[u8]) -> Result<TstFields, String> {
    fn tlv(b: &[u8], pos: usize) -> Result<(u8, usize, usize), String> {
        let bad = || "bad TSTInfo encoding".to_string();
        let tag = *b.get(pos).ok_or_else(bad)?;
        let first = *b.get(pos + 1).ok_or_else(bad)? as usize;
        let (len, hdr) = if first < 0x80 {
            (first, 2)
        } else {
            let n = first & 0x7f;
            if n == 0 || n > 4 {
                return Err(bad());
            }
            let mut l = 0usize;
            for i in 0..n {
                l = (l << 8) | *b.get(pos + 2 + i).ok_or_else(bad)? as usize;
            }
            (l, 2 + n)
        };
        let start = pos + hdr;
        if start + len > b.len() {
            return Err(bad());
        }
        Ok((tag, start, start + len))
    }
    let (tag, start, end) = tlv(der, 0)?;
    if tag != 0x30 {
        return Err("TSTInfo is not a SEQUENCE".into());
    }
    let mut fields = Vec::new();
    let mut pos = start;
    while pos < end {
        let (t, s, e) = tlv(der, pos)?;
        fields.push((t, s, e));
        pos = e;
    }
    let (t, s, e) = *fields.get(2).ok_or("TSTInfo too short")?;
    if t != 0x30 {
        return Err("bad messageImprint".into());
    }
    let (_, _, alg_end) = tlv(der, s)?;
    let (ot, os, oe) = tlv(der, alg_end)?;
    if ot != 0x04 || oe > e {
        return Err("bad messageImprint".into());
    }
    let imprint = der[os..oe].to_vec();
    let (gt, gs, ge) = *fields.get(4).ok_or("TSTInfo without genTime")?;
    if gt != 0x18 {
        return Err("bad genTime".into());
    }
    let raw = std::str::from_utf8(&der[gs..ge]).map_err(|_| "bad genTime")?;
    if raw.len() < 14 || !raw[..14].chars().all(|c| c.is_ascii_digit()) {
        return Err("bad genTime".into());
    }
    let gen_time = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &raw[0..4],
        &raw[4..6],
        &raw[6..8],
        &raw[8..10],
        &raw[10..12],
        &raw[12..14]
    );
    let nonce = fields
        .iter()
        .skip(5)
        .find(|(t, _, _)| *t == 0x02)
        .map(|(_, s, e)| der[*s..*e].to_vec());
    Ok(TstFields {
        imprint,
        gen_time,
        nonce,
    })
}

pub fn request_timestamp(digest: &[u8], url: &str) -> Result<(String, Vec<u8>), String> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(format!("unsupported TSA URL scheme: {}", url));
    }
    let n = nonce();
    let body = build_request(digest, &n)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(15)))
        .build()
        .into();
    let mut resp = agent
        .post(url)
        .header("Content-Type", "application/timestamp-query")
        .send(&body[..])
        .map_err(|e| format!("cannot reach {}: {}", url, e))?;
    let der = resp
        .body_mut()
        .with_config()
        .limit(1 << 20)
        .read_to_vec()
        .map_err(|e| format!("cannot read TSA response: {}", e))?;
    let gen_time = parse_response(&der, digest, Some(&n))?;
    Ok((gen_time, der))
}

pub fn timestamp_head(
    log_dir: &Path,
    seq: u64,
    head: &str,
    url: &str,
) -> Result<Timestamp, String> {
    let digest = crate::hash::hex_decode(head).ok_or("bad chain head")?;
    let (gen_time, der) = request_timestamp(&digest, url)?;
    let file = format!("timestamp-{:05}.tsr", seq);
    std::fs::write(log_dir.join(&file), &der).map_err(|e| e.to_string())?;
    let ts = Timestamp {
        tsa: url.into(),
        gen_time,
        covers_seq: seq,
        head: head.into(),
        token_sha256: hash_bytes(&der, HashAlgo::Sha256),
        file,
    };
    let mut text = serde_json::to_string_pretty(&ts.to_json()).expect("json");
    text.push('\n');
    std::fs::write(log_dir.join(format!("timestamp-{:05}.json", seq)), text)
        .map_err(|e| e.to_string())?;
    Ok(ts)
}

/// Checks every timestamp-*.json/.tsr pair against the chain heads (seq -> entry_hash).
pub fn verify_timestamps(log_dir: &Path, heads: &BTreeMap<u64, String>) -> Vec<String> {
    let mut problems = Vec::new();
    let mut metas: Vec<_> = std::fs::read_dir(log_dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n| n.starts_with("timestamp-") && n.ends_with(".json"))
                })
                .collect()
        })
        .unwrap_or_default();
    metas.sort();
    for m in metas {
        let meta: Value = match std::fs::read_to_string(&m)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
        {
            Some(v) => v,
            None => {
                problems.push(format!("{}: unreadable", m.display()));
                continue;
            }
        };
        let seq = meta["covers_seq"].as_u64().unwrap_or(0);
        let file = meta["file"].as_str().unwrap_or_default();
        let Some(head) = heads.get(&seq).and_then(|h| crate::hash::hex_decode(h)) else {
            problems.push(format!(
                "truncated: {} covers entry #{}, which is not in the log (entries removed from the end)",
                file, seq
            ));
            continue;
        };
        let der = std::fs::read(log_dir.join(file)).unwrap_or_default();
        if hash_bytes(&der, HashAlgo::Sha256) != meta["token_sha256"].as_str().unwrap_or_default() {
            problems.push(format!("{}: token file missing or altered", file));
            continue;
        }
        if let Err(e) = parse_response(&der, &head, None) {
            problems.push(format!("{}: {} (entry #{})", file, e, seq));
        }
    }
    problems
}

// ---------------------------------------------------------------- PDF signatures

pub struct PdfSigner {
    key: SigningKey<Sha256>,
    certs: Vec<Certificate>,
    pub subject: String,
    pub fingerprint_sha256: String,
}

impl PdfSigner {
    pub fn load(path: &Path, password: &str) -> Result<PdfSigner, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("cannot read signing certificate {}: {}", path.display(), e))?;
        let ks = p12_keystore::KeyStore::from_pkcs12(
            &data,
            password,
            p12_keystore::Pkcs12ImportPolicy::Relaxed,
        )
        .map_err(|e| {
            format!(
                "cannot load signing certificate {}: wrong password or unsupported file ({})",
                path.display(),
                e
            )
        })?;
        let (_, chain) = ks
            .private_key_chain()
            .ok_or("the certificate file contains no private key")?;
        let key = rsa::RsaPrivateKey::from_pkcs8_der(chain.key().as_der())
            .map_err(|_| "only RSA signing certificates are supported".to_string())?;
        let certs = chain
            .certs()
            .iter()
            .map(|c| Certificate::from_der(c.as_der()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        let first = chain.certs().first().ok_or("no certificate in the file")?;
        Ok(PdfSigner {
            key: SigningKey::<Sha256>::new(key),
            certs,
            subject: first.subject().to_string(),
            fingerprint_sha256: hash_bytes(first.as_der(), HashAlgo::Sha256),
        })
    }

    /// CMS SignedData (detached) over `content`, DER-encoded.
    pub fn sign_detached(&self, content: &[u8]) -> Result<Vec<u8>, String> {
        let digest = Sha256::digest(content);
        let cert = &self.certs[0];
        let eci = EncapsulatedContentInfo {
            econtent_type: const_oid::db::rfc5911::ID_DATA,
            econtent: None,
        };
        let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: cert.tbs_certificate.issuer.clone(),
            serial_number: cert.tbs_certificate.serial_number.clone(),
        });
        let dalg = AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::ID_SHA_256,
            parameters: None,
        };
        fn err<E: std::fmt::Debug>(e: E) -> String {
            format!("{:?}", e)
        }
        let mut sib = SignerInfoBuilder::new(&self.key, sid, dalg.clone(), &eci, Some(&digest))
            .map_err(err)?;
        sib.add_signed_attribute(create_signing_time_attribute().map_err(err)?)
            .map_err(err)?;
        let mut b = SignedDataBuilder::new(&eci);
        b.add_digest_algorithm(dalg).map_err(err)?;
        for c in &self.certs {
            b.add_certificate(CertificateChoices::Certificate(c.clone()))
                .map_err(err)?;
        }
        b.add_signer_info::<_, Signature>(sib).map_err(err)?;
        b.build().map_err(err)?.to_der().map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_valid_der_and_bad_responses_are_rejected() {
        let req = build_request(&[7u8; 32], &[1, 2, 3]).unwrap();
        assert_eq!(req[0], 0x30);
        assert!(TimeStampReq::from_der(&req).is_ok());
        assert!(parse_response(b"garbage", &[0u8; 32], None).is_err());
        assert!(request_timestamp(&[0u8; 32], "file:///etc/passwd").is_err());
        assert!(request_timestamp(&[0u8; 32], "http://127.0.0.1:9/tsr").is_err());
    }
}
