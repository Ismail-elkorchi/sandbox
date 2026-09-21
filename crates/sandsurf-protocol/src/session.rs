use crate::{
    AUTHENTICATION_BYTES, Counter, Digest, Frame, FrameKind, Invalid, MAX_CREDIT, MAX_STREAMS,
    SandboxId, bytes_digest,
};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use zeroize::Zeroize;

const HANDSHAKE_VERSION: u16 = 1;
const NONCE_BYTES: usize = 32;
const LABEL_CHALLENGE: &[u8] = b"SANDSURF/GUEST-CHALLENGE/1";
const LABEL_FINISH: &[u8] = b"SANDSURF/HOST-FINISH/1";
const LABEL_SESSION: &[u8] = b"SANDSURF/GUEST-SESSION/1";
const LABEL_FRAME: &[u8] = b"SANDSURF/FRAME/1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone)]
pub struct BootCapability([u8; 32]);

impl BootCapability {
    pub fn generate() -> Result<Self, getrandom::Error> {
        let mut value = [0; 32];
        getrandom::getrandom(&mut value)?;
        Ok(Self(value))
    }

    pub fn from_bytes(value: [u8; 32]) -> Self {
        Self(value)
    }

    /// Copy the capability only at the trusted boot-disk/channel boundary.
    /// Callers must not serialize it into catalogs, logs, or application APIs.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for BootCapability {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("BootCapability([REDACTED])")
    }
}

impl Drop for BootCapability {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestHello {
    pub version: u16,
    pub sandbox_id: SandboxId,
    pub epoch: Counter,
    pub boot_identity: Digest,
    pub client_nonce: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestChallenge {
    pub server_nonce: Vec<u8>,
    pub proof: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestFinish {
    pub proof: Vec<u8>,
}

pub struct HostHandshake {
    capability: BootCapability,
    transcript: Vec<u8>,
}

pub struct GuestHandshake {
    capability: BootCapability,
    transcript: Vec<u8>,
}

impl HostHandshake {
    pub fn start(
        capability: BootCapability,
        sandbox_id: SandboxId,
        epoch: Counter,
        boot_identity: Digest,
    ) -> Result<(Self, GuestHello), Invalid> {
        let mut nonce = [0; NONCE_BYTES];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| Invalid("guest handshake entropy unavailable"))?;
        Self::start_with_nonce(capability, sandbox_id, epoch, boot_identity, nonce)
    }

    pub fn start_with_nonce(
        capability: BootCapability,
        sandbox_id: SandboxId,
        epoch: Counter,
        boot_identity: Digest,
        nonce: [u8; NONCE_BYTES],
    ) -> Result<(Self, GuestHello), Invalid> {
        if epoch == Counter::ZERO {
            return Err(Invalid("guest handshake epoch must be positive"));
        }
        let hello = GuestHello {
            version: HANDSHAKE_VERSION,
            sandbox_id,
            epoch,
            boot_identity,
            client_nonce: nonce.to_vec(),
        };
        let transcript = bounded_json(&hello)?;
        Ok((
            Self {
                capability,
                transcript,
            },
            hello,
        ))
    }

    pub fn finish(
        self,
        challenge: &GuestChallenge,
    ) -> Result<(GuestFinish, SessionCodec), Invalid> {
        validate_bytes(
            &challenge.server_nonce,
            NONCE_BYTES,
            "guest challenge nonce is invalid",
        )?;
        validate_bytes(
            &challenge.proof,
            AUTHENTICATION_BYTES,
            "guest challenge proof is invalid",
        )?;
        let mut transcript = self.transcript;
        append_field(&mut transcript, &challenge.server_nonce)?;
        let expected = authenticate(&self.capability.0, LABEL_CHALLENGE, &transcript)?;
        if !constant_time_equal(&expected, &challenge.proof) {
            return Err(Invalid("guest challenge authentication failed"));
        }
        let proof = authenticate(&self.capability.0, LABEL_FINISH, &transcript)?;
        let session = SessionCodec::from_transcript(&self.capability, &transcript)?;
        Ok((
            GuestFinish {
                proof: proof.to_vec(),
            },
            session,
        ))
    }
}

impl GuestHandshake {
    pub fn accept(
        capability: BootCapability,
        expected_sandbox: &SandboxId,
        expected_epoch: Counter,
        expected_boot: &Digest,
        hello: &GuestHello,
    ) -> Result<(Self, GuestChallenge), Invalid> {
        let mut nonce = [0; NONCE_BYTES];
        getrandom::getrandom(&mut nonce)
            .map_err(|_| Invalid("guest handshake entropy unavailable"))?;
        Self::accept_with_nonce(
            capability,
            expected_sandbox,
            expected_epoch,
            expected_boot,
            hello,
            nonce,
        )
    }

    pub fn accept_with_nonce(
        capability: BootCapability,
        expected_sandbox: &SandboxId,
        expected_epoch: Counter,
        expected_boot: &Digest,
        hello: &GuestHello,
        nonce: [u8; NONCE_BYTES],
    ) -> Result<(Self, GuestChallenge), Invalid> {
        if hello.version != HANDSHAKE_VERSION
            || &hello.sandbox_id != expected_sandbox
            || hello.epoch != expected_epoch
            || &hello.boot_identity != expected_boot
        {
            return Err(Invalid("guest handshake identity mismatch"));
        }
        validate_bytes(
            &hello.client_nonce,
            NONCE_BYTES,
            "guest hello nonce is invalid",
        )?;
        let mut transcript = bounded_json(hello)?;
        append_field(&mut transcript, &nonce)?;
        let proof = authenticate(&capability.0, LABEL_CHALLENGE, &transcript)?;
        Ok((
            Self {
                capability,
                transcript,
            },
            GuestChallenge {
                server_nonce: nonce.to_vec(),
                proof: proof.to_vec(),
            },
        ))
    }

    pub fn finish(self, finish: &GuestFinish) -> Result<SessionCodec, Invalid> {
        validate_bytes(
            &finish.proof,
            AUTHENTICATION_BYTES,
            "host finish proof is invalid",
        )?;
        let expected = authenticate(&self.capability.0, LABEL_FINISH, &self.transcript)?;
        if !constant_time_equal(&expected, &finish.proof) {
            return Err(Invalid("host finish authentication failed"));
        }
        SessionCodec::from_transcript(&self.capability, &self.transcript)
    }
}

/// Per-reconnect authenticated multiplexing state. Sequence and credit state is
/// never restored from an older connection; durable operation reconciliation
/// happens in the guest ledger above this channel.
pub struct SessionCodec {
    key: [u8; 32],
    id: Digest,
    outbound: BTreeMap<u32, Counter>,
    inbound: BTreeMap<u32, Counter>,
    send_credit: BTreeMap<u32, u64>,
    receive_credit: BTreeMap<u32, u64>,
}

impl std::fmt::Debug for SessionCodec {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output
            .debug_struct("SessionCodec")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl Drop for SessionCodec {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl SessionCodec {
    fn from_transcript(capability: &BootCapability, transcript: &[u8]) -> Result<Self, Invalid> {
        let key = authenticate(&capability.0, LABEL_SESSION, transcript)?;
        let id = bytes_digest(&key);
        Ok(Self {
            key,
            id,
            outbound: BTreeMap::new(),
            inbound: BTreeMap::new(),
            send_credit: BTreeMap::new(),
            receive_credit: BTreeMap::new(),
        })
    }

    pub fn id(&self) -> &Digest {
        &self.id
    }

    /// Stream zero is reserved for control. Host-created streams are odd and
    /// guest-created streams are even, preventing stream-ID collisions.
    pub fn open_stream(&mut self, stream: u32, opened_by_host: bool) -> Result<(), Invalid> {
        if stream == 0
            || (stream % 2 == 1) != opened_by_host
            || self.outbound.len() >= MAX_STREAMS
            || self.outbound.contains_key(&stream)
        {
            return Err(Invalid("authenticated stream admission refused"));
        }
        self.outbound.insert(stream, Counter::ZERO);
        self.inbound.insert(stream, Counter::ZERO);
        self.send_credit.insert(stream, 0);
        self.receive_credit.insert(stream, 0);
        Ok(())
    }

    pub fn close_stream(&mut self, stream: u32) -> Result<(), Invalid> {
        if self.outbound.remove(&stream).is_none() {
            return Err(Invalid("unknown authenticated stream"));
        }
        self.inbound.remove(&stream);
        self.send_credit.remove(&stream);
        self.receive_credit.remove(&stream);
        Ok(())
    }

    pub fn grant_receive_credit(&mut self, stream: u32, amount: u64) -> Result<(), Invalid> {
        add_credit(&mut self.receive_credit, stream, amount)
    }

    pub fn accept_send_credit(&mut self, stream: u32, amount: u64) -> Result<(), Invalid> {
        add_credit(&mut self.send_credit, stream, amount)
    }

    pub fn seal(&mut self, mut frame: Frame) -> Result<Frame, Invalid> {
        require_stream(&self.outbound, &frame)?;
        if frame.kind == FrameKind::Data {
            consume_credit(&mut self.send_credit, frame.stream, frame.payload.len())?;
        }
        let expected = next_sequence(&mut self.outbound, frame.stream)?;
        if frame.sequence != expected || frame.authentication != [0; AUTHENTICATION_BYTES] {
            return Err(Invalid("outbound authenticated frame sequence is invalid"));
        }
        frame.authentication = frame_tag(&self.key, &self.id, &frame)?;
        Ok(frame)
    }

    pub fn open(&mut self, frame: Frame) -> Result<Frame, Invalid> {
        require_stream(&self.inbound, &frame)?;
        let current = self
            .inbound
            .get(&frame.stream)
            .copied()
            .unwrap_or(Counter::ZERO);
        let expected = current.next()?;
        if frame.sequence != expected {
            return Err(Invalid("inbound authenticated frame sequence is invalid"));
        }
        let expected_tag = frame_tag(&self.key, &self.id, &frame)?;
        if !constant_time_equal(&expected_tag, &frame.authentication) {
            return Err(Invalid("authenticated frame proof is invalid"));
        }
        if frame.kind == FrameKind::Data {
            consume_credit(&mut self.receive_credit, frame.stream, frame.payload.len())?;
        }
        self.inbound.insert(frame.stream, frame.sequence);
        Ok(frame)
    }
}

fn require_stream(sequences: &BTreeMap<u32, Counter>, frame: &Frame) -> Result<(), Invalid> {
    if frame.stream == 0 {
        if frame.kind != FrameKind::Control {
            return Err(Invalid("stream zero only accepts control traffic"));
        }
    } else if !sequences.contains_key(&frame.stream) {
        return Err(Invalid("unknown authenticated stream"));
    }
    Ok(())
}

fn next_sequence(sequences: &mut BTreeMap<u32, Counter>, stream: u32) -> Result<Counter, Invalid> {
    let current = sequences.entry(stream).or_insert(Counter::ZERO);
    let next = current.next()?;
    *current = next;
    Ok(next)
}

fn add_credit(credits: &mut BTreeMap<u32, u64>, stream: u32, amount: u64) -> Result<(), Invalid> {
    let current = credits
        .get_mut(&stream)
        .ok_or(Invalid("unknown authenticated stream"))?;
    *current = current
        .checked_add(amount)
        .filter(|value| *value <= MAX_CREDIT)
        .ok_or(Invalid("authenticated stream credit overflow"))?;
    Ok(())
}

fn consume_credit(
    credits: &mut BTreeMap<u32, u64>,
    stream: u32,
    amount: usize,
) -> Result<(), Invalid> {
    let current = credits
        .get_mut(&stream)
        .ok_or(Invalid("unknown authenticated stream"))?;
    *current = current
        .checked_sub(amount as u64)
        .ok_or(Invalid("authenticated stream credit exhausted"))?;
    Ok(())
}

fn frame_tag(key: &[u8; 32], session_id: &Digest, frame: &Frame) -> Result<[u8; 32], Invalid> {
    let mut material = Vec::with_capacity(96 + frame.payload.len());
    material.extend_from_slice(session_id.as_str().as_bytes());
    material.push(frame.kind as u8);
    material.extend_from_slice(&frame.stream.to_be_bytes());
    material.extend_from_slice(&frame.sequence.get().to_be_bytes());
    material.extend_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    material.extend_from_slice(&frame.payload);
    authenticate(key, LABEL_FRAME, &material)
}

fn authenticate(key: &[u8], label: &[u8], value: &[u8]) -> Result<[u8; 32], Invalid> {
    let mut hmac =
        HmacSha256::new_from_slice(key).map_err(|_| Invalid("invalid authentication key"))?;
    hmac.update(label);
    hmac.update(&(value.len() as u64).to_be_bytes());
    hmac.update(value);
    Ok(hmac.finalize().into_bytes().into())
}

fn bounded_json<T: Serialize>(value: &T) -> Result<Vec<u8>, Invalid> {
    let result = serde_json::to_vec(value).map_err(|_| Invalid("handshake encoding failed"))?;
    if result.len() > crate::MAX_CONTROL_BYTES {
        return Err(Invalid("handshake exceeds control bound"));
    }
    Ok(result)
}

fn append_field(target: &mut Vec<u8>, field: &[u8]) -> Result<(), Invalid> {
    let length = u32::try_from(field.len()).map_err(|_| Invalid("handshake field is oversized"))?;
    target.extend_from_slice(&length.to_be_bytes());
    target.extend_from_slice(field);
    if target.len() > crate::MAX_CONTROL_BYTES {
        return Err(Invalid("handshake transcript exceeds control bound"));
    }
    Ok(())
}

fn validate_bytes(value: &[u8], expected: usize, message: &'static str) -> Result<(), Invalid> {
    if value.len() != expected {
        return Err(Invalid(message));
    }
    Ok(())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FrameKind, MAX_STREAM_BYTES};

    fn sessions(epoch: u64) -> (SessionCodec, SessionCodec) {
        let sandbox = SandboxId::try_from("box").unwrap();
        let boot = bytes_digest(b"verified-boot");
        let capability = [7; 32];
        let (host, hello) = HostHandshake::start_with_nonce(
            BootCapability::from_bytes(capability),
            sandbox.clone(),
            epoch.try_into().unwrap(),
            boot.clone(),
            [1; 32],
        )
        .unwrap();
        let (guest, challenge) = GuestHandshake::accept_with_nonce(
            BootCapability::from_bytes(capability),
            &sandbox,
            epoch.try_into().unwrap(),
            &boot,
            &hello,
            [2; 32],
        )
        .unwrap();
        let (finish, host_session) = host.finish(&challenge).unwrap();
        let guest_session = guest.finish(&finish).unwrap();
        assert_eq!(host_session.id(), guest_session.id());
        (host_session, guest_session)
    }

    fn frame(stream: u32, sequence: u64, payload: &[u8]) -> Frame {
        Frame {
            kind: FrameKind::Data,
            stream,
            sequence: sequence.try_into().unwrap(),
            authentication: [0; AUTHENTICATION_BYTES],
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn handshake_binds_identity_epoch_and_rotates_reconnect_session() {
        let (first, _) = sessions(1);
        let (second, _) = sessions(2);
        assert_ne!(first.id(), second.id());
        let (third, _) = sessions(1);
        assert_eq!(first.id(), third.id());

        let sandbox = SandboxId::try_from("box").unwrap();
        let boot = bytes_digest(b"verified-boot");
        let (_, hello) = HostHandshake::start_with_nonce(
            BootCapability::from_bytes([7; 32]),
            sandbox.clone(),
            Counter::ONE,
            boot.clone(),
            [1; 32],
        )
        .unwrap();
        assert!(
            GuestHandshake::accept_with_nonce(
                BootCapability::from_bytes([7; 32]),
                &sandbox,
                2_u64.try_into().unwrap(),
                &boot,
                &hello,
                [2; 32]
            )
            .is_err()
        );
    }

    #[test]
    fn authenticated_streams_enforce_order_proof_direction_and_credit() {
        let (mut host, mut guest) = sessions(1);
        host.open_stream(1, true).unwrap();
        guest.open_stream(1, true).unwrap();
        host.accept_send_credit(1, 5).unwrap();
        guest.grant_receive_credit(1, 5).unwrap();
        let sealed = host.seal(frame(1, 1, b"hello")).unwrap();
        assert_eq!(guest.open(sealed.clone()).unwrap().payload, b"hello");
        assert!(guest.open(sealed).is_err());
        assert!(host.seal(frame(1, 2, b"x")).is_err());
        assert!(host.open_stream(2, true).is_err());
        assert!(host.open_stream(3, true).is_ok());
        assert!(host.accept_send_credit(3, MAX_CREDIT + 1).is_err());
        assert!(host.accept_send_credit(3, MAX_STREAM_BYTES as u64).is_ok());
    }

    #[test]
    fn tampering_and_wrong_boot_capability_fail_closed() {
        let (mut host, mut guest) = sessions(1);
        host.open_stream(1, true).unwrap();
        guest.open_stream(1, true).unwrap();
        host.accept_send_credit(1, 16).unwrap();
        guest.grant_receive_credit(1, 16).unwrap();
        let mut sealed = host.seal(frame(1, 1, b"protected")).unwrap();
        sealed.payload[0] ^= 1;
        assert!(guest.open(sealed).is_err());

        let sandbox = SandboxId::try_from("box").unwrap();
        let boot = bytes_digest(b"verified-boot");
        let (host, hello) = HostHandshake::start_with_nonce(
            BootCapability::from_bytes([1; 32]),
            sandbox.clone(),
            Counter::ONE,
            boot.clone(),
            [1; 32],
        )
        .unwrap();
        let (_, challenge) = GuestHandshake::accept_with_nonce(
            BootCapability::from_bytes([2; 32]),
            &sandbox,
            Counter::ONE,
            &boot,
            &hello,
            [2; 32],
        )
        .unwrap();
        assert!(host.finish(&challenge).is_err());
    }
}
