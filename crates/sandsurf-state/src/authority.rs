use crate::{
    Error, Result,
    database::{private_file, sync_directory, sync_file},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sandsurf_protocol::*;
use std::io::{Read, Write};
use std::path::Path;
use zeroize::Zeroize;

const AUTHORITY_VERSION: u16 = 1;
const PRIVATE_KEY_FILE: &str = "authority.key";

pub(crate) struct HostAuthority {
    signing_key: SigningKey,
    binding: AuthorityBinding,
}

impl HostAuthority {
    pub(crate) fn create(root: &Path, host_id: HostId) -> Result<Self> {
        let mut seed = [0_u8; 32];
        getrandom::getrandom(&mut seed)
            .map_err(|error| std::io::Error::other(format!("authority key generation: {error}")))?;
        let mut file = private_file(&root.join(PRIVATE_KEY_FILE), true)?;
        file.write_all(&seed)?;
        sync_file(&file)?;
        sync_directory(root)?;
        Self::from_seed(host_id, seed)
    }

    pub(crate) fn open(root: &Path, expected: &AuthorityBinding) -> Result<Self> {
        let mut file = private_file(&root.join(PRIVATE_KEY_FILE), false)?;
        let mut seed = [0_u8; 32];
        file.read_exact(&mut seed)?;
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing)? != 0 {
            return Err(Error::Corrupt(
                "authority private key has an invalid length",
            ));
        }
        let authority = Self::from_seed(expected.host_id.clone(), seed)?;
        if authority.binding != *expected {
            return Err(Error::Corrupt(
                "authority private key does not match the pinned host identity",
            ));
        }
        Ok(authority)
    }

    fn from_seed(host_id: HostId, mut seed: [u8; 32]) -> Result<Self> {
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let public = signing_key.verifying_key().to_bytes();
        let binding = AuthorityBinding {
            host_id,
            key_id: bytes_digest(&public),
            public_key: encode_hex(&public).try_into()?,
        };
        Ok(Self {
            signing_key,
            binding,
        })
    }

    pub(crate) fn binding(&self) -> &AuthorityBinding {
        &self.binding
    }

    pub(crate) fn authorize_mutation(
        &self,
        mutation: Mutation,
        capability: Capability,
        scope_digest: Digest,
        grant_revision: Counter,
    ) -> Result<AuthorizedMutation> {
        let statement = AuthorizedMutationStatement {
            version: AUTHORITY_VERSION,
            host_id: self.binding.host_id.clone(),
            key_id: self.binding.key_id.clone(),
            mutation,
            capability,
            scope_digest,
            grant_revision,
        };
        let signature = self.sign("host-authorized-mutation-v1", &statement)?;
        Ok(AuthorizedMutation {
            statement,
            signature,
        })
    }

    pub(crate) fn authorize_loss(
        &self,
        sandbox_id: SandboxId,
        process_id: ProcessId,
        receipt_digest: Digest,
        output: OutputBoundary,
        approval_id: CommitmentId,
        request_digest: Digest,
    ) -> Result<AuthorizedLoss> {
        let statement = AuthorizedLossStatement {
            version: AUTHORITY_VERSION,
            host_id: self.binding.host_id.clone(),
            key_id: self.binding.key_id.clone(),
            sandbox_id,
            process_id,
            receipt_digest,
            output,
            approval_id,
            request_digest,
        };
        let signature = self.sign("host-authorized-loss-v1", &statement)?;
        Ok(AuthorizedLoss {
            statement,
            signature,
        })
    }

    fn sign<T: serde::Serialize>(&self, tag: &str, statement: &T) -> Result<AuthoritySignature> {
        let identity = digest(Domain::Operation, &(tag, statement))?;
        let signature = self.signing_key.sign(identity.as_str().as_bytes());
        Ok(encode_hex(&signature.to_bytes()).try_into()?)
    }
}

pub(crate) struct AuthorityVerifier {
    binding: AuthorityBinding,
    verifying_key: VerifyingKey,
}

impl AuthorityVerifier {
    pub(crate) fn new(binding: AuthorityBinding) -> Result<Self> {
        let public = decode_hex::<32>(binding.public_key.as_str())?;
        if bytes_digest(&public) != binding.key_id {
            return Err(Error::Corrupt(
                "authority key identity does not match its bytes",
            ));
        }
        let verifying_key = VerifyingKey::from_bytes(&public)
            .map_err(|_| Error::Corrupt("authority public key is invalid"))?;
        Ok(Self {
            binding,
            verifying_key,
        })
    }

    pub(crate) fn binding(&self) -> &AuthorityBinding {
        &self.binding
    }

    pub(crate) fn verify_mutation(&self, value: &AuthorizedMutation) -> Result<()> {
        self.verify_statement(
            value.statement.version,
            &value.statement.host_id,
            &value.statement.key_id,
            "host-authorized-mutation-v1",
            &value.statement,
            &value.signature,
        )
    }

    pub(crate) fn verify_loss(&self, value: &AuthorizedLoss) -> Result<()> {
        self.verify_statement(
            value.statement.version,
            &value.statement.host_id,
            &value.statement.key_id,
            "host-authorized-loss-v1",
            &value.statement,
            &value.signature,
        )
    }

    fn verify_statement<T: serde::Serialize>(
        &self,
        version: u16,
        host_id: &HostId,
        key_id: &Digest,
        tag: &str,
        statement: &T,
        signature: &AuthoritySignature,
    ) -> Result<()> {
        if version != AUTHORITY_VERSION
            || host_id != &self.binding.host_id
            || key_id != &self.binding.key_id
        {
            return Err(Error::Conflict("host authority binding mismatch"));
        }
        let identity = digest(Domain::Operation, &(tag, statement))?;
        let signature = Signature::from_bytes(&decode_hex::<64>(signature.as_str())?);
        self.verifying_key
            .verify(identity.as_str().as_bytes(), &signature)
            .map_err(|_| Error::Conflict("host authority signature is invalid"))
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0xf) as usize] as char);
    }
    output
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        return Err(Error::Corrupt("authority hex value has an invalid length"));
    }
    let mut output = [0_u8; N];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}

fn nibble(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(Error::Corrupt("authority hex value is invalid")),
    }
}
