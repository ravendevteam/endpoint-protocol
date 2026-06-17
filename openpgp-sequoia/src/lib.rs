use std::collections::HashMap;
use std::io::{Read, Write};

use anyhow::{anyhow, Result};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};
use sequoia_openpgp as openpgp;

use openpgp::armor;
use openpgp::cert::prelude::*;
use openpgp::cert::CipherSuite;
use openpgp::crypto::SessionKey;
use openpgp::packet::{PKESK, SKESK};
use openpgp::parse::stream::{
	DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure, VerificationHelper,
};
use openpgp::parse::Parse;
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Armorer, Encryptor, LiteralWriter, Message, Signer};
use openpgp::serialize::Serialize;
use openpgp::types::SymmetricAlgorithm;
use openpgp::{Cert, KeyHandle};

create_exception!(endpoint_openpgp_sequoia, OpenPgpError, PyException);
create_exception!(endpoint_openpgp_sequoia, CryptoFailed, OpenPgpError);
create_exception!(endpoint_openpgp_sequoia, SignatureInvalid, OpenPgpError);
create_exception!(endpoint_openpgp_sequoia, MalformedCiphertext, OpenPgpError);

#[pyfunction]
fn generate_identity(name: &str, email: &str) -> PyResult<HashMap<String, String>> {
	generate_identity_inner(name, email).map_err(to_crypto_failed)
}

fn generate_identity_inner(name: &str, email: &str) -> Result<HashMap<String, String>> {
	let userid = if email.is_empty() {
		name.to_string()
	} else {
		format!("{} <{}>", name, email)
	};
	let (cert, _) = CertBuilder::general_purpose([userid.as_str()])
		.set_profile(openpgp::Profile::RFC4880)?
		.set_cipher_suite(CipherSuite::Cv25519)
		.generate()?;
	let public_key_armored = armor_cert(&cert)?;
	let secret_key_armored = armor_secret_cert(&cert)?;
	let mut out = HashMap::new();
	out.insert("raw_fingerprint".to_string(), cert.fingerprint().to_string());
	out.insert("public_key_armored".to_string(), public_key_armored);
	out.insert("secret_key_armored".to_string(), secret_key_armored);
	Ok(out)
}

#[pyfunction]
fn canonical_public_key_bytes(py: Python<'_>, public_key_armored: &str) -> PyResult<Py<PyBytes>> {
	let bytes = canonical_public_key_bytes_inner(public_key_armored).map_err(to_crypto_failed)?;
	Ok(PyBytes::new_bound(py, &bytes).into())
}

fn canonical_public_key_bytes_inner(public_key_armored: &str) -> Result<Vec<u8>> {
	let cert = parse_cert(public_key_armored)?;
	let mut out = Vec::new();
	cert.export(&mut out)?;
	Ok(out)
}

#[pyfunction]
fn raw_openpgp_fingerprint(public_key_armored: &str) -> PyResult<String> {
	let cert = parse_cert(public_key_armored).map_err(to_crypto_failed)?;
	Ok(cert.fingerprint().to_string())
}

#[pyfunction]
fn sign_detached(secret_key_armored: &str, payload: &[u8]) -> PyResult<String> {
	sign_detached_inner(secret_key_armored, payload).map_err(to_crypto_failed)
}

fn sign_detached_inner(secret_key_armored: &str, payload: &[u8]) -> Result<String> {
	let cert = parse_cert(secret_key_armored)?;
	let policy = StandardPolicy::new();
	let signing_key = cert
		.keys()
		.unencrypted_secret()
		.with_policy(&policy, None)
		.supported()
		.alive()
		.revoked(false)
		.for_signing()
		.next()
		.ok_or_else(|| anyhow!("no signing key"))?;
	let key = signing_key.key().clone();
	let keypair = key.into_keypair()?;
	let mut sink = Vec::new();
	{
		let message = Message::new(&mut sink);
		let message = Armorer::new(message).kind(armor::Kind::Signature).build()?;
		let mut signer = Signer::new(message, keypair)?.detached().build()?;
		signer.write_all(payload)?;
		signer.finalize()?;
	}
	String::from_utf8(sink).map_err(Into::into)
}

#[pyfunction]
fn verify_detached(public_key_armored: &str, payload: &[u8], signature_armored: &str) -> PyResult<()> {
	verify_detached_inner(public_key_armored, payload, signature_armored).map_err(to_signature_invalid)
}

fn verify_detached_inner(public_key_armored: &str, payload: &[u8], signature_armored: &str) -> Result<()> {
	let cert = parse_cert(public_key_armored)?;
	let policy = StandardPolicy::new();
	let helper = VerifyHelper { cert };
	let mut verifier = DetachedVerifierBuilder::from_bytes(signature_armored.as_bytes())?
		.with_policy(&policy, None, helper)?;
	verifier.verify_bytes(payload)?;
	Ok(())
}

#[pyfunction]
fn encrypt_to(public_key_armored: &str, plaintext: &[u8]) -> PyResult<String> {
	encrypt_to_inner(public_key_armored, plaintext).map_err(to_crypto_failed)
}

fn encrypt_to_inner(public_key_armored: &str, plaintext: &[u8]) -> Result<String> {
	let cert = parse_cert(public_key_armored)?;
	let policy = StandardPolicy::new();
	let recipients: Vec<_> = cert
		.keys()
		.with_policy(&policy, None)
		.supported()
		.alive()
		.revoked(false)
		.for_transport_encryption()
		.collect();
	if recipients.is_empty() {
		return Err(anyhow!("no encryption key"));
	}
	let mut sink = Vec::new();
	{
		let message = Message::new(&mut sink);
		let message = Armorer::new(message).kind(armor::Kind::Message).build()?;
		let message = Encryptor::for_recipients(message, recipients).build()?;
		let mut writer = LiteralWriter::new(message).build()?;
		writer.write_all(plaintext)?;
		writer.finalize()?;
	}
	String::from_utf8(sink).map_err(Into::into)
}

#[pyfunction]
fn decrypt(py: Python<'_>, secret_key_armored: &str, ciphertext_armored: &str) -> PyResult<Py<PyBytes>> {
	let bytes = decrypt_inner(secret_key_armored, ciphertext_armored).map_err(to_malformed_ciphertext)?;
	Ok(PyBytes::new_bound(py, &bytes).into())
}

fn decrypt_inner(secret_key_armored: &str, ciphertext_armored: &str) -> Result<Vec<u8>> {
	let cert = parse_cert(secret_key_armored)?;
	let policy = StandardPolicy::new();
	let helper = DecryptHelper { cert };
	let mut decryptor = DecryptorBuilder::from_bytes(ciphertext_armored.as_bytes())?
		.with_policy(&policy, None, helper)?;
	let mut out = Vec::new();
	decryptor.read_to_end(&mut out)?;
	Ok(out)
}

fn parse_cert(armored: &str) -> Result<Cert> {
	Cert::from_bytes(armored.as_bytes()).map_err(Into::into)
}

fn armor_cert(cert: &Cert) -> Result<String> {
	let mut out = Vec::new();
	cert.armored().export(&mut out)?;
	String::from_utf8(out).map_err(Into::into)
}

fn armor_secret_cert(cert: &Cert) -> Result<String> {
	let mut out = Vec::new();
	cert.as_tsk().armored().export(&mut out)?;
	String::from_utf8(out).map_err(Into::into)
}

struct VerifyHelper {
	cert: Cert,
}

impl VerificationHelper for VerifyHelper {
	fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
		Ok(vec![self.cert.clone()])
	}

	fn check(&mut self, structure: MessageStructure<'_>) -> openpgp::Result<()> {
		for layer in structure.into_iter() {
			if let MessageLayer::SignatureGroup { results } = layer {
				if results.iter().any(|result| result.is_ok()) {
					return Ok(());
				}
			}
		}
		Err(anyhow!("no valid signature"))
	}
}

struct DecryptHelper {
	cert: Cert,
}

impl VerificationHelper for DecryptHelper {
	fn get_certs(&mut self, _ids: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
		Ok(Vec::new())
	}

	fn check(&mut self, _structure: MessageStructure<'_>) -> openpgp::Result<()> {
		Ok(())
	}
}

impl DecryptionHelper for DecryptHelper {
	fn decrypt(
		&mut self,
		pkesks: &[PKESK],
		_skesks: &[SKESK],
		sym_algo: Option<SymmetricAlgorithm>,
		decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
	) -> openpgp::Result<Option<Cert>> {
		let policy = StandardPolicy::new();
		let keys: Vec<_> = self
			.cert
			.keys()
			.unencrypted_secret()
			.with_policy(&policy, None)
			.supported()
			.alive()
			.revoked(false)
			.for_transport_encryption()
			.collect();
		for pkesk in pkesks {
			for key in &keys {
				let secret = key.key().clone();
				let mut keypair = secret.into_keypair()?;
				if pkesk
					.decrypt(&mut keypair, sym_algo)
					.map(|(algo, session_key)| decrypt(algo, &session_key))
					.unwrap_or(false)
				{
					return Ok(Some(self.cert.clone()));
				}
			}
		}
		Err(anyhow!("no key to decrypt message"))
	}
}

fn to_crypto_failed(err: anyhow::Error) -> PyErr {
	CryptoFailed::new_err(err.to_string())
}

fn to_signature_invalid(err: anyhow::Error) -> PyErr {
	SignatureInvalid::new_err(err.to_string())
}

fn to_malformed_ciphertext(err: anyhow::Error) -> PyErr {
	MalformedCiphertext::new_err(err.to_string())
}

#[pymodule]
fn endpoint_openpgp_sequoia(py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
	module.add("OpenPgpError", py.get_type_bound::<OpenPgpError>())?;
	module.add("CryptoFailed", py.get_type_bound::<CryptoFailed>())?;
	module.add("SignatureInvalid", py.get_type_bound::<SignatureInvalid>())?;
	module.add("MalformedCiphertext", py.get_type_bound::<MalformedCiphertext>())?;
	module.add_function(wrap_pyfunction!(generate_identity, module)?)?;
	module.add_function(wrap_pyfunction!(canonical_public_key_bytes, module)?)?;
	module.add_function(wrap_pyfunction!(raw_openpgp_fingerprint, module)?)?;
	module.add_function(wrap_pyfunction!(sign_detached, module)?)?;
	module.add_function(wrap_pyfunction!(verify_detached, module)?)?;
	module.add_function(wrap_pyfunction!(encrypt_to, module)?)?;
	module.add_function(wrap_pyfunction!(decrypt, module)?)?;
	Ok(())
}
