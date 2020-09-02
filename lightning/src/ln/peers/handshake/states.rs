use bitcoin::secp256k1;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::hashes::sha256::Hash as Sha256;
use bitcoin::secp256k1::{SecretKey, PublicKey};

use ln::peers::{chacha, hkdf5869rfc};
use ln::peers::conduit::{Conduit, SymmetricKey};
use ln::peers::handshake::acts::{Act, ActBuilder, ACT_ONE_LENGTH, ACT_TWO_LENGTH, ACT_THREE_LENGTH, EMPTY_ACT_ONE, EMPTY_ACT_TWO, EMPTY_ACT_THREE};

// Alias type to help differentiate between temporary key and chaining key when passing bytes around
type ChainingKey = [u8; 32];

// Generate a SHA-256 hash from one or more elements concatenated together
macro_rules! concat_then_sha256 {
	( $( $x:expr ),+ ) => {{
		let mut sha = Sha256::engine();
		$(
			sha.input($x.as_ref());
		)+
		Sha256::from_engine(sha)
	}}
}

pub(super) enum HandshakeState {
	InitiatorStarting(InitiatorStartingState),
	ResponderAwaitingActOne(ResponderAwaitingActOneState),
	InitiatorAwaitingActTwo(InitiatorAwaitingActTwoState),
	ResponderAwaitingActThree(ResponderAwaitingActThreeState),
	Complete(Option<(Conduit, PublicKey)>),
}

// Trait for all individual states to implement that ensure HandshakeState::next() can
// delegate to a common function signature. May transition to the same state in the event there are
// not yet enough bytes to move forward with the handshake.
pub(super) trait IHandshakeState {
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState), String>;
}

// Enum dispatch for state machine. Single public interface can statically dispatch to all states
impl HandshakeState {
	pub(super) fn new_initiator(initiator_static_private_key: &SecretKey, responder_static_public_key: &PublicKey, initiator_ephemeral_private_key: &SecretKey) -> Self {
		HandshakeState::InitiatorStarting(InitiatorStartingState::new(initiator_static_private_key.clone(), initiator_ephemeral_private_key.clone(), responder_static_public_key.clone()))
	}
	pub(super) fn new_responder(responder_static_private_key: &SecretKey, responder_ephemeral_private_key: &SecretKey) -> Self {
		HandshakeState::ResponderAwaitingActOne(ResponderAwaitingActOneState::new(responder_static_private_key.clone(), responder_ephemeral_private_key.clone()))
	}
}

impl IHandshakeState for HandshakeState {
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState), String> {
		match self {
			HandshakeState::InitiatorStarting(state) => { state.next(input) },
			HandshakeState::ResponderAwaitingActOne(state) => { state.next(input) },
			HandshakeState::InitiatorAwaitingActTwo(state) => { state.next(input) },
			HandshakeState::ResponderAwaitingActThree(state) => { state.next(input) },
			HandshakeState::Complete(_conduit) => { panic!("no acts left to process") }
		}
	}
}

// Handshake state of the Initiator prior to generating Act 1
pub(super) struct InitiatorStartingState {
	initiator_static_private_key: SecretKey,
	initiator_static_public_key: PublicKey,
	initiator_ephemeral_private_key: SecretKey,
	initiator_ephemeral_public_key: PublicKey,
	responder_static_public_key: PublicKey,
	chaining_key: Sha256,
	hash: Sha256
}

// Handshake state of the Responder prior to receiving Act 1
pub(super) struct ResponderAwaitingActOneState {
	responder_static_private_key: SecretKey,
	responder_ephemeral_private_key: SecretKey,
	responder_ephemeral_public_key: PublicKey,
	chaining_key: Sha256,
	hash: Sha256,
	act_one_builder: ActBuilder
}

// Handshake state of the Initiator prior to receiving Act 2
pub(super) struct InitiatorAwaitingActTwoState {
	initiator_static_private_key: SecretKey,
	initiator_static_public_key: PublicKey,
	initiator_ephemeral_private_key: SecretKey,
	responder_static_public_key: PublicKey,
	chaining_key: ChainingKey,
	hash: Sha256,
	act_two_builder: ActBuilder
}

// Handshake state of the Responder prior to receiving Act 3
pub(super) struct ResponderAwaitingActThreeState {
	hash: Sha256,
	responder_ephemeral_private_key: SecretKey,
	chaining_key: ChainingKey,
	temporary_key: [u8; 32],
	act_three_builder: ActBuilder
}

impl InitiatorStartingState {
	pub(crate) fn new(initiator_static_private_key: SecretKey, initiator_ephemeral_private_key: SecretKey, responder_static_public_key: PublicKey) -> Self {
		let initiator_static_public_key = private_key_to_public_key(&initiator_static_private_key);
		let (hash, chaining_key) = handshake_state_initialization(&responder_static_public_key);
		let initiator_ephemeral_public_key = private_key_to_public_key(&initiator_ephemeral_private_key);
		InitiatorStartingState {
			initiator_static_private_key,
			initiator_static_public_key,
			initiator_ephemeral_private_key,
			initiator_ephemeral_public_key,
			responder_static_public_key,
			chaining_key,
			hash
		}
	}
}

impl IHandshakeState for InitiatorStartingState {
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-one (sender)
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState), String> {

		if input.len() > 0 {
			return Err("first call for initiator must be empty".to_string());
		}

		let initiator_static_private_key = self.initiator_static_private_key;
		let initiator_static_public_key = self.initiator_static_public_key;
		let initiator_ephemeral_private_key = self.initiator_ephemeral_private_key;
		let initiator_ephemeral_public_key = self.initiator_ephemeral_public_key;
		let responder_static_public_key = self.responder_static_public_key;
		let chaining_key = self.chaining_key;
		let hash = self.hash;

		// serialize act one
		let mut act_one = EMPTY_ACT_ONE;
		let (hash, chaining_key, _) = calculate_act_message(
			&initiator_ephemeral_private_key,
			&initiator_ephemeral_public_key,
			&responder_static_public_key,
			chaining_key.into_inner(),
			hash,
			&mut act_one
		);

		Ok((
			Some(Act::One(act_one)),
			HandshakeState::InitiatorAwaitingActTwo(InitiatorAwaitingActTwoState {
				initiator_static_private_key,
				initiator_static_public_key,
				initiator_ephemeral_private_key,
				responder_static_public_key,
				chaining_key,
				hash,
				act_two_builder: ActBuilder::new(Act::Two(EMPTY_ACT_TWO))
			})
		))
	}
}

impl ResponderAwaitingActOneState {
	pub(crate) fn new(responder_static_private_key: SecretKey, responder_ephemeral_private_key: SecretKey) -> Self {
		let responder_static_public_key = private_key_to_public_key(&responder_static_private_key);
		let (hash, chaining_key) = handshake_state_initialization(&responder_static_public_key);
		let responder_ephemeral_public_key = private_key_to_public_key(&responder_ephemeral_private_key);

		ResponderAwaitingActOneState {
			responder_static_private_key,
			responder_ephemeral_private_key,
			responder_ephemeral_public_key,
			chaining_key,
			hash,
			act_one_builder: ActBuilder::new(Act::One(EMPTY_ACT_ONE))
		}
	}
}

impl IHandshakeState for ResponderAwaitingActOneState {
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-one (receiver)
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-two (sender)
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState), String> {
		let mut act_one_builder = self.act_one_builder;
		let remaining = act_one_builder.fill(input);

		// Any payload larger than ACT_ONE_LENGTH indicates a bad peer since initiator data
		// is required to generate act3 (so it can't come before we transition)
		if remaining.len() != 0 {
			return Err("Act One too large".to_string());
		}

		// In the event of a partial fill, stay in the same state and wait for more data
		if !act_one_builder.is_finished() {
			assert_eq!(remaining.len(), 0);
			return Ok((
				None,
				HandshakeState::ResponderAwaitingActOne(Self {
					responder_static_private_key: self.responder_static_private_key,
					responder_ephemeral_private_key: self.responder_ephemeral_private_key,
					responder_ephemeral_public_key: self.responder_ephemeral_public_key,
					chaining_key: self.chaining_key,
					hash: self.hash,
					act_one_builder
				})
			));
		}

		let hash = self.hash;
		let responder_static_private_key = self.responder_static_private_key;
		let chaining_key = self.chaining_key;
		let responder_ephemeral_private_key = self.responder_ephemeral_private_key;
		let responder_ephemeral_public_key = self.responder_ephemeral_public_key;
		let act_one = Act::from(act_one_builder);

		let (initiator_ephemeral_public_key, hash, chaining_key, _) = process_act_message(
			&act_one,
			&responder_static_private_key,
			chaining_key.into_inner(),
			hash,
		)?;

		let mut act_two = EMPTY_ACT_TWO;
		let (hash, chaining_key, temporary_key) = calculate_act_message(
			&responder_ephemeral_private_key,
			&responder_ephemeral_public_key,
			&initiator_ephemeral_public_key,
			chaining_key,
			hash,
			&mut act_two
		);

		Ok((
			Some(Act::Two(act_two)),
			HandshakeState::ResponderAwaitingActThree(ResponderAwaitingActThreeState {
				hash,
				responder_ephemeral_private_key,
				chaining_key,
				temporary_key,
				act_three_builder: ActBuilder::new(Act::Three(EMPTY_ACT_THREE))
			})
		))
	}
}

impl IHandshakeState for InitiatorAwaitingActTwoState {
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-two (receiver)
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-three (sender)
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState), String> {
		let mut act_two_builder = self.act_two_builder;
		let remaining = act_two_builder.fill(input);

		// Any payload larger than ACT_TWO_LENGTH indicates a bad peer since responder data
		// is required to generate post-authentication messages (so it can't come before we transition)
		if remaining.len() != 0 {
			return Err("Act Two too large".to_string());
		}

		// In the event of a partial fill, stay in the same state and wait for more data
		if !act_two_builder.is_finished() {
			assert_eq!(remaining.len(), 0);
			return Ok((
				None,
				HandshakeState::InitiatorAwaitingActTwo(Self {
					initiator_static_private_key: self.initiator_static_private_key,
					initiator_static_public_key: self.initiator_static_public_key,
					initiator_ephemeral_private_key: self.initiator_ephemeral_private_key,
					responder_static_public_key: self.responder_static_public_key,
					chaining_key: self.chaining_key,
					hash: self.hash,
					act_two_builder
				})
			));
		}

		let initiator_static_private_key = self.initiator_static_private_key;
		let initiator_static_public_key = self.initiator_static_public_key;
		let initiator_ephemeral_private_key = self.initiator_ephemeral_private_key;
		let responder_static_public_key = self.responder_static_public_key;
		let hash = self.hash;
		let chaining_key = self.chaining_key;
		let act_two = Act::from(act_two_builder);

		let (responder_ephemeral_public_key, hash, chaining_key, temporary_key) = process_act_message(
			&act_two,
			&initiator_ephemeral_private_key,
			chaining_key,
			hash,
		)?;

		let mut act_three = EMPTY_ACT_THREE;

		// start serializing act three
		// 1. c = encryptWithAD(temp_k2, 1, h, s.pub.serializeCompressed())
		chacha::encrypt(&temporary_key, 1, &hash, &initiator_static_public_key.serialize(), &mut act_three[1..50]);

		// 2. h = SHA-256(h || c)
		let hash = concat_then_sha256!(hash, act_three[1..50]);

		// 3. se = ECDH(s.priv, re)
		let ecdh = ecdh(&initiator_static_private_key, &responder_ephemeral_public_key);

		// 4. ck, temp_k3 = HKDF(ck, se)
		let (chaining_key, temporary_key) = hkdf5869rfc::derive(&chaining_key, &ecdh);

		// 5. t = encryptWithAD(temp_k3, 0, h, zero)
		chacha::encrypt(&temporary_key, 0, &hash, &[0; 0], &mut act_three[50..]);

		// 6. sk, rk = HKDF(ck, zero)
		let (sending_key, receiving_key) = hkdf5869rfc::derive(&chaining_key, &[0; 0]);

		// 7. rn = 0, sn = 0
		// - done by Conduit
		let conduit = Conduit::new(sending_key, receiving_key, chaining_key);

		// 8. Send m = 0 || c || t
		Ok((
			Some(Act::Three(act_three)),
			HandshakeState::Complete(Some((conduit, responder_static_public_key)))
		))
	}
}

impl IHandshakeState for ResponderAwaitingActThreeState {
	// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-three (receiver)
	fn next(self, input: &[u8]) -> Result<(Option<Act>, HandshakeState), String> {
		let mut act_three_builder = self.act_three_builder;
		let remaining = act_three_builder.fill(input);

		// In the event of a partial fill, stay in the same state and wait for more data
		if !act_three_builder.is_finished() {
			assert_eq!(remaining.len(), 0);
			return Ok((
				None,
				HandshakeState::ResponderAwaitingActThree(Self {
					hash: self.hash,
					responder_ephemeral_private_key: self.responder_ephemeral_private_key,
					chaining_key: self.chaining_key,
					temporary_key: self.temporary_key,
					act_three_builder
				})
			));
		}

		let hash = self.hash;
		let temporary_key = self.temporary_key;
		let responder_ephemeral_private_key = self.responder_ephemeral_private_key;
		let chaining_key = self.chaining_key;

		// 1. Read exactly 66 bytes from the network buffer
		let act_three_bytes = Act::from(act_three_builder);
		assert_eq!(act_three_bytes.len(), ACT_THREE_LENGTH);

		// 2. Parse the read message (m) into v, c, and t
		let version = act_three_bytes[0];
		let tagged_encrypted_pubkey = &act_three_bytes[1..50];
		let chacha_tag = &act_three_bytes[50..];

		// 3. If v is an unrecognized handshake version, then the responder MUST abort the connection attempt.
		if version != 0 {
			// this should not crash the process, hence no panic
			return Err("unexpected version".to_string());
		}

		// 4. rs = decryptWithAD(temp_k2, 1, h, c)
		let mut remote_pubkey = [0; 33];
		chacha::decrypt(&temporary_key, 1, &hash, &tagged_encrypted_pubkey, &mut remote_pubkey)?;
		let initiator_pubkey = if let Ok(public_key) = PublicKey::from_slice(&remote_pubkey) {
			public_key
		} else {
			return Err("invalid remote public key".to_string());
		};

		// 5. h = SHA-256(h || c)
		let hash = concat_then_sha256!(hash, tagged_encrypted_pubkey);

		// 6. se = ECDH(e.priv, rs)
		let ecdh = ecdh(&responder_ephemeral_private_key, &initiator_pubkey);

		// 7. ck, temp_k3 = HKDF(ck, se)
		let (chaining_key, temporary_key) = hkdf5869rfc::derive(&chaining_key, &ecdh);

		// 8. p = decryptWithAD(temp_k3, 0, h, t)
		chacha::decrypt(&temporary_key, 0, &hash, &chacha_tag, &mut [0; 0])?;

		// 9. rk, sk = HKDF(ck, zero)
		let (receiving_key, sending_key) = hkdf5869rfc::derive(&chaining_key, &[0; 0]);

		// 10. rn = 0, sn = 0
		// - done by Conduit
		let mut conduit = Conduit::new(sending_key, receiving_key, chaining_key);

		// Any remaining data in the read buffer would be encrypted, so transfer ownership
		// to the Conduit for future use.
		conduit.read(remaining);

		Ok((
			None,
			HandshakeState::Complete(Some((conduit, initiator_pubkey)))
		))
	}
}

// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#handshake-state-initialization
fn handshake_state_initialization(responder_static_public_key: &PublicKey) -> (Sha256, Sha256) {
	let protocol_name = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";
	let prologue = b"lightning";

	// 1. h = SHA-256(protocolName)
	// 2. ck = h
	let chaining_key = concat_then_sha256!(protocol_name);

	// 3. h = SHA-256(h || prologue)
	let hash = concat_then_sha256!(chaining_key, prologue);

	// h = SHA-256(h || responderPublicKey)
	let hash = concat_then_sha256!(hash, responder_static_public_key.serialize());

	(hash, chaining_key)
}

// Due to the very high similarity of acts 1 and 2, this method is used to process both
// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-one (sender)
// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-two (sender)
fn calculate_act_message(local_private_ephemeral_key: &SecretKey, local_public_ephemeral_key: &PublicKey, remote_public_key: &PublicKey, chaining_key: ChainingKey, hash: Sha256, act_out: &mut [u8]) -> (Sha256, SymmetricKey, SymmetricKey) {
	// 1. e = generateKey() (passed in)
	// 2. h = SHA-256(h || e.pub.serializeCompressed())
	let serialized_local_public_key = local_public_ephemeral_key.serialize();
	let hash = concat_then_sha256!(hash, serialized_local_public_key);

	// 3. ACT1: es = ECDH(e.priv, rs)
	// 3. ACT2: es = ECDH(e.priv, re)
	let ecdh = ecdh(local_private_ephemeral_key, &remote_public_key);

	// 4. ACT1: ck, temp_k1 = HKDF(ck, es)
	// 4. ACT2: ck, temp_k2 = HKDF(ck, ee)
	let (chaining_key, temporary_key) = hkdf5869rfc::derive(&chaining_key, &ecdh);

	// 5. ACT1: c = encryptWithAD(temp_k1, 0, h, zero)
	// 5. ACT2: c = encryptWithAD(temp_k2, 0, h, zero)
	chacha::encrypt(&temporary_key, 0, &hash, &[0; 0], &mut act_out[34..]);

	// 6. h = SHA-256(h || c)
	let hash = concat_then_sha256!(hash, &act_out[34..]);

	// Send m = 0 || e.pub.serializeCompressed() || c
	act_out[1..34].copy_from_slice(&serialized_local_public_key);

	(hash, chaining_key, temporary_key)
}

// Due to the very high similarity of acts 1 and 2, this method is used to process both
// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-one (receiver)
// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#act-two (receiver)
fn process_act_message(act_bytes: &[u8], local_private_key: &SecretKey, chaining_key: ChainingKey, hash: Sha256) -> Result<(PublicKey, Sha256, SymmetricKey, SymmetricKey), String> {
	// 1. Read exactly 50 bytes from the network buffer
	// Partial act messages are handled by the callers. By the time it gets here, it
	// must be the correct size.
	assert_eq!(act_bytes.len(), ACT_ONE_LENGTH);
	assert_eq!(act_bytes.len(), ACT_TWO_LENGTH);

	// 2.Parse the read message (m) into v, re, and c
	let version = act_bytes[0];
	let ephemeral_public_key_bytes = &act_bytes[1..34];
	let chacha_tag = &act_bytes[34..];

	let ephemeral_public_key = if let Ok(public_key) = PublicKey::from_slice(&ephemeral_public_key_bytes) {
		public_key
	} else {
		return Err("invalid remote ephemeral public key".to_string());
	};

	// 3. If v is an unrecognized handshake version, then the responder MUST abort the connection attempt
	if version != 0 {
		// this should not crash the process, hence no panic
		return Err("unexpected version".to_string());
	}

	// 4. h = SHA-256(h || re.serializeCompressed())
	let hash = concat_then_sha256!(hash, ephemeral_public_key_bytes);

	// 5. Act1: es = ECDH(s.priv, re)
	// 5. Act2: ee = ECDH(e.priv, ee)
	let ecdh = ecdh(local_private_key, &ephemeral_public_key);

	// 6. Act1: ck, temp_k1 = HKDF(ck, es)
	// 6. Act2: ck, temp_k2 = HKDF(ck, ee)
	let (chaining_key, temporary_key) = hkdf5869rfc::derive(&chaining_key, &ecdh);

	// 7. Act1: p = decryptWithAD(temp_k1, 0, h, c)
	// 7. Act2: p = decryptWithAD(temp_k2, 0, h, c)
	chacha::decrypt(&temporary_key, 0, &hash, &chacha_tag, &mut [0; 0])?;

	// 8. h = SHA-256(h || c)
	let hash = concat_then_sha256!(hash, chacha_tag);

	Ok((ephemeral_public_key, hash, chaining_key, temporary_key))
}

fn private_key_to_public_key(private_key: &SecretKey) -> PublicKey {
	let curve = secp256k1::Secp256k1::new();
	let pk_object = PublicKey::from_secret_key(&curve, &private_key);
	pk_object
}

fn ecdh(private_key: &SecretKey, public_key: &PublicKey) -> SymmetricKey {
	let curve = secp256k1::Secp256k1::new();
	let mut pk_object = public_key.clone();
	pk_object.mul_assign(&curve, &private_key[..]).expect("invalid multiplication");

	let preimage = pk_object.serialize();
	concat_then_sha256!(preimage).into_inner()
}

#[cfg(test)]
// Reference RFC test vectors for hard-coded values
// https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md#appendix-a-transport-test-vectors
mod test {
	use super::*;
	use super::HandshakeState::*;

	use hex;

	use bitcoin::secp256k1;
	use bitcoin::secp256k1::{PublicKey, SecretKey};

	struct TestCtx {
		initiator: HandshakeState,
		initiator_public_key: PublicKey,
		responder: HandshakeState,
		responder_static_public_key: PublicKey,
		valid_act1: Vec<u8>,
		valid_act2: Vec<u8>,
		valid_act3: Vec<u8>,

	}

	impl TestCtx {
		fn new() -> Self {
			let curve = secp256k1::Secp256k1::new();
			let initiator_static_private_key = SecretKey::from_slice(&[0x_11_u8; 32]).unwrap();
			let initiator_public_key = PublicKey::from_secret_key(&curve, &initiator_static_private_key);
			let initiator_ephemeral_private_key = SecretKey::from_slice(&[0x_12_u8; 32]).unwrap();

			let responder_static_private_key = SecretKey::from_slice(&[0x_21_u8; 32]).unwrap();
			let responder_static_public_key = PublicKey::from_secret_key(&curve, &responder_static_private_key);
			let responder_ephemeral_private_key = SecretKey::from_slice(&[0x_22_u8; 32]).unwrap();

			let initiator = InitiatorStartingState::new(initiator_static_private_key, initiator_ephemeral_private_key, responder_static_public_key);
			let responder = ResponderAwaitingActOneState::new(responder_static_private_key, responder_ephemeral_private_key);

			TestCtx {
				initiator: InitiatorStarting(initiator),
				initiator_public_key,
				responder: ResponderAwaitingActOne(responder),
				responder_static_public_key,
				valid_act1: hex::decode("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap(),
				valid_act2: hex::decode("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap(),
				valid_act3: hex::decode("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap()
			}
		}
	}

	macro_rules! do_next_or_panic {
		($state:expr, $input:expr) => {
			if let (Some(output_act), next_state) = $state.next($input).unwrap() {
				(output_act, next_state)
			} else {
				panic!();
			}
		}
	}

	macro_rules! assert_matches {
		($e:expr, $state_match:pat) => {
			match $e {
				$state_match => (),
				_ => panic!()
			}
		}
	}

	// Initiator::Starting -> AwaitingActTwo
	#[test]
	fn starting_to_awaiting_act_two() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);

		assert_eq!(act1.as_ref(), test_ctx.valid_act1.as_slice());
		assert_matches!(awaiting_act_two_state, InitiatorAwaitingActTwo(_));
	}

	// Initiator::Starting -> AwaitingActTwo (extra bytes in argument)
	#[test]
	fn starting_to_awaiting_act_two_extra_bytes() {
		let test_ctx = TestCtx::new();

		assert_eq!(test_ctx.initiator.next(&[1]).err(), Some(String::from("first call for initiator must be empty")));
	}

	// Responder::AwaitingActOne -> AwaitingActThree
	// RFC test vector: transport-responder successful handshake
	#[test]
	fn awaiting_act_one_to_awaiting_act_three() {
		let test_ctx = TestCtx::new();
		let (act2, awaiting_act_three_state) = test_ctx.responder.next(&test_ctx.valid_act1).unwrap();

		assert_eq!(act2.unwrap().as_ref(), test_ctx.valid_act2.as_slice());
		assert_matches!(awaiting_act_three_state, ResponderAwaitingActThree(_));
	}

	// Responder::AwaitingActOne -> AwaitingActThree (bad peer)
	// Act2 requires data from the initiator. If we receive a payload for act1 that is larger than
	// expected it indicates a bad peer
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_input_extra_bytes() {
		let test_ctx = TestCtx::new();
		let mut act1 = test_ctx.valid_act1;
		act1.extend_from_slice(&[1]);

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("Act One too large")));
	}

	// Responder::AwaitingActOne -> AwaitingActThree (segmented calls)
	// RFC test vector: transport-responder act1 short read test
	// Divergence from RFC tests due to not reading directly from the socket (partial message OK)
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_segmented() {
		let test_ctx = TestCtx::new();
		let act1_partial1 = &test_ctx.valid_act1[..25];
		let act1_partial2 = &test_ctx.valid_act1[25..];

		let next_state = test_ctx.responder.next(&act1_partial1).unwrap();
		assert_matches!(next_state, (None, ResponderAwaitingActOne(_)));
		assert_matches!(next_state.1.next(&act1_partial2).unwrap(), (Some(_), ResponderAwaitingActThree(_)));
	}

	// Responder::AwaitingActOne -> Error (bad version byte)
	// RFC test vector: transport-responder act1 bad version test
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_input_bad_version() {
		let test_ctx = TestCtx::new();
		let act1 = hex::decode("01036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap();

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("unexpected version")));
	}

	// Responder::AwaitingActOne -> Error (invalid remote ephemeral key)
	// RFC test vector: transport-responder act1 bad key serialization test
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_invalid_remote_ephemeral_key() {
		let test_ctx = TestCtx::new();
		let act1 = hex::decode("00046360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a").unwrap();

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("invalid remote ephemeral public key")));
	}

	// Responder::AwaitingActOne -> Error (invalid hmac)
	// RFC test vector: transport-responder act1 bad MAC test
	#[test]
	fn awaiting_act_one_to_awaiting_act_three_invalid_hmac() {
		let test_ctx = TestCtx::new();
		let act1 = hex::decode("00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6b").unwrap();

		assert_eq!(test_ctx.responder.next(&act1).err(), Some(String::from("invalid hmac")));
	}

	// Initiator::AwaitingActTwo -> Complete (bad peer)
	// Initiator data is required to generate post-authentication messages. This means any extra
	// data indicates a bad peer.
	#[test]
	fn awaiting_act_two_to_complete_extra_bytes() {
		let test_ctx = TestCtx::new();
		let (_act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let mut act2 = test_ctx.valid_act2;
		act2.extend_from_slice(&[1]);

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("Act Two too large")));
	}

	// Initiator::AwaitingActTwo -> Complete
	// RFC test vector: transport-initiator successful handshake
	#[test]
	fn awaiting_act_two_to_complete() {
		let test_ctx = TestCtx::new();
		let (_act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act3, complete_state) = do_next_or_panic!(awaiting_act_two_state, &test_ctx.valid_act2);

		let (conduit, remote_pubkey) = if let Complete(Some((conduit, remote_pubkey))) = complete_state {
			(conduit, remote_pubkey)
		} else {
			panic!();
		};

		assert_eq!(act3.as_ref(), test_ctx.valid_act3.as_slice());
		assert_eq!(remote_pubkey, test_ctx.responder_static_public_key);
		assert_eq!(0, conduit.decryptor.read_buffer_length());
	}

	// Initiator::AwaitingActTwo -> Complete (segmented calls)
	// RFC test vector: transport-initiator act2 short read test
	// Divergence from RFC tests due to not reading directly from the socket (partial message OK)
	#[test]
	fn awaiting_act_two_to_complete_segmented() {
		let test_ctx = TestCtx::new();
		let (_act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);

		let act2_partial1 = &test_ctx.valid_act2[..25];
		let act2_partial2 = &test_ctx.valid_act2[25..];

		let next_state = awaiting_act_two_state.next(&act2_partial1).unwrap();
		assert_matches!(next_state, (None, InitiatorAwaitingActTwo(_)));
		assert_matches!(next_state.1.next(&act2_partial2).unwrap(), (Some(_), Complete(_)));
	}

	// Initiator::AwaitingActTwo -> Error (bad version byte)
	// RFC test vector: transport-initiator act2 bad version test
	#[test]
	fn awaiting_act_two_bad_version_byte() {
		let test_ctx = TestCtx::new();
		let (_act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let act2 = hex::decode("0102466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap();

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("unexpected version")));
	}

	// Initiator::AwaitingActTwo -> Error (invalid ephemeral public key)
	// RFC test vector: transport-initiator act2 bad key serialization test
	#[test]
	fn awaiting_act_two_invalid_ephemeral_public_key() {
		let test_ctx = TestCtx::new();
		let (_act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let act2 = hex::decode("0004466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae").unwrap();

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("invalid remote ephemeral public key")));
	}

	// Initiator::AwaitingActTwo -> Error (invalid hmac)
	// RFC test vector: transport-initiator act2 bad MAC test
	#[test]
	fn awaiting_act_two_invalid_hmac() {
		let test_ctx = TestCtx::new();
		let (_act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let act2 = hex::decode("0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730af").unwrap();

		assert_eq!(awaiting_act_two_state.next(&act2).err(), Some(String::from("invalid hmac")));
	}

	// Responder::AwaitingActThree -> Complete
	// RFC test vector: transport-responder successful handshake
	#[test]
	fn awaiting_act_three_to_complete() {
		let test_ctx = TestCtx::new();
		let (_act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &test_ctx.valid_act1);

		let (conduit, remote_pubkey) = if let (None, Complete(Some((conduit, remote_pubkey)))) = awaiting_act_three_state.next(&test_ctx.valid_act3).unwrap() {
			(conduit, remote_pubkey)
		} else {
			panic!();
		};

		assert_eq!(remote_pubkey, test_ctx.initiator_public_key);
		assert_eq!(0, conduit.decryptor.read_buffer_length());
	}

	// Responder::AwaitingActThree -> None (with extra bytes)
	// Ensures that any remaining data in the read buffer is transferred to the conduit once
	// the handshake is complete
	#[test]
	fn awaiting_act_three_excess_bytes_after_complete_are_in_conduit() {
		let test_ctx = TestCtx::new();
		let (_act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &test_ctx.valid_act1);
		let mut act3 = test_ctx.valid_act3;
		act3.extend_from_slice(&[2; 100]);

		let (conduit, remote_pubkey) = if let (None, Complete(Some((conduit, remote_pubkey)))) = awaiting_act_three_state.next(&act3).unwrap() {
			(conduit, remote_pubkey)
		} else {
			panic!();
		};

		assert_eq!(remote_pubkey, test_ctx.initiator_public_key);
		assert_eq!(100, conduit.decryptor.read_buffer_length());
	}

	// Responder::AwaitingActThree -> Error (bad version bytes)
	// RFC test vector: transport-responder act3 bad version test
	#[test]
	fn awaiting_act_three_bad_version_bytes() {
		let test_ctx = TestCtx::new();
		let (_act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &test_ctx.valid_act1);
		let act3 = hex::decode("01b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap();

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("unexpected version")));
	}

	// Responder::AwaitingActThree -> Complete (segmented calls)
	// RFC test vector: transport-responder act3 short read test
	// Divergence from RFC tests due to not reading directly from the socket (partial message OK)
	#[test]
	fn awaiting_act_three_to_complete_segmented() {
		let test_ctx = TestCtx::new();
		let (_act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &test_ctx.valid_act1);

		let act3_partial1 = &test_ctx.valid_act3[..35];
		let act3_partial2 = &test_ctx.valid_act3[35..];

		let next_state = awaiting_act_three_state.next(&act3_partial1).unwrap();
		assert_matches!(next_state, (None, ResponderAwaitingActThree(_)));
		assert_matches!(next_state.1.next(&act3_partial2), Ok((None, Complete(_))));
	}

	// Responder::AwaitingActThree -> Error (invalid hmac)
	// RFC test vector: transport-responder act3 bad MAC for ciphertext test
	#[test]
	fn awaiting_act_three_invalid_hmac() {
		let test_ctx = TestCtx::new();
		let (_act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &test_ctx.valid_act1);
		let act3 = hex::decode("00c9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba").unwrap();

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("invalid hmac")));
	}

	// Responder::AwaitingActThree -> Error (invalid remote_static_key)
	// RFC test vector: transport-responder act3 bad rs test
	#[test]
	fn awaiting_act_three_invalid_rs() {
		let test_ctx = TestCtx::new();
		let (_act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &test_ctx.valid_act1);
		let act3 = hex::decode("00bfe3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa2235536ad09a8ee351870c2bb7f78b754a26c6cef79a98d25139c856d7efd252c2ae73c").unwrap();

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("invalid remote public key")));
	}

	// Responder::AwaitingActThree -> Error (invalid tag hmac)
	// RFC test vector: transport-responder act3 bad MAC test
	#[test]
	fn awaiting_act_three_invalid_tag_hmac() {
		let test_ctx = TestCtx::new();
		let (_act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &test_ctx.valid_act1);
		let act3 = hex::decode("00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139bb").unwrap();

		assert_eq!(awaiting_act_three_state.next(&act3).err(), Some(String::from("invalid hmac")));
	}

	// Initiator::Complete -> Error
	#[test]
	#[should_panic(expected = "no acts left to process")]
	fn initiator_complete_next_fail() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (_act3, complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		complete_state.next(&[]).unwrap();
	}

	// Initiator::Complete -> Error
	#[test]
	#[should_panic(expected = "no acts left to process")]
	fn responder_complete_next_fail() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		let complete_state = if let (None, complete_state) = awaiting_act_three_state.next(&act3).unwrap() {
			complete_state
		} else {
			panic!();
		};

		complete_state.next(&[]).unwrap();
	}

	// Test the Act byte generation against known good hard-coded values in case the implementation
	// changes in a symmetric way that makes the other tests useless
	#[test]
	fn test_acts_against_reference_bytes() {
		let test_ctx = TestCtx::new();
		let (act1, awaiting_act_two_state) = do_next_or_panic!(test_ctx.initiator, &[]);
		let (act2, _awaiting_act_three_state) = do_next_or_panic!(test_ctx.responder, &act1);
		let (act3, _complete_state) = do_next_or_panic!(awaiting_act_two_state, &act2);

		assert_eq!(hex::encode(&act1),
				   "00036360e856310ce5d294e8be33fc807077dc56ac80d95d9cd4ddbd21325eff73f70df6086551151f58b8afe6c195782c6a");
		assert_eq!(hex::encode(&act2),
				   "0002466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f276e2470b93aac583c9ef6eafca3f730ae");
		assert_eq!(hex::encode(&act3),
				   "00b9e3a702e93e3a9948c2ed6e5fd7590a6e1c3a0344cfc9d5b57357049aa22355361aa02e55a8fc28fef5bd6d71ad0c38228dc68b1c466263b47fdf31e560e139ba");
	}
}

