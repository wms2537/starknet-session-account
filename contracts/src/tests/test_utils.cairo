use starknet::ContractAddress;
use core::traits::TryInto;
use core::ecdsa::check_ecdsa_signature;
use core::pedersen;

// Constants for testing
const ACCOUNT: felt252 = 0x111;
const TARGET: felt252 = 0x222;

// Test keys (these are example keys, you can replace with your own)
const PRIVATE_KEY: felt252 = 0x00000000000000000000000000000000b467066159b295a7667b633d6bdaabac; // Example private key
pub const PUBLIC_KEY: felt252 = 0x00c6c2f7833f681c8fe001533e99571f6ff8dec59268792a429a14b5b252f1ad;  // Corresponding public key
pub const SESSION_PRIVATE_KEY: felt252 = 0x0000000000000000000000000000000057b2f8431c772e647712ae93cc616638; // Session key private
pub const SESSION_PUBLIC_KEY: felt252 = 0x0374f7fcb50bc2d6b8b7a267f919232e3ac68354ce3eafe88d3df323fc1deb23;  // Session key public

pub fn setup_contracts() -> (ContractAddress, ContractAddress) {
    // Convert constants to contract addresses
    let account_address: ContractAddress = ACCOUNT.try_into().unwrap();
    let target_address: ContractAddress = TARGET.try_into().unwrap();

    (account_address, target_address)
}

// Helper to sign messages with private key
pub fn sign_message(msg_hash: felt252, private_key: felt252) -> (felt252, felt252) {
    // In a real implementation, this would use actual ECDSA signing
    // For testing, we'll simulate the signature
    let r = pedersen::pedersen(private_key, msg_hash);
    let s = pedersen::pedersen(r, private_key);
    (r, s)
}

// Helper to verify signatures
pub fn verify_signature(
    message_hash: felt252,
    public_key: felt252,
    signature: (felt252, felt252)
) -> bool {
    let (r, s) = signature;
    check_ecdsa_signature(
        message_hash,
        public_key,
        r,
        s
    )
}
