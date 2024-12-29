use starknet::{ContractAddress, contract_address_const, VALIDATED};
use contracts::interfaces::session_key::{Session, ISession};
use contracts::interfaces::permission::{AccessMode, IPermission};
use contracts::interfaces::policy::{Policy, IPolicy};
use contracts::nex_account::{NexAccount, NexAccount::InternalTrait};
use starknet::account::Call;
use contracts::tests::test_utils::setup_contracts;

use core::traits::Into;
use core::array::ArrayTrait;
use core::result::ResultTrait;
use core::poseidon;
use contracts::tests::test_utils::{sign_message, verify_signature, SESSION_PUBLIC_KEY, SESSION_PRIVATE_KEY};

// Constants for testing
const OWNER: felt252 = 0x111;
const SESSION_KEY: felt252 = 0x456;
const EXPIRES_AT: u64 = 0x1111111111111111;

fn setup() -> (ContractAddress, NexAccount::ContractState) {
    let (account_address, _) = setup_contracts();
    let state = NexAccount::contract_state_for_testing();
    (account_address, state)
}

fn create_test_session() -> Session {
    Session {
        public_key: SESSION_KEY,
        expires_at: EXPIRES_AT,
        metadata: "test_session"
    }
}

fn compute_session_hash(session: @Session) -> felt252 {
    // Create array for hash inputs
    let mut data = array![
        *session.public_key,
        (*session.expires_at).into(),
        session.metadata.len().into()
    ];
    
    // Add metadata bytes
    let mut i = 0;
    loop {
        if i >= session.metadata.len() {
            break;
        }
        data.append(session.metadata.at(i).unwrap().into());
        i += 1;
    };
    
    poseidon::poseidon_hash_span(data.span())
}

#[test]
fn test_register_session() {
    let (account_address, mut state) = setup();
    let session = create_test_session();
    let session_hash = compute_session_hash(@session);

    state.session_key.register_session(session, OWNER);

    assert(!state.session_key.is_session_revoked(session_hash), 'not revoked');
    assert(state.session_key.is_session_registered(session_hash, OWNER), 'not registered');
}

#[test]
fn test_revoke_session() {
    let (account_address, mut state) = setup();
    let session = create_test_session();
    let session_hash = compute_session_hash(@session);

    state.session_key.register_session(session, OWNER);
    state.session_key.revoke_session(session_hash);

    assert(state.session_key.is_session_revoked(session_hash), 'not revoked');
    assert(!state.session_key.is_session_registered(session_hash, OWNER), 'still registered');
}

#[test]
fn test_set_permission() {
    let (account_address, mut state) = setup();
    let session = create_test_session();
    let session_hash = compute_session_hash(@session);

    state.session_key.register_session(session, OWNER);
    
    let target_contract = contract_address_const::<0x789>();
    let selectors = array![selector!("transfer"), selector!("approve")];
    
    state.session_key.set_permission(
        session_hash,
        target_contract,
        AccessMode::Whitelist,
        selectors
    );

    assert(
        state.session_key.check_permission(session_hash, target_contract, selector!("transfer")),
        'transfer denied'
    );
    assert(
        state.session_key.check_permission(session_hash, target_contract, selector!("approve")),
        'approve denied'
    );
    assert(
        !state.session_key.check_permission(session_hash, target_contract, selector!("mint")),
        'mint allowed'
    );
}

#[test]
fn test_set_policy() {
    let (account_address, mut state) = setup();
    let session = create_test_session();
    let session_hash = compute_session_hash(@session);

    state.session_key.register_session(session, OWNER);
    
    let target_contract = contract_address_const::<0x789>();
    let policy = Policy {
        max_amount: 1000,
        current_amount: 0,
        window_length: 86400,
        last_reset: 0
    };
    
    state.session_key.set_policy(session_hash, target_contract, policy);

    assert(
        state.session_key.check_policy(session_hash, target_contract, 500),
        'valid amount denied'
    );
    assert(
        !state.session_key.check_policy(session_hash, target_contract, 1500),
        'invalid amount allowed'
    );
}

#[test]
#[should_panic(expected: ('Session already revoked',))]
fn test_revoke_session_twice() {
    let (account_address, mut state) = setup();
    let session = create_test_session();
    let session_hash = compute_session_hash(@session);

    // Register session
    state.session_key.register_session(session, OWNER);
    
    state.session_key.revoke_session(session_hash);
    state.session_key.revoke_session(session_hash); // Should panic
}

#[test]
fn test_session_validation() {
    let (account_address, mut state) = setup();
    let session = create_test_session();
    let session_hash = compute_session_hash(@session);

    state.session_key.register_session(session, OWNER);

    // Set up test call
    let target = contract_address_const::<0x789>();
    let transfer_selector = selector!("transfer");
    let mut calldata = array![1000]; // Amount to transfer

    // Set permission
    state.session_key.set_permission(
        session_hash,
        target,
        AccessMode::Whitelist,
        array![transfer_selector]
    );

    // Set policy
    let policy = Policy {
        max_amount: 2000,
        current_amount: 0,
        window_length: 86400,
        last_reset: 0
    };
    state.session_key.set_policy(session_hash, target, policy);

    // Create test call
    let call = Call {
        to: target,
        selector: transfer_selector,
        calldata: calldata.span()
    };

    // Test validation
    let mut calls = array![call];
    let mut signature = array![session_hash, 0x1234, 0x5678]; // Mock signature
    let result = state.validate_session_transaction(calls, signature);
    assert(result == VALIDATED, 'Validation should succeed');
}

#[test]
#[should_panic(expected: ('Invalid selector',))]
fn test_session_validation_invalid_selector() {
    let (account_address, mut state) = setup();
    let session = create_test_session();
    let session_hash = compute_session_hash(@session);

    state.session_key.register_session(session, OWNER);

    // Set up test call with unauthorized selector
    let target = contract_address_const::<0x789>();
    let transfer_selector = selector!("transfer");
    let unauthorized_selector = selector!("mint");

    // Set up whitelist permission for transfer only
    state.session_key.set_permission(
        session_hash,
        target,
        AccessMode::Whitelist,
        array![transfer_selector]
    );

    // Try to call with unauthorized selector
    let call = Call {
        to: target,
        selector: unauthorized_selector,
        calldata: array![].span()
    };

    // Should fail validation because mint is not in whitelist
    let mut calls = array![call];
    let mut signature = array![session_hash, 0x1234, 0x5678];
    state.validate_session_transaction(calls, signature);
}

#[test]
#[should_panic(expected: ('Policy check failed',))]
fn test_session_validation_policy_exceeded() {
    let (account_address, mut state) = setup();
    let session = create_test_session();
    let session_hash = compute_session_hash(@session);

    state.session_key.register_session(session, OWNER);

    // Set up test call
    let target = contract_address_const::<0x789>();
    let transfer_selector = selector!("transfer");
    
    // Set permission
    state.session_key.set_permission(
        session_hash,
        target,
        AccessMode::Whitelist,
        array![transfer_selector]
    );

    // Set policy with low limit
    let policy = Policy {
        max_amount: 500,
        current_amount: 0,
        window_length: 86400,
        last_reset: 0
    };
    state.session_key.set_policy(session_hash, target, policy);

    // Create call exceeding policy limit
    let call = Call {
        to: target,
        selector: transfer_selector,
        calldata: array![1000].span() // Amount exceeds policy
    };

    // Should fail validation
    let mut calls = array![call];
    let mut signature = array![session_hash, 0x1234, 0x5678];
    state.validate_session_transaction(calls, signature);
}

#[test]
#[should_panic(expected: ('Session already revoked',))]
fn test_session_validation_revoked() {
    let (account_address, mut state) = setup();
    let session = create_test_session();
    let session_hash = compute_session_hash(@session);

    state.session_key.register_session(session, OWNER);

    // Revoke session
    state.session_key.revoke_session(session_hash);

    // Try to validate with revoked session
    let call = Call {
        to: contract_address_const::<0x789>(),
        selector: selector!("transfer"),
        calldata: array![].span()
    };

    let mut calls = array![call];
    let mut signature = array![session_hash, 0x1234, 0x5678];
    state.validate_session_transaction(calls, signature);
}

#[test]
fn test_session_with_real_signatures() {
    let (account_address, mut state) = setup();
    
    // Create session with real session public key
    let session = Session {
        public_key: SESSION_PUBLIC_KEY,
        expires_at: EXPIRES_AT,
        metadata: "test_session"
    };
    let session_hash = compute_session_hash(@session);

    // Register session
    state.session_key.register_session(session, OWNER);

    // Set up test call
    let target = contract_address_const::<0x789>();
    let transfer_selector = selector!("transfer");
    let amount = 1000;
    let calldata = array![amount];

    // Set permission
    state.session_key.set_permission(
        session_hash,
        target,
        AccessMode::Whitelist,
        array![transfer_selector]
    );

    // Set policy
    let policy = Policy {
        max_amount: 2000,
        current_amount: 0,
        window_length: 86400,
        last_reset: 0
    };
    state.session_key.set_policy(session_hash, target, policy);

    // Create transaction hash
    let tx_hash = compute_transaction_hash(
        target,
        transfer_selector,
        calldata.span()
    );

    // Sign with session key
    let (sig_r, sig_s) = sign_message(tx_hash, SESSION_PRIVATE_KEY);

    // Create test call
    let call = Call {
        to: target,
        selector: transfer_selector,
        calldata: calldata.span()
    };

    // Create signature array with session info
    let mut signature = array![
        session_hash,
        sig_r,
        sig_s
    ];

    // Validate transaction
    let mut calls = array![call];
    let result = state.validate_session_transaction(calls, signature);
    assert(result == VALIDATED, 'Session validation failed');

    // Verify signature directly
    assert(
        verify_signature(tx_hash, SESSION_PUBLIC_KEY, (sig_r, sig_s)),
        'Invalid signature'
    );
}

fn compute_transaction_hash(
    to: ContractAddress,
    selector: felt252,
    calldata: Span<felt252>
) -> felt252 {
    let mut data = array![
        to.into(),
        selector
    ];
    
    // Add calldata
    let mut i = 0;
    loop {
        if i >= calldata.len() {
            break;
        }
        data.append(*calldata[i]);
        i += 1;
    };
    
    poseidon::poseidon_hash_span(data.span())
}
