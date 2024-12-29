// SPDX-License-Identifier: MIT
use contracts::interfaces::permission::{Permission, PermissionResult};
use contracts::interfaces::policy::{Policy, PolicyResult};
use starknet::storage::{Map, Vec};
use starknet::ContractAddress;

#[starknet::storage_node]
pub struct Session {
    pub data: SessionData,
    pub permissions_map: Map<ContractAddress, Permission>,
    pub permissions_vec: Vec<ContractAddress>,
    pub policies_map: Map<ContractAddress, Policy>,
    pub policies_vec: Vec<ContractAddress>,
}

#[derive(Drop, Serde, starknet::Store)]
pub struct SessionData {
    pub public_key: felt252,
    pub expires_at: u64,
    pub metadata: ByteArray,
    pub is_revoked: bool,
}

#[derive(Drop, Serde)]
pub struct SessionResult {
    pub data: SessionData,
    pub permissions: Array<PermissionResult>,
    pub policies: Array<PolicyResult>,
}

#[starknet::interface]
pub trait ISession<TContractState> {
    fn register_session(
        ref self: TContractState,
        session: SessionData,
        guid_or_address: felt252
    );
    
    fn revoke_session(
        ref self: TContractState,
        public_key: felt252
    );

    fn is_session(
        self: @TContractState,
        signature: Span<felt252>
    ) -> bool;
    
    fn is_session_revoked(
        self: @TContractState,
        public_key: felt252
    ) -> bool;
    
    fn is_session_registered(
        self: @TContractState,
        public_key: felt252,
        guid_or_address: felt252
    ) -> bool;

    fn get_all_sessions(
        self: @TContractState
    ) -> Array<felt252>;
    
    fn get_session(
        self: @TContractState,
        public_key: felt252
    ) -> Option<SessionResult>;
}
