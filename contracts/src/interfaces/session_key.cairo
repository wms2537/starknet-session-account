// SPDX-License-Identifier: MIT


#[derive(Drop, Serde, starknet::Store)]
pub struct Session {
    pub public_key: felt252,
    pub expires_at: u64,
    pub metadata: ByteArray,
    pub is_revoked: bool
}

#[starknet::interface]
pub trait ISession<TContractState> {
    fn register_session(
        ref self: TContractState,
        session: Session,
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
    ) -> Option<Session>;
}
