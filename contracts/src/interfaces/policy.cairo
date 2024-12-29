// SPDX-License-Identifier: MIT
use starknet::ContractAddress;

#[derive(Copy, Drop, Serde, starknet::Store)]
pub struct Policy {
    pub max_amount: u256,
    pub current_amount: u256,
}

#[starknet::interface]
pub trait IPolicy<TContractState> {
    fn set_policy(
        ref self: TContractState,
        public_key: felt252,
        contract: ContractAddress,
        policy: Policy
    );

    fn check_policy(
        ref self: TContractState,
        public_key: felt252,
        contract: ContractAddress,
        amount: u256,
    ) -> bool;

    fn get_policy(
        self: @TContractState,
        public_key: felt252,
        contract: ContractAddress
    ) -> Option<Policy>;
}