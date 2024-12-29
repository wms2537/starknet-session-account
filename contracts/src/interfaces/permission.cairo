// SPDX-License-Identifier: MIT
use starknet::ContractAddress;
use starknet::storage::Map;
#[derive(Copy, Drop, Serde, PartialEq, starknet::Store)]
pub enum AccessMode {
    Whitelist,
    #[default]
    Blacklist
}

#[starknet::storage_node]
pub struct Permission{
    pub mode: AccessMode,
    pub selectors: Map<u32, felt252>,
    pub selectors_map: Map<felt252, bool>,
    pub selector_count: u32,
}

#[derive(Drop, Serde)]
pub struct PermissionResult {
    pub mode: AccessMode,
    pub contract: ContractAddress,
    pub selectors: Array<felt252>,
}

#[starknet::interface]
pub trait IPermission<TContractState> {
    fn set_permission(
        ref self: TContractState,
        public_key: felt252,
        contract: ContractAddress,
        mode: AccessMode,
        selectors: Array<felt252>
    );

    fn check_permission(
        self: @TContractState,
        public_key: felt252,
        contract: ContractAddress,
        selector: felt252
    ) -> bool;

    fn get_permission_details(
        self: @TContractState,
        public_key: felt252,
        contract: ContractAddress
    ) -> PermissionResult;
}
