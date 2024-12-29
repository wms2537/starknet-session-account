/**
 * This file is autogenerated by Scaffold-Stark.
 * You should not edit it manually or your changes might be overwritten.
 */

const deployedContracts = {
  devnet: {
    NexAccount: {
      address:
        "0x49481bfcbe1e390889c67d793e851ee33166bc0feed54db684f6501539bed57",
      abi: [
        {
          type: "impl",
          name: "UpgradeableImpl",
          interface_name: "openzeppelin_upgrades::interface::IUpgradeable",
        },
        {
          type: "interface",
          name: "openzeppelin_upgrades::interface::IUpgradeable",
          items: [
            {
              type: "function",
              name: "upgrade",
              inputs: [
                {
                  name: "new_class_hash",
                  type: "core::starknet::class_hash::ClassHash",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
          ],
        },
        {
          type: "struct",
          name: "core::array::Span::<core::felt252>",
          members: [
            {
              name: "snapshot",
              type: "@core::array::Array::<core::felt252>",
            },
          ],
        },
        {
          type: "struct",
          name: "core::starknet::account::Call",
          members: [
            {
              name: "to",
              type: "core::starknet::contract_address::ContractAddress",
            },
            {
              name: "selector",
              type: "core::felt252",
            },
            {
              name: "calldata",
              type: "core::array::Span::<core::felt252>",
            },
          ],
        },
        {
          type: "struct",
          name: "core::array::Span::<core::starknet::account::Call>",
          members: [
            {
              name: "snapshot",
              type: "@core::array::Array::<core::starknet::account::Call>",
            },
          ],
        },
        {
          type: "function",
          name: "validate_session_transaction",
          inputs: [
            {
              name: "calls",
              type: "core::array::Span::<core::starknet::account::Call>",
            },
            {
              name: "signature",
              type: "core::array::Span::<core::felt252>",
            },
            {
              name: "transaction_hash",
              type: "core::felt252",
            },
          ],
          outputs: [
            {
              type: "core::felt252",
            },
          ],
          state_mutability: "external",
        },
        {
          type: "impl",
          name: "SessionValidateImpl",
          interface_name: "core::starknet::account::AccountContract",
        },
        {
          type: "interface",
          name: "core::starknet::account::AccountContract",
          items: [
            {
              type: "function",
              name: "__validate_declare__",
              inputs: [
                {
                  name: "class_hash",
                  type: "core::felt252",
                },
              ],
              outputs: [
                {
                  type: "core::felt252",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "__validate__",
              inputs: [
                {
                  name: "calls",
                  type: "core::array::Array::<core::starknet::account::Call>",
                },
              ],
              outputs: [
                {
                  type: "core::felt252",
                },
              ],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "__execute__",
              inputs: [
                {
                  name: "calls",
                  type: "core::array::Array::<core::starknet::account::Call>",
                },
              ],
              outputs: [
                {
                  type: "core::array::Array::<core::array::Span::<core::felt252>>",
                },
              ],
              state_mutability: "external",
            },
          ],
        },
        {
          type: "impl",
          name: "SessionImpl",
          interface_name: "contracts::interfaces::session_key::ISession",
        },
        {
          type: "struct",
          name: "core::byte_array::ByteArray",
          members: [
            {
              name: "data",
              type: "core::array::Array::<core::bytes_31::bytes31>",
            },
            {
              name: "pending_word",
              type: "core::felt252",
            },
            {
              name: "pending_word_len",
              type: "core::integer::u32",
            },
          ],
        },
        {
          type: "struct",
          name: "contracts::interfaces::session_key::Session",
          members: [
            {
              name: "public_key",
              type: "core::felt252",
            },
            {
              name: "expires_at",
              type: "core::integer::u64",
            },
            {
              name: "metadata",
              type: "core::byte_array::ByteArray",
            },
          ],
        },
        {
          type: "enum",
          name: "core::bool",
          variants: [
            {
              name: "False",
              type: "()",
            },
            {
              name: "True",
              type: "()",
            },
          ],
        },
        {
          type: "enum",
          name: "core::option::Option::<contracts::interfaces::session_key::Session>",
          variants: [
            {
              name: "Some",
              type: "contracts::interfaces::session_key::Session",
            },
            {
              name: "None",
              type: "()",
            },
          ],
        },
        {
          type: "interface",
          name: "contracts::interfaces::session_key::ISession",
          items: [
            {
              type: "function",
              name: "register_session",
              inputs: [
                {
                  name: "session",
                  type: "contracts::interfaces::session_key::Session",
                },
                {
                  name: "guid_or_address",
                  type: "core::felt252",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "revoke_session",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "is_session",
              inputs: [
                {
                  name: "signature",
                  type: "core::array::Span::<core::felt252>",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "is_session_revoked",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "is_session_registered",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
                {
                  name: "guid_or_address",
                  type: "core::felt252",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "get_all_sessions",
              inputs: [],
              outputs: [
                {
                  type: "core::array::Array::<core::felt252>",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "get_session",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
              ],
              outputs: [
                {
                  type: "core::option::Option::<contracts::interfaces::session_key::Session>",
                },
              ],
              state_mutability: "view",
            },
          ],
        },
        {
          type: "impl",
          name: "PermissionImpl",
          interface_name: "contracts::interfaces::permission::IPermission",
        },
        {
          type: "enum",
          name: "contracts::interfaces::permission::AccessMode",
          variants: [
            {
              name: "Whitelist",
              type: "()",
            },
            {
              name: "Blacklist",
              type: "()",
            },
          ],
        },
        {
          type: "interface",
          name: "contracts::interfaces::permission::IPermission",
          items: [
            {
              type: "function",
              name: "set_permission",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
                {
                  name: "contract",
                  type: "core::starknet::contract_address::ContractAddress",
                },
                {
                  name: "mode",
                  type: "contracts::interfaces::permission::AccessMode",
                },
                {
                  name: "selectors",
                  type: "core::array::Array::<core::felt252>",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "check_permission",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
                {
                  name: "contract",
                  type: "core::starknet::contract_address::ContractAddress",
                },
                {
                  name: "selector",
                  type: "core::felt252",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "view",
            },
            {
              type: "function",
              name: "get_permission_details",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
                {
                  name: "contract",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "(contracts::interfaces::permission::AccessMode, core::array::Array::<core::felt252>)",
                },
              ],
              state_mutability: "view",
            },
          ],
        },
        {
          type: "impl",
          name: "PolicyImpl",
          interface_name: "contracts::interfaces::policy::IPolicy",
        },
        {
          type: "struct",
          name: "core::integer::u256",
          members: [
            {
              name: "low",
              type: "core::integer::u128",
            },
            {
              name: "high",
              type: "core::integer::u128",
            },
          ],
        },
        {
          type: "struct",
          name: "contracts::interfaces::policy::Policy",
          members: [
            {
              name: "max_amount",
              type: "core::integer::u256",
            },
            {
              name: "current_amount",
              type: "core::integer::u256",
            },
          ],
        },
        {
          type: "enum",
          name: "core::option::Option::<contracts::interfaces::policy::Policy>",
          variants: [
            {
              name: "Some",
              type: "contracts::interfaces::policy::Policy",
            },
            {
              name: "None",
              type: "()",
            },
          ],
        },
        {
          type: "interface",
          name: "contracts::interfaces::policy::IPolicy",
          items: [
            {
              type: "function",
              name: "set_policy",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
                {
                  name: "contract",
                  type: "core::starknet::contract_address::ContractAddress",
                },
                {
                  name: "policy",
                  type: "contracts::interfaces::policy::Policy",
                },
              ],
              outputs: [],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "check_policy",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
                {
                  name: "contract",
                  type: "core::starknet::contract_address::ContractAddress",
                },
                {
                  name: "amount",
                  type: "core::integer::u256",
                },
              ],
              outputs: [
                {
                  type: "core::bool",
                },
              ],
              state_mutability: "external",
            },
            {
              type: "function",
              name: "get_policy",
              inputs: [
                {
                  name: "public_key",
                  type: "core::felt252",
                },
                {
                  name: "contract",
                  type: "core::starknet::contract_address::ContractAddress",
                },
              ],
              outputs: [
                {
                  type: "core::option::Option::<contracts::interfaces::policy::Policy>",
                },
              ],
              state_mutability: "view",
            },
          ],
        },
        {
          type: "constructor",
          name: "constructor",
          inputs: [
            {
              name: "public_key",
              type: "core::felt252",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_account::account::AccountComponent::OwnerAdded",
          kind: "struct",
          members: [
            {
              name: "new_owner_guid",
              type: "core::felt252",
              kind: "key",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_account::account::AccountComponent::OwnerRemoved",
          kind: "struct",
          members: [
            {
              name: "removed_owner_guid",
              type: "core::felt252",
              kind: "key",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_account::account::AccountComponent::Event",
          kind: "enum",
          variants: [
            {
              name: "OwnerAdded",
              type: "openzeppelin_account::account::AccountComponent::OwnerAdded",
              kind: "nested",
            },
            {
              name: "OwnerRemoved",
              type: "openzeppelin_account::account::AccountComponent::OwnerRemoved",
              kind: "nested",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_introspection::src5::SRC5Component::Event",
          kind: "enum",
          variants: [],
        },
        {
          type: "event",
          name: "openzeppelin_upgrades::upgradeable::UpgradeableComponent::Upgraded",
          kind: "struct",
          members: [
            {
              name: "class_hash",
              type: "core::starknet::class_hash::ClassHash",
              kind: "data",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_upgrades::upgradeable::UpgradeableComponent::Event",
          kind: "enum",
          variants: [
            {
              name: "Upgraded",
              type: "openzeppelin_upgrades::upgradeable::UpgradeableComponent::Upgraded",
              kind: "nested",
            },
          ],
        },
        {
          type: "event",
          name: "openzeppelin_security::reentrancyguard::ReentrancyGuardComponent::Event",
          kind: "enum",
          variants: [],
        },
        {
          type: "event",
          name: "contracts::components::session_key::session_key_component::SessionRegistered",
          kind: "struct",
          members: [
            {
              name: "public_key",
              type: "core::felt252",
              kind: "data",
            },
            {
              name: "guid_or_address",
              type: "core::felt252",
              kind: "data",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::components::session_key::session_key_component::SessionRevoked",
          kind: "struct",
          members: [
            {
              name: "public_key",
              type: "core::felt252",
              kind: "data",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::components::session_key::session_key_component::PermissionUpdated",
          kind: "struct",
          members: [
            {
              name: "public_key",
              type: "core::felt252",
              kind: "data",
            },
            {
              name: "contract",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "data",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::components::session_key::session_key_component::PolicyUpdated",
          kind: "struct",
          members: [
            {
              name: "public_key",
              type: "core::felt252",
              kind: "data",
            },
            {
              name: "contract",
              type: "core::starknet::contract_address::ContractAddress",
              kind: "data",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::components::session_key::session_key_component::Event",
          kind: "enum",
          variants: [
            {
              name: "SessionRegistered",
              type: "contracts::components::session_key::session_key_component::SessionRegistered",
              kind: "nested",
            },
            {
              name: "SessionRevoked",
              type: "contracts::components::session_key::session_key_component::SessionRevoked",
              kind: "nested",
            },
            {
              name: "PermissionUpdated",
              type: "contracts::components::session_key::session_key_component::PermissionUpdated",
              kind: "nested",
            },
            {
              name: "PolicyUpdated",
              type: "contracts::components::session_key::session_key_component::PolicyUpdated",
              kind: "nested",
            },
          ],
        },
        {
          type: "event",
          name: "contracts::nex_account::NexAccount::Event",
          kind: "enum",
          variants: [
            {
              name: "AccountEvent",
              type: "openzeppelin_account::account::AccountComponent::Event",
              kind: "flat",
            },
            {
              name: "SRC5Event",
              type: "openzeppelin_introspection::src5::SRC5Component::Event",
              kind: "flat",
            },
            {
              name: "UpgradeableEvent",
              type: "openzeppelin_upgrades::upgradeable::UpgradeableComponent::Event",
              kind: "flat",
            },
            {
              name: "ReentrancyGuardEvent",
              type: "openzeppelin_security::reentrancyguard::ReentrancyGuardComponent::Event",
              kind: "flat",
            },
            {
              name: "SessionKeyEvent",
              type: "contracts::components::session_key::session_key_component::Event",
              kind: "flat",
            },
          ],
        },
      ],
      classHash:
        "0x7c2126e6e3727ff78d9897702275e04a7ba72a29be39e5dc3f1a2983bf86ad1",
    },
  },
} as const;

export default deployedContracts;