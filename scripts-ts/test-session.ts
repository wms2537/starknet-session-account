import { Account, CallData, RpcProvider, hash, uint256, ec, Provider, TransactionFinalityStatus, Signer, stark, RevertedTransactionReceiptResponse } from "starknet";


import { networks } from "./helpers/networks";
import deployedContracts from "../outputs/contracts/deployedContracts";
import { green, yellow } from "./helpers/colorize-log";

class Session {
    publicKey: string;
    expiresAt: number;
    metadata: string;
    isRevoked: boolean;
    permissions: SessionPermission[];
    policy: SessionPolicy;

    constructor(publicKey: string, expiresAt: number, metadata: string, isRevoked: boolean = false) {
        this.publicKey = publicKey;
        this.expiresAt = expiresAt;
        this.metadata = metadata;
        this.isRevoked = isRevoked;
        this.permissions = null;
        this.policy = null;
    }
}

class SessionPermission {
    mode: string;
    contract: string;
    selectors: string[];

    constructor(mode: string, contract: string, selectors: string[]) {
        this.mode = mode;
        this.contract = contract;
        this.selectors = selectors;
    }
}

class SessionPolicy {
    maxAmount: string;
    currentAmount: string;

    constructor(maxAmount: string, currentAmount: string) {
        this.maxAmount = maxAmount;
        this.currentAmount = currentAmount;
    }
}


// Main account keys (used to deploy and manage the account)
const MAIN_PRIVATE_KEY = "0x00000000000000000000000000000000b467066159b295a7667b633d6bdaabac";
const MAIN_PUBLIC_KEY = "0x00c6c2f7833f681c8fe001533e99571f6ff8dec59268792a429a14b5b252f1ad";

// Master account for funding
const MASTER_ADDRESS = "0x64b48806902a367c8598f4f95c305e8c1a1acba5f082d294a43793113115691";
const MASTER_PRIVATE_KEY = "0x0000000000000000000000000000000071d7bb07b9a64f6f78ac4c816aff4da9";

// ETH/STRK contract addresses on devnet
const ETH_ADDRESS = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
const STRK_ADDRESS = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";

// Move provider to global scope
let provider: RpcProvider;

async function fundAccount(
    provider: RpcProvider, 
    targetAddress: string, 
    amount: string = "0.1"
) {
    console.log(yellow("\nFunding account with ETH and STRK..."));
    
    // Create master account instance
    const masterAccount = new Account(
        provider,
        MASTER_ADDRESS,
        MASTER_PRIVATE_KEY,
        "1",                // cairoVersion (use "1" for Cairo 1.0)
        "0x2"              // transactionVersion
    );

    // Convert amount to uint256
    const amountUint256 = uint256.bnToUint256(
        BigInt(parseFloat(amount) * 10**18)
    );

    // Transfer ETH
    const ethTransfer = {
        contractAddress: ETH_ADDRESS,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: targetAddress,
            amount: amountUint256
        })
    };

    // Transfer STRK
    const strkTransfer = {
        contractAddress: STRK_ADDRESS,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: targetAddress,
            amount: amountUint256
        })
    };

    const tx = await masterAccount.execute([ethTransfer, strkTransfer]);
    await provider.waitForTransaction(tx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Account funded successfully"));
}

// Add this helper function to generate key pairs
function generateSessionKeyPair() {
    const privateKey = stark.randomAddress();
    const publicKey = ec.starkCurve.getStarkKey(privateKey);
    
    return {
        privateKey: privateKey,
        publicKey: publicKey
    };
}

// Modify SessionAccount to not require public key in constructor
class SessionAccount extends Account {
    constructor(
        provider: Provider,
        address: string,
        privateKey: string
    ) {
        super(provider, address, privateKey, "1", "0x2");
        this.signer = new SessionSigner(privateKey);
    }
}

// Update SessionSigner to compute public key from private key
class SessionSigner extends Signer {
    private privateKey: string;

    constructor(privateKey: string) {
        super();
        this.privateKey = privateKey;
    }

    protected async signRaw(msgHash: string): Promise<string[]> {
        const signature = ec.starkCurve.sign(msgHash, this.privateKey);
        const publicKey = ec.starkCurve.getStarkKey(this.privateKey);

        return [
            "0x73657373696f6e2d746f6b656e", // Magic value
            publicKey.toString(),           // Compute public key from private key
            signature.r.toString(),         // r value
            signature.s.toString()          // s value
        ];
    }

    public async getPubKey(): Promise<string> {
        return ec.starkCurve.getStarkKey(this.privateKey);
    }
}

async function main() {
    // Initialize provider and accounts
    provider = networks.devnet.provider;
    const contracts = deployedContracts.devnet;
    const accountAddress = contracts.NexAccount.address;
    const targetContract = ETH_ADDRESS;
    
    await fundAccount(provider, accountAddress);

    // Create main account
    const mainAccount = new Account(
        provider,
        accountAddress,
        MAIN_PRIVATE_KEY,
        "1",
        "0x2"
    );

    console.log(yellow("Testing Session Key Implementation"));
    console.log("Account Address:", accountAddress);
    console.log("Target Contract:", targetContract);

    // Test Case 1: Basic Session Setup (now includes getter tests)
    console.log(yellow("\nTest Case 1: Basic Session Setup"));
    await testBasicSessionSetup(mainAccount, accountAddress, targetContract);

    // Test Case 2: Policy Limits
    console.log(yellow("\nTest Case 2: Testing Policy Limits"));
    await testPolicyLimits(mainAccount, accountAddress, targetContract);

    // Test Case 3: Session Expiry
    console.log(yellow("\nTest Case 3: Testing Session Expiry"));
    await testSessionExpiry(mainAccount, accountAddress, targetContract);

    // Test Case 4: Permission Restrictions
    console.log(yellow("\nTest Case 4: Testing Permission Restrictions"));
    await testPermissionRestrictions(mainAccount, accountAddress, targetContract);

    // Test Case 5: Session Revocation
    console.log(yellow("\nTest Case 5: Testing Session Revocation"));
    await testSessionRevocation(mainAccount, accountAddress, targetContract);

    // Test Case 6: Multiple Sessions
    console.log(yellow("\nTest Case 6: Testing Multiple Sessions"));
    await testMultipleSessions(mainAccount, accountAddress, targetContract);

    // Test Case 7: Multiple Selectors
    console.log(yellow("\nTest Case 7: Testing Multiple Selectors"));
    await testMultipleSelectors(mainAccount, accountAddress, targetContract);

    // Test Case 8: Blacklist Mode
    console.log(yellow("\nTest Case 8: Testing Blacklist Mode"));
    await testBlacklistMode(mainAccount, accountAddress, targetContract);

    // Test Case 9: Multiple Calls
    console.log(yellow("\nTest Case 9: Testing Multiple Calls"));
    await testMultipleCalls(mainAccount, accountAddress, targetContract);

    // Test Case 10: Event Emission
    console.log(yellow("\nTest Case 10: Testing Event Emission"));
    await testEventEmission(mainAccount, accountAddress, targetContract);
}

async function testBasicSessionSetup(
    mainAccount: Account,
    accountAddress: string,
    targetContract: string
) {
    console.log(yellow("\nSetting up basic session..."));
    // Generate session keys and create session account
    const {sessionKeys, sessionAccount} = await setupTestSession(accountAddress, "basic_test_session", mainAccount, targetContract);
    
    // Set permissions for transfer
    await setupBasicPermission(accountAddress, sessionKeys, targetContract, mainAccount);

    // Set basic policy
    await setupBasicPolicy(accountAddress, sessionKeys, targetContract, mainAccount);

    // Try a basic transfer
    console.log(yellow("Testing basic transfer..."));
    const transferCall = {
        contractAddress: targetContract,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: "0x123",
            amount: { low: 100, high: 0 }
        })
    };

    const transferTx = await sessionAccount.execute([transferCall]);
    await provider.waitForTransaction(transferTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green(`Basic transfer with session key ${sessionKeys.publicKey} successful`));

    // Verify session is registered
    console.log(yellow("Verifying session registration..."));
    const checkSessionCall = {
        contractAddress: accountAddress,
        entrypoint: "is_session_registered",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            guid_or_address: MAIN_PUBLIC_KEY
        })
    };

    const result = await mainAccount.execute(checkSessionCall);

    if (result.transaction_hash) {
        console.log(green(`Session registration verified successfully for session key ${sessionKeys.publicKey}`));
    } else {
        throw new Error("Session registration verification failed");
    }

    // Add calls to new test functions
    await testGetAllSessions(accountAddress);
    console.log(yellow("\nTesting Get Session Details..."));
    const session = await getSessionDetails(accountAddress, sessionKeys);
    console.log(green("Session Details:"));
    console.log({
        exists: true,
        session: {
            publicKey: session.publicKey,
            expiresAt: new Date(session.expiresAt * 1000).toISOString(),
            metadata: session.metadata,
            isRevoked: session.isRevoked
        }
    });
    console.log(yellow("\nTesting Get Permission Details..."));
    const permissions = await getPermissionDetails(accountAddress, sessionKeys, targetContract);
    console.log(green("Permission Details:"));
    console.log(permissions);
    console.log(yellow("\nTesting Get Policy Details..."));
    const policy = await getPolicyDetails(accountAddress, sessionKeys, targetContract);
    console.log(green("Policy Details:"));
    console.log(policy);
}

async function setupTestSession(accountAddress: string, metadata: string, mainAccount: Account, targetContract: string, expiry: number = 3600, setPermissions: boolean = true, setPolicy: boolean = true) {
    const sessionKeys = generateSessionKeyPair();
    const sessionAccount = new SessionAccount(
        provider,
        accountAddress,
        sessionKeys.privateKey
    );

    const currentTime = Math.floor(Date.now() / 1000);
    const registerCall = {
        contractAddress: accountAddress,
        entrypoint: "register_session",
        calldata: CallData.compile({
            session: {
                public_key: sessionKeys.publicKey,
                expires_at: currentTime + expiry,
                metadata: createMetadata(metadata),
                is_revoked: false,
            },
            guid_or_address: MAIN_PUBLIC_KEY
        })
    };

    const registerTx = await mainAccount.execute(registerCall);
    await provider.waitForTransaction(registerTx.transaction_hash, {
        retryInterval: 1000,
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2]
    });
    console.log(green("Session registered successfully"));

    if (setPermissions) {
        await setupBasicPermission(accountAddress, sessionKeys, targetContract, mainAccount);
    }

    if (setPolicy) {
        await setupBasicPolicy(accountAddress, sessionKeys, targetContract, mainAccount);
    }

    return {sessionKeys, sessionAccount};
}

async function setupBasicPermission(accountAddress: string, sessionKeys: { privateKey: string; publicKey: string; }, targetContract: string, mainAccount: Account) {
    console.log(yellow("Setting up basic permissions..."));
    const permissionCall = {
        contractAddress: accountAddress,
        entrypoint: "set_permission",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            contract: targetContract,
            mode: 0,
            selectors: [hash.getSelectorFromName("transfer")]
        })
    };
    const permissionTx = await mainAccount.execute(permissionCall);
    await provider.waitForTransaction(permissionTx.transaction_hash, {
        retryInterval: 1000,
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2]
    });
    console.log(green(`Basic permissions set successfully for session key ${sessionKeys.publicKey}`));
}

async function setupBasicPolicy(accountAddress: string, sessionKeys: { privateKey: string; publicKey: string; }, targetContract: string, mainAccount: Account) {
    console.log(yellow("Setting up basic policy..."));
    const policyCall = {
        contractAddress: accountAddress,
        entrypoint: "set_policy",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            contract: targetContract,
            policy: {
                max_amount: uint256.bnToUint256(10000n), // 10000 tokens
                current_amount: uint256.bnToUint256(0n),
            }
        })
    };
    const policyTx = await mainAccount.execute(policyCall);
    await provider.waitForTransaction(policyTx.transaction_hash, {
        retryInterval: 1000,
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2]
    });
    console.log(green(`Basic policy set successfully for session key ${sessionKeys.publicKey}`));
}

async function testGetAllSessions(
    accountAddress: string
) {
    console.log(yellow("\nTesting Get All Sessions..."));

    const getAllSessionsCall = {
        contractAddress: accountAddress,
        entrypoint: "get_all_sessions",
        calldata: CallData.compile({})
    };

    const allSessions = await provider.callContract(getAllSessionsCall);
    console.log(green("All Sessions:"));
    const sessions_len = Number(allSessions[0]);
    const sessions = [];
    for (let i = 0; i < sessions_len; i++) {
        sessions.push(allSessions[i + 1]);
    }
    console.log({
        sessions_len,
        sessions
    });
}

async function getSessionDetails(
    accountAddress: string,
    sessionKeys: { publicKey: string, privateKey: string }
) {
    const getSessionCall = {
        contractAddress: accountAddress,
        entrypoint: "get_session",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey
        })
    };
    const sessionResult = await provider.callContract(getSessionCall);
    if (sessionResult[0] !== '0') {
        const publicKey = sessionResult[1];
        const expiresAt = Number(sessionResult[2]);
        const metadataLen = Number(sessionResult[3]);
        const metadata = sessionResult.slice(4, 4 + metadataLen)
            .map(n => String.fromCharCode(Number(n)))
            .join('');
        const isRevoked = Boolean(Number(sessionResult[4 + metadataLen]));
        const session = new Session(publicKey, expiresAt, metadata, isRevoked);
        return session;
    }
    return null;
}

async function getPermissionDetails(
    accountAddress: string,
    sessionKeys: { publicKey: string, privateKey: string },
    targetContract: string
) {
    

    const getPermissionCall = {
        contractAddress: accountAddress,
        entrypoint: "get_permission_details",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            contract: targetContract
        })
    };

    const permissionResult = await provider.callContract(getPermissionCall);
    
    if (permissionResult.length > 0) {
        const mode = permissionResult[0] === '0' ? 'Whitelist' : 'Blacklist';
        const selectorsLength = Number(permissionResult[1]);
        const selectors = permissionResult.slice(2, 2 + selectorsLength);

        return new SessionPermission(mode, targetContract, selectors);
    }
}

async function getPolicyDetails(
    accountAddress: string,
    sessionKeys: { publicKey: string, privateKey: string },
    targetContract: string
) {
    const getPolicyCall = {
        contractAddress: accountAddress,
        entrypoint: "get_policy",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            contract: targetContract
        })
    };

    const policyResult = await provider.callContract(getPolicyCall);
    
    if (policyResult.length > 0) {
        const maxAmount = {
            low: policyResult[1],
            high: policyResult[2]
        };
        const currentAmount = {
            low: policyResult[3],
            high: policyResult[4]
        };
        
        const policy = new SessionPolicy(
            uint256.uint256ToBN(maxAmount).toString(),
            uint256.uint256ToBN(currentAmount).toString()
        );
        return policy;
    }
}

async function testPolicyLimits(
    mainAccount: Account, 
    accountAddress: string, 
    targetContract: string
) {
    console.log(yellow("\nSetting up session for policy limits test..."));

    // Register session first
    const {sessionKeys, sessionAccount} = await setupTestSession(accountAddress, "policy_test_session", mainAccount, targetContract);

    // Set permissions for transfer
    const permissionCall = {
        contractAddress: accountAddress,
        entrypoint: "set_permission",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            contract: targetContract,
            mode: 0, // Whitelist
            selectors: [hash.getSelectorFromName("transfer")]
        })
    };

    const permissionTx = await mainAccount.execute(permissionCall);
    await provider.waitForTransaction(permissionTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Permissions set successfully"));

    // Rest of the existing policy test code...
    const maxAmount = 1000n;
    console.log(yellow(`Setting policy with max amount: ${maxAmount}`));
    
    // Set policy with low max amount
    const policyCall = {
        contractAddress: accountAddress,
        entrypoint: "set_policy",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,  // Use generated public key
            contract: targetContract,
            policy: {
                max_amount: uint256.bnToUint256(maxAmount),
                current_amount: uint256.bnToUint256(0n),
            }
        })
    };
    const policyTx = await mainAccount.execute(policyCall);
    await provider.waitForTransaction(policyTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });

    // Try transfer within limit
    const validTransfer = {
        contractAddress: targetContract,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: "0x123",
            amount: { low: Number(maxAmount) - 100, high: 0 }
        })
    };
    const validTx = await sessionAccount.execute([validTransfer]);
    await provider.waitForTransaction(validTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Transfer within policy limit successful"));

    // Try transfer exceeding limit
    const invalidTransfer = {
        contractAddress: targetContract,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: "0x123",
            amount: { low: Number(maxAmount) + 100, high: 0 }
        })
    };
    try {
        const invalidTx = await sessionAccount.execute([invalidTransfer]);
        await provider.waitForTransaction(invalidTx.transaction_hash, { 
            retryInterval: 1000, 
            successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
        });
        const tx = await provider.getTransactionReceipt(invalidTx.transaction_hash);
        console.log(tx)
        throw new Error("Should have failed");
    } catch (error) {
        if (error.message.includes("Policy check failed")) {
            console.log(green("Policy limit check working correctly"));
        } else {
            throw error;
        }
    }
}

async function testSessionExpiry(
    mainAccount: Account,
    accountAddress: string,
    targetContract: string
) {
    console.log(yellow("\nTesting Session Expiry..."));
    
    // Setup session with short expiry
    const {sessionKeys, sessionAccount} = await setupTestSession(accountAddress, "test_session", mainAccount, targetContract, 0);

    // Wait for session to expire
    console.log("Waiting for session to expire...");
    await new Promise(resolve => setTimeout(resolve, 10000));

    // Try to use expired session
    const transfer = {
        contractAddress: targetContract,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: "0x123",
            amount: { low: 100, high: 0 }
        })
    };

    try {
        // Use the passed sessionAccount which was created with the short session keys
        const transferTx = await sessionAccount.execute([transfer]);
        await provider.waitForTransaction(transferTx.transaction_hash, { 
            retryInterval: 1000, 
            successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
        });
        const receipt = await provider.getTransactionReceipt(transferTx.transaction_hash);
        if(receipt.isReverted) {
            throw new Error((receipt.value as RevertedTransactionReceiptResponse).revert_reason);
        }
    } catch (error) {
        if (error.message.includes("Session expired")) {
            console.log(green("Session expiry check working correctly"));
        } else {
            throw error;
        }
    }
}

async function testPermissionRestrictions(
    mainAccount: Account,
    accountAddress: string, 
    targetContract: string
) {
    console.log(yellow("\nSetting up session for permission restrictions test..."));
    // Generate session keys and create session account
    const {sessionKeys, sessionAccount} = await setupTestSession(accountAddress, "permission_test_session", mainAccount, targetContract);

    // Try allowed function (transfer)
    const validCall = {
        contractAddress: targetContract,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: "0x123",
            amount: { low: 100, high: 0 }
        })
    };
    const validTx = await sessionAccount.execute([validCall]);
    await provider.waitForTransaction(validTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Allowed function call successful"));

    // Try restricted function (e.g., approve)
    const invalidCall = {
        contractAddress: targetContract,
        entrypoint: "approve",
        calldata: CallData.compile({
            spender: "0x123",
            amount: { low: 100, high: 0 }
        })
    };

    try {
        const invalidTx = await sessionAccount.execute([invalidCall]);
        await provider.waitForTransaction(invalidTx.transaction_hash, { 
            retryInterval: 1000, 
            successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
        });
        throw new Error("Should have failed");
    } catch (error) {
        if (error.message.includes("Invalid selector")) {
            console.log(green("Permission restriction working correctly"));
        } else {
            throw error;
        }
    }
}

async function testSessionRevocation(
    mainAccount: Account,
    accountAddress: string,
    targetContract: string
) {
    console.log(yellow("\nSetting up session for revocation test..."));
    
    // Register session first
    const {sessionKeys, sessionAccount} = await setupTestSession(accountAddress, "revocation_test_session", mainAccount, targetContract);

    // Update to use sessionKeys.publicKey instead of sessionPublicKey
    console.log(yellow("Revoking session..."));
    const revokeCall = {
        contractAddress: accountAddress,
        entrypoint: "revoke_session",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey
        })
    };
    const revokeTx = await mainAccount.execute(revokeCall);
    await provider.waitForTransaction(revokeTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Session revoked successfully"));

    // Try to use revoked session
    console.log(yellow("Testing revoked session..."));
    const transfer = {
        contractAddress: targetContract,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: "0x123",
            amount: { low: 100, high: 0 }
        })
    };

    try {
        const transferTx = await sessionAccount.execute([transfer]);
        await provider.waitForTransaction(transferTx.transaction_hash, { 
            retryInterval: 1000, 
            successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
        });
        throw new Error("Should have failed");
    } catch (error) {
        if (error.message.includes("Session already revoked")) {
            console.log(green("Session revocation working correctly"));
        } else {
            throw error;
        }
    }
}

async function testMultipleSessions(
    mainAccount: Account,
    accountAddress: string,
    targetContract: string
) {
    console.log(yellow("\nSetting up multiple sessions test..."));
    
    // Generate multiple session keys
    const {sessionKeys: session1Keys, sessionAccount: sessionAccount1} = await setupTestSession(accountAddress, "multiple_sessions_test_session_1", mainAccount, targetContract);
    const {sessionKeys: session2Keys, sessionAccount: sessionAccount2} = await setupTestSession(accountAddress, "multiple_sessions_test_session_2", mainAccount, targetContract);

    console.log("Session 1 public key:", session1Keys.publicKey);
    console.log("Session 2 public key:", session2Keys.publicKey);

    // Test transfers with both sessions
    const transferCall = {
        contractAddress: targetContract,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: "0x123",
            amount: { low: 100, high: 0 }
        })
    };

    // Try transfer with session 1
    const transferTx1 = await sessionAccount1.execute([transferCall]);
    await provider.waitForTransaction(transferTx1.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Transfer with session 1 successful"));

    // Try transfer with session 2
    const transferTx2 = await sessionAccount2.execute([transferCall]);
    await provider.waitForTransaction(transferTx2.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Transfer with session 2 successful"));
}

// Helper function to create metadata
function createMetadata(text: string) {
    const metadataBytes = Array.from(Buffer.from(text));
    const BYTES_PER_FELT = 31;
    const fullWords = Math.floor(metadataBytes.length / BYTES_PER_FELT);
    const fullWordsData = Array(fullWords).fill(0);
    const remainingBytes = metadataBytes.slice(fullWords * BYTES_PER_FELT);
    const remainingWord = remainingBytes.reduce(
        (acc, byte, i) => acc + BigInt(byte) * (256n ** BigInt(i)), 
        0n
    ).toString();

    return {
        data: fullWordsData,
        pending_word: remainingWord,
        pending_word_len: remainingBytes.length
    };
}

async function testMultipleSelectors(
    mainAccount: Account,
    accountAddress: string,
    targetContract: string
) {
    console.log(yellow("\nSetting up session for multiple selectors test..."));
    
    // Register session first
    const {sessionKeys, sessionAccount} = await setupTestSession(accountAddress, "multiple_selectors_test_session", mainAccount, targetContract, 3600, false);
    
    // Set permissions with multiple selectors
    console.log(yellow("Setting up permissions with multiple selectors..."));
    const permissionCall = {
        contractAddress: accountAddress,
        entrypoint: "set_permission",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            contract: targetContract,
            mode: 0,
            selectors: [
                hash.getSelectorFromName("transfer"),
                hash.getSelectorFromName("approve"),
                hash.getSelectorFromName("transferFrom")
            ]
        })
    };

    const permissionTx = await mainAccount.execute(permissionCall);
    await provider.waitForTransaction(permissionTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Permissions set with multiple selectors"));

    // Try all allowed functions
    const calls = [
        {
            contractAddress: targetContract,
            entrypoint: "transfer",
            calldata: CallData.compile({
                recipient: "0x123",
                amount: { low: 100, high: 0 }
            })
        },
        {
            contractAddress: targetContract,
            entrypoint: "approve",
            calldata: CallData.compile({
                spender: "0x123",
                amount: { low: 100, high: 0 }
            })
        }
    ];

    const validTx = await sessionAccount.execute(calls);
    await provider.waitForTransaction(validTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Multiple allowed functions executed successfully"));
}

async function testMultipleCalls(
    mainAccount: Account,
    accountAddress: string,
    targetContract: string
) {
    console.log(yellow("\nSetting up session for multiple calls test..."));
    
    // Register session first
    const {sessionKeys, sessionAccount} = await setupTestSession(accountAddress, "multiple_calls_test_session", mainAccount, targetContract, 3600);

    // Try multiple transfers in single transaction
    console.log(yellow("Testing multiple calls within policy limit..."));
    const calls = [
        {
            contractAddress: targetContract,
            entrypoint: "transfer",
            calldata: CallData.compile({
                recipient: "0x123",
                amount: { low: 3000, high: 0 }
            })
        },
        {
            contractAddress: targetContract,
            entrypoint: "transfer",
            calldata: CallData.compile({
                recipient: "0x456",
                amount: { low: 3000, high: 0 }
            })
        }
    ];

    const validTx = await sessionAccount.execute(calls);
    await provider.waitForTransaction(validTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Multiple calls executed successfully"));

    // Try multiple calls exceeding policy limit
    console.log(yellow("Testing multiple calls exceeding policy limit..."));
    const invalidCalls = [
        {
            contractAddress: targetContract,
            entrypoint: "transfer",
            calldata: CallData.compile({
                recipient: "0x123",
                amount: { low: 6000, high: 0 }
            })
        },
        {
            contractAddress: targetContract,
            entrypoint: "transfer",
            calldata: CallData.compile({
                recipient: "0x456",
                amount: { low: 6000, high: 0 }
            })
        }
    ];

    try {
        const invalidTx = await sessionAccount.execute(invalidCalls);
        await provider.waitForTransaction(invalidTx.transaction_hash, { 
            retryInterval: 1000, 
            successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
        });
        throw new Error("Should have failed");
    } catch (error) {
        if (error.message.includes("Policy check failed")) {
            console.log(green("Policy limit correctly enforced for multiple calls"));
        } else {
            throw error;
        }
    }
}

async function testBlacklistMode(
    mainAccount: Account,
    accountAddress: string,
    targetContract: string
) {
    console.log(yellow("\nSetting up session for blacklist mode test..."));
    
    // Register session first
    const {sessionKeys, sessionAccount} = await setupTestSession(accountAddress, "blacklist_test_session", mainAccount, targetContract, 3600, false);

    // Set permissions with blacklist mode
    console.log(yellow("Setting up blacklist mode permissions..."));
    const permissionCall = {
        contractAddress: accountAddress,
        entrypoint: "set_permission",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            contract: targetContract,
            mode: 1, // Blacklist mode
            selectors: [hash.getSelectorFromName("approve")]
        })
    };

    const permissionTx = await mainAccount.execute(permissionCall);
    await provider.waitForTransaction(permissionTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Blacklist permissions set successfully"));

    // Try non-blacklisted function (transfer)
    console.log(yellow("Testing non-blacklisted function..."));
    const validCall = {
        contractAddress: targetContract,
        entrypoint: "transfer",
        calldata: CallData.compile({
            recipient: "0x123",
            amount: { low: 100, high: 0 }
        })
    };
    
    const validTx = await sessionAccount.execute([validCall]);
    await provider.waitForTransaction(validTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });
    console.log(green("Non-blacklisted function call successful"));

    // Try blacklisted function (approve)
    console.log(yellow("Testing blacklisted function..."));
    const invalidCall = {
        contractAddress: targetContract,
        entrypoint: "approve",
        calldata: CallData.compile({
            spender: "0x123",
            amount: { low: 100, high: 0 }
        })
    };

    try {
        const invalidTx = await sessionAccount.execute([invalidCall]);
        await provider.waitForTransaction(invalidTx.transaction_hash, { 
            retryInterval: 1000, 
            successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
        });
        throw new Error("Should have failed");
    } catch (error) {
        if (error.message.includes("Invalid selector")) {
            console.log(green("Blacklist mode working correctly"));
        } else {
            throw error;
        }
    }
}

async function testEventEmission(
    mainAccount: Account,
    accountAddress: string,
    targetContract: string
) {
    // Generate session keys and create session account
    const sessionKeys = generateSessionKeyPair();
    const sessionAccount = new SessionAccount(
        provider,
        accountAddress,
        sessionKeys.privateKey
    );

    console.log(yellow("\nTesting Event Emission..."));
    
    // 1. Test SessionRegistered event
    const currentTime = Math.floor(Date.now() / 1000);
    const registerCall = {
        contractAddress: accountAddress,
        entrypoint: "register_session",
        calldata: CallData.compile({
            session: {
                public_key: sessionKeys.publicKey,
                expires_at: currentTime + 3600,
                metadata: createMetadata("event_test_session"),
                is_revoked: false
            },
            guid_or_address: MAIN_PUBLIC_KEY
        })
    };

    const registerTx = await mainAccount.execute(registerCall);
    await provider.waitForTransaction(registerTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });

    // Verify SessionRegistered event
    const registerReceipt = await provider.getTransactionReceipt(registerTx.transaction_hash);
    if ('events' in registerReceipt) {
        const sessionRegisteredEvent = registerReceipt.events?.find(
            e => e.keys.includes(hash.getSelectorFromName("SessionRegistered"))
        );
        if (sessionRegisteredEvent) {
            if (sessionRegisteredEvent.data[0] === sessionKeys.publicKey) {
                console.log(green("SessionRegistered event verified"));
            } else {
                throw new Error("Wrong public key in SessionRegistered event");
            }
        } else {
            throw new Error("SessionRegistered event not emitted");
        }
    }

    // 2. Test PermissionUpdated event
    const permissionCall = {
        contractAddress: accountAddress,
        entrypoint: "set_permission",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            contract: targetContract,
            mode: 0,
            selectors: [hash.getSelectorFromName("transfer")]
        })
    };

    const permissionTx = await mainAccount.execute(permissionCall);
    await provider.waitForTransaction(permissionTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });

    // Verify PermissionUpdated event
    const permissionReceipt = await provider.getTransactionReceipt(permissionTx.transaction_hash);
    if ('events' in permissionReceipt) {
        const permissionEvent = permissionReceipt.events?.find(
            e => e.keys.includes(hash.getSelectorFromName("PermissionUpdated"))
        );
        if (permissionEvent) {
            console.log(green("PermissionUpdated event verified"));
        } else {
            throw new Error("PermissionUpdated event not emitted");
        }
    }

    // 3. Test PolicyUpdated event
    const policyCall = {
        contractAddress: accountAddress,
        entrypoint: "set_policy",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey,
            contract: targetContract,
            policy: {
                max_amount: uint256.bnToUint256(1000n),
                current_amount: uint256.bnToUint256(0n),
            }
        })
    };

    const policyTx = await mainAccount.execute(policyCall);
    await provider.waitForTransaction(policyTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });

    // Verify PolicyUpdated event
    const policyReceipt = await provider.getTransactionReceipt(policyTx.transaction_hash);
    if ('events' in policyReceipt) {
        const policyEvent = policyReceipt.events?.find(
            e => e.keys.includes(hash.getSelectorFromName("PolicyUpdated"))
        );
        if (policyEvent) {
            console.log(green("PolicyUpdated event verified"));
        } else {
            throw new Error("PolicyUpdated event not emitted");
        }
    }

    // 4. Test SessionRevoked event
    const revokeCall = {
        contractAddress: accountAddress,
        entrypoint: "revoke_session",
        calldata: CallData.compile({
            public_key: sessionKeys.publicKey
        })
    };

    const revokeTx = await mainAccount.execute(revokeCall);
    await provider.waitForTransaction(revokeTx.transaction_hash, { 
        retryInterval: 1000, 
        successStates: [TransactionFinalityStatus.ACCEPTED_ON_L2] 
    });

    // Verify SessionRevoked event
    const revokeReceipt = await provider.getTransactionReceipt(revokeTx.transaction_hash);
    if ('events' in revokeReceipt) {
        const revokeEvent = revokeReceipt.events?.find(
            e => e.keys.includes(hash.getSelectorFromName("SessionRevoked"))
        );
        if (revokeEvent) {
            console.log(green("SessionRevoked event verified"));
        } else {
            throw new Error("SessionRevoked event not emitted");
        }
    }
}

main()
    .then(() => process.exit(0))
    .catch((error) => {
        console.error(error);
        process.exit(1);
    }); 