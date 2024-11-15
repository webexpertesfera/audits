# EmPower Token Security Review

A security review of the Empower Token smart contract protocol was done by [0xepley](https://twitter.com/0xepley). \
This audit report includes all the vulnerabilities, issues and code improvements found during the security review.

## About Empower Token

EmpowerCoin’s unique model redistributes a portion of transaction fees to EMPC token holders, creating a steady stream of passive income. This means users earn rewards simply by holding EMPC tokens, making it an attractive investment that continuously generates returns.

## Disclaimer

"Audits are a time, resource and expertise bound effort where trained experts evaluate smart
contracts using a combination of automated and manual techniques to find as many vulnerabilities
as possible. Audits can show the presence of vulnerabilities **but not their absence**."

\- Secureum

## Risk classification

| Severity           | Impact: High | Impact: Medium | Impact: Low |
| :----------------- | :----------: | :------------: | :---------: |
| Likelihood: High   |   Critical   |      High      |   Medium    |
| Likelihood: Medium |     High     |     Medium     |     Low     |
| Likelihood: Low    |    Medium    |      Low       |     Low     |

### Impact

- **High** - leads to a significant material loss of assets in the protocol or significantly harms a group of users.
- **Medium** - only a small amount of funds can be lost (such as leakage of value) or a core functionality of the protocol is affected.
- **Low** - can lead to any kind of unexpected behaviour with some of the protocol's functionalities that's not so critical.

### Likelihood

- **High** - attack path is possible with reasonable assumptions that mimic on-chain conditions and the cost of the attack is relatively low to the amount of funds that can be stolen or lost.
- **Medium** - only conditionally incentivized attack vector, but still relatively likely.
- **Low** - has too many or too unlikely assumptions or requires a huge stake by the attacker with little or no incentive.

### Actions required by severity level

- **High** - client **must** fix the issue.
- **Medium** - client **should** fix the issue.
- **Low** - client **could** fix the issue.

## Executive summary

### Overview

|               |                                                                                              |
| :------------ | :------------------------------------------------------------------------------------------- |
| Project Name  | Empower Token                                                                                   |
| Website    | https://empowercoin.finance/  
| Methods       | Static + Manual review                                                                                |
|               |


### Issues found

| Severity      |                                                     Count |
| :------------ | --------------------------------------------------------: |
| High risk     |       1 |
| Medium risk   |     4 |
| Low risk      |       1 |
| Gas risk      |    2  |
| Informational      |       2 |



### Scope

| File | 
| :------------------------------------------------------------------------------------------------------ | 
| *Contracts (12)*                                                  |
| /UpgradeableProxies/BorrowLendProxy.sol |
| /UpgradeableProxies/DonationProxy.sol |
| /UpgradeableProxies/EmpowerTokenProxy.sol |
| /UpgradeableProxies/EscrowProxy.sol |
| /UpgradeableProxies/LoanPaymentProxy.sol |
| /UpgradeableProxies/TreasuryProxy.sol |
| /BorrowLendUpgradeable.sol |
| /DonationUpgradable.sol |
| /EmpowerTokenUpgradeable.sol |
| /EscrowUpgradeable.sol |
| /LoanPaymentUpgradeable.sol |
| /TreasuryUpgradeable.sol |

# Findings

## High Severity

### Issue[01]: Oracle data feed can be outdated yet used anyways

#### Description
Chainlink classifies their data feeds into four different groups regarding how reliable is each source thus, how risky they are. The groups are *Verified Feeds, Monitored Feeds, Custom Feeds and Specialized Feeds* (they can be seen [here](https://docs.chain.link/docs/selecting-data-feeds/#data-feed-categories)). The risk is the lowest on the first one and highest on the last one.

A strong reliance on the price feeds has to be also monitored as recommended on the [Risk Mitigation section](https://docs.chain.link/docs/selecting-data-feeds/#risk-mitigation). There are several reasons why a data feed may fail such as unforeseen market events, volatile market conditions, degraded performance of infrastructure, chains, or networks, upstream data providers outage, malicious activities from third parties among others.

Chainlink recommends using their data feeds along with some controls to prevent mismatches with the retrieved data. Along some recommendations, the feed can include circuit breakers (for extreme price events), contract update delays (to ensure that the injected data into the protocol is fresh enough), manual kill-switches (to cease connection in case of found bug or vulnerability in an upstream contract), monitoring (control the deviation of the data) and soak testing (of the price feeds).

```solidity
function convertEthToUsd() public view returns (uint256) {
        (
            ,
            /* uint80 roundID */
            int256 answer,
            ,
            ,
        ) = /*uint startedAt*/
        /*uint timeStamp*/
        /*uint80 answeredInRound*/
         s_ethUsdPriceFeed.latestRoundData(); //@audit

        uint256 additionalPrecision = s_ethUsdPriceFeed.decimals() - ERC20Upgradeable(i_usdcToken).decimals();
        return uint256(answer) / (10 ** additionalPrecision);
    }
```

Regarding Empower Token itself, only the `answer` is used. The retrieved price of the `priceFeed` can be outdated and used anyways as a valid data because no timestamp tolerance of the update source time is checked while storing the return parameters of `feed.latestRoundData()` as recommended by Chainlink. The usage of outdated data can impact on how the Payment terminals work regarding pricing calculation and value measurement.


#### **Recommendation**
It is recommended to add a tolerance that compares the `updatedAt` return timestamp from `latestRoundData()` with the current block timestamp and ensure that the `priceFeed` is being updated with the required frequency.

 `ETH/USD` is the only one that is needed to retrieve, because it is the most popular and available pair. It can also be useful to add other oracle to get the price feed (such as Uniswap's). This can be used as a redundancy in the case of having one oracle that returns outdated values (what is outdated and what is up to date can be determined by a tolerance as mentioned).

#### **Resolution:**
Solved



## Medium severity

### Issue[01]: No Withdraw Function for Ether in the Contract

#### **Summary**
The contract `Rounter.sol` includes a `receive()` function to accept Ether (ETH) transfers, but it does not have a corresponding withdraw function to allow users to retrieve or withdraw their funds. 

#### **Issue Description**
In Solidity, a `receive()` function allows a contract to accept Ether payments. The function is automatically triggered when Ether is sent to the contract. However, in this contract, there is no mechanism to allow users to withdraw their funds after sending them.

The absence of a withdraw function can be problematic in the following ways:
1. **Accidental ETH Transfers**: If a user mistakenly sends ETH to the contract, they will not be able to recover it because there is no withdraw function implemented.
2. **No Recovery Mechanism**: Without a dedicated function to withdraw Ether, the contract cannot offer a safe way to reverse transactions in case of mistakes or unintended transfers.

#### **Recommendation**
It is recommended to implement a **withdraw function** that allows the contract owner or users to withdraw Ether from the contract. 

#### **Resolution:**
Solved



### Issue[02]: ETH transfer uses deprecated `.transfer()` instead of `.call()`

#### Description
The contract `Donation.sol` in the function `transferETH` uses `.transfer()` to send ETH. This method is deprecated and has a hard-coded gas limit of 2300 gas units, which could potentially cause transactions to fail if the receiving address is a contract with a more complex receive function.

#### Proof of Concept (PoC)
```solidity
// Current implementation
function retrieve() public onlyOwner {
    if (ethBal > 0) {
        payable(msg.sender).transfer(ethBal); //@audit - using deprecated transfer
    }
}
```

#### Technical Details
1. `.transfer()` forwards exactly 2300 gas
2. `.call()` forwards all available gas by default
3. `.call()` returns a boolean indicating success/failure
4. Important to check the return value of `.call()`

#### Recommended Mitigation
Use `.call()` with value instead of `.transfer()` and implement checks-effects-interactions pattern:

```solidity
function retrieve() public onlyOwner {

    if (ethBal > 0) {
        // Using call instead of transfer
        (bool success, ) = payable(msg.sender).call{value: ethBal}("");
        require(success, "ETH transfer failed");
    }
}
```

#### **Resolution**
Solved








## Issue[03]: Missing sender tracking in ETH deposits breaks protocol functionality

#### Description
The `receive()` function accumulates ETH rewards without tracking the sender's address. This is a critical issue as the protocol lacks a mechanism to identify who contributed what amount of ETH, which could break core protocol functionality like reward distribution or withdrawal mechanisms.

#### Impact
- Protocol cannot track individual user contributions
- Unable to attribute rewards to specific users
- No way to implement user-specific withdrawals
- Could lead to loss of user funds or unfair reward distribution
- Core protocol functionality may be compromised

#### Proof of Concept (PoC)
```solidity
receive() external payable {
    if (msg.value == 0) {
        revert();
    }
    // @audit Critical: No tracking of sender address
    ethReward.lastTimeRewardGotInTime = block.timestamp;
    ethReward.totalRewardsAccumulatedTillTime += msg.value;
}
```

If multiple users send ETH:
1. User A sends 1 ETH
2. User B sends 2 ETH
3. Total is tracked (3 ETH) but protocol has no way to know:
   - Who sent what amount
   - How to distribute rewards fairly
   - How to handle user-specific withdrawals

#### Recommended Mitigation
Implement a mapping to track user deposits:

```solidity
// Add state variable
mapping(address => uint256) public userEthContributions;

// Add event
event EthReceived(address indexed sender, uint256 amount, uint256 timestamp);

receive() external payable {
    if (msg.value == 0) {
        revert();
    }
    
    // Track individual contributions
    userEthContributions[msg.sender] += msg.value;
    
    ethReward.lastTimeRewardGotInTime = block.timestamp;
    ethReward.totalRewardsAccumulatedTillTime += msg.value;
    
    emit EthReceived(msg.sender, msg.value, block.timestamp);
}

```
#### **Resolution**
This is by deisng, user should be aware of this.

### Issue[04]: Missing Return Check on `staticcall` in `getBorrowAmountInUSDC`

In the function `getBorrowAmountInUSDC`, the code is using the `staticcall` function to interact with other contracts, but there is no check on the return value of the `staticcall`. The `staticcall` is a low-level function that executes a function in another contract, and its result could potentially fail or return invalid data. It’s important to verify both the success of the call and the validity of the returned data to ensure your contract behaves as expected.

#### **Description**
The `staticcall` function returns two values:
1. `success`: A boolean indicating whether the call succeeded (i.e., whether it did not revert).
2. `data`: The data returned by the call, which could represent any type of result depending on the function being called.

The code is using `staticcall` to retrieve values such as the token’s decimals and the Ethereum equivalent of the borrowed amount. However, if either of these `staticcall` operations fails, the contract will continue execution without any explicit check, potentially leading to incorrect results or even state corruption.

#### Recommendation

```solidity
    (bool success, bytes memory data) = (i_empowerToken).staticcall(abi.encodeWithSignature("decimals()"));
    if (!success || data.length == 0) {
        revert("Failed to get decimals");
    }
}
```

#### Resolution
Solved

## Low

### [L-01] Unused Function `transferFunds`

#### Summary
The function `transferFunds` in `BorrowLend.sol` is defined in the contract but is not used anywhere in the codebase. This is a low-severity issue, as the presence of an unused function does not introduce security vulnerabilities directly. However, it can lead to unnecessary increases in the bytecode size, making the contract slightly more costly to deploy and possibly more challenging to understand for future maintainers.

#### **Recommendations**
If there are no plans to use this function in future logic, remove it to optimize contract size and clarity.

#### **Resolution**
Solved


## Gas Severity

### [G-01] Nesting if-statements is cheaper than using &&

#### Details
Nesting if-statements avoids the stack operations of setting up and using an extra jumpdest, and saves 6 [gas](https://gist.github.com/IllIllI000/7f3b818abecfadbef93b894481ae7d19)

#### **Resolution**
Solved

### [G-02] Cache array length outside of loop

#### Details
If not cached, the solidity compiler will always read the length of the array during each iteration. That is, if it is a storage array, this is an extra sload operation (100 additional extra gas for each iteration except for the first) and if it is a memory array, this is an extra mload operation (3 additional gas for each iteration except for the first).

There are two instances of this issue in `BorrowLendUpgradeable.sol`

#### **Resolution**
Solved


## Informational

### [I-01] Emit event at the end of function

#### Summary
It is always recommended to emit the event at the end of function to ensure that the whole function completes before emitting the event. If that's not the case then th event can be emitted first and if there is any offChain system that is looking for the event emission may interpret it wrongly

**Resolution**
Solved

### [I-02] Use the latest solidity version for deployment

### Summary 
Upgrading to a newer Solidity release can optimize gas usage and solve bugs that previous version can have take advantage of new features and improve overall contract efficiency. Where possible, based on compatibility requirements, it is recommended to use newer/latest solidity version to take advantage of the latest optimizations and features. You can see the latest version [here](https://soliditylang.org/blog/category/releases/)

#### Resolution

Acknoledged
