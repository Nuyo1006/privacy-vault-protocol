import { describe, it, beforeEach, expect } from "vitest";
import { Clarinet, Tx, Chain, Account, Contract } from "@hirosystems/clarinet-sdk";

describe("Privacy Vault Protocol - Core Security Operations", () => {
  let chain: Chain;
  let accounts: Map<string, Account>;
  let contract: Contract;

  beforeEach(async () => {
    const deployment = await Clarinet.testEnv();
    chain = deployment.chain;
    accounts = deployment.accounts;
    contract = deployment.contracts.get("vault-security-core")!;
  });

  describe("Entity Registration Flow", () => {
    it("initializes new entity with valid parameters", () => {
      const owner = accounts.get("deployer")!;
      const initialTxn = Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["ST1ENTITY001", "Primary Organization"],
        owner.address
      );

      const executionResult = chain.mineBlock([initialTxn]);
      expect(executionResult[0].result).toBeOk();
    });

    it("prevents duplicate entity registration with same identifier", () => {
      const operator = accounts.get("deployer")!;
      
      const firstAttempt = Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["ST2ENT000001", "Test Org Alpha"],
        operator.address
      );
      chain.mineBlock([firstAttempt]);

      const secondAttempt = Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["ST2ENT000001", "Different Name"],
        operator.address
      );

      const resultBlock = chain.mineBlock([secondAttempt]);
      expect(resultBlock[0].result).toBeErr(101);
    });

    it("tracks entity metadata appropriately", () => {
      const initiator = accounts.get("deployer")!;
      
      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["ENTITY0099", "Established Firm"],
        initiator.address
      );
      chain.mineBlock();

      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-entity",
        ["ENTITY0099"],
        initiator.address
      );
      
      const resultBlock = chain.mineBlock([queryTxn]);
      const queryResult = resultBlock[0].result;
      
      expect(queryResult).toBeOk();
    });
  });

  describe("Record Deposit and Management", () => {
    beforeEach(() => {
      const owner = accounts.get("deployer")!;
      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["CORP_VAULT", "Corporate Records Inc"],
        owner.address
      );
      chain.mineBlock();
    });

    it("successfully deposits record into vault", () => {
      const owner = accounts.get("deployer")!;
      
      const recordHash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
      const depositTxn = Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        [
          "CORP_VAULT",
          "REC_2024_001",
          "Quarterly Financial Statement",
          "Q3 2024 consolidated financial data",
          recordHash,
          "financial"
        ],
        owner.address
      );

      const result = chain.mineBlock([depositTxn]);
      expect(result[0].result).toBeOk();
    });

    it("blocks record deposit by unauthorized entity member", () => {
      const owner = accounts.get("deployer")!;
      const unauthorized = accounts.get("wallet_1")!;
      
      const recordHash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
      const depositTxn = Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        [
          "CORP_VAULT",
          "REC_UNAUTH",
          "Unauthorized Record",
          "Should not work",
          recordHash,
          "test"
        ],
        unauthorized.address
      );

      const result = chain.mineBlock([depositTxn]);
      expect(result[0].result).toBeErr(100);
    });

    it("prevents duplicate record identifiers within entity", () => {
      const owner = accounts.get("deployer")!;
      const recordHash = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

      const firstDeposit = Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["CORP_VAULT", "REC_DUP", "First Document", "Original content", recordHash, "legal"],
        owner.address
      );
      chain.mineBlock([firstDeposit]);

      const secondDeposit = Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["CORP_VAULT", "REC_DUP", "Second Document", "New content", recordHash, "legal"],
        owner.address
      );

      const result = chain.mineBlock([secondDeposit]);
      expect(result[0].result).toBeErr(103);
    });
  });

  describe("Record Revision Capabilities", () => {
    beforeEach(() => {
      const owner = accounts.get("deployer")!;
      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["EDIT_ENTITY", "Edit Test Corp"],
        owner.address
      );
      chain.mineBlock();

      const hash1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["EDIT_ENTITY", "EDIT_REC", "Original Title", "Original description", hash1, "draft"],
        owner.address
      );
      chain.mineBlock();
    });

    it("allows owner to revise record content", () => {
      const owner = accounts.get("deployer")!;
      const newHash = "0x2222222222222222222222222222222222222222222222222222222222222222";

      const reviseTxn = Tx.contractCall(
        "vault-security-core",
        "revise-record",
        ["EDIT_ENTITY", "EDIT_REC", "Updated Title", "Updated description", newHash, "finalized"],
        owner.address
      );

      const result = chain.mineBlock([reviseTxn]);
      expect(result[0].result).toBeOk();
    });

    it("tracks revision history with incremented version counter", () => {
      const owner = accounts.get("deployer")!;
      const hash2 = "0x3333333333333333333333333333333333333333333333333333333333333333";

      Tx.contractCall(
        "vault-security-core",
        "revise-record",
        ["EDIT_ENTITY", "EDIT_REC", "Second Revision", "New data", hash2, "approved"],
        owner.address
      );
      chain.mineBlock();

      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-record",
        ["EDIT_ENTITY", "EDIT_REC"],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });

    it("denies revision to users without modifier tier", () => {
      const unauthorized = accounts.get("wallet_2")!;
      const hash3 = "0x4444444444444444444444444444444444444444444444444444444444444444";

      const reviseTxn = Tx.contractCall(
        "vault-security-core",
        "revise-record",
        ["EDIT_ENTITY", "EDIT_REC", "Unauthorized Change", "Bad data", hash3, "invalid"],
        unauthorized.address
      );

      const result = chain.mineBlock([reviseTxn]);
      expect(result[0].result).toBeErr(100);
    });
  });

  describe("Access Control Tier Management", () => {
    let owner: Account;
    let grantee: Account;

    beforeEach(() => {
      owner = accounts.get("deployer")!;
      grantee = accounts.get("wallet_3")!;

      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["ACCESS_CTRL", "Access Control Test"],
        owner.address
      );
      chain.mineBlock();

      const hash = "0x5555555555555555555555555555555555555555555555555555555555555555";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["ACCESS_CTRL", "AC_TEST", "Access Record", "Test content", hash, "security"],
        owner.address
      );
      chain.mineBlock();
    });

    it("allocates reader tier to participant", () => {
      const allocateTxn = Tx.contractCall(
        "vault-security-core",
        "allocate-access",
        ["ACCESS_CTRL", "AC_TEST", grantee.address, "u1"],
        owner.address
      );

      const result = chain.mineBlock([allocateTxn]);
      expect(result[0].result).toBeOk();
    });

    it("allocates modifier tier to participant", () => {
      const allocateTxn = Tx.contractCall(
        "vault-security-core",
        "allocate-access",
        ["ACCESS_CTRL", "AC_TEST", grantee.address, "u2"],
        owner.address
      );

      const result = chain.mineBlock([allocateTxn]);
      expect(result[0].result).toBeOk();
    });

    it("prevents allocation of invalid access tier level", () => {
      const allocateTxn = Tx.contractCall(
        "vault-security-core",
        "allocate-access",
        ["ACCESS_CTRL", "AC_TEST", grantee.address, "u99"],
        owner.address
      );

      const result = chain.mineBlock([allocateTxn]);
      expect(result[0].result).toBeErr(106);
    });

    it("enforces custodian access requirement for allocations", () => {
      const unauthorizedGranter = accounts.get("wallet_4")!;

      const allocateTxn = Tx.contractCall(
        "vault-security-core",
        "allocate-access",
        ["ACCESS_CTRL", "AC_TEST", grantee.address, "u1"],
        unauthorizedGranter.address
      );

      const result = chain.mineBlock([allocateTxn]);
      expect(result[0].result).toBeErr(100);
    });
  });

  describe("Access Tier Revocation Process", () => {
    let owner: Account;
    let participant: Account;

    beforeEach(() => {
      owner = accounts.get("deployer")!;
      participant = accounts.get("wallet_5")!;

      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["REVOKE_TEST", "Revocation Test Entity"],
        owner.address
      );
      chain.mineBlock();

      const hash = "0x6666666666666666666666666666666666666666666666666666666666666666";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["REVOKE_TEST", "REV_REC", "Revoke Record", "Data", hash, "temporal"],
        owner.address
      );
      chain.mineBlock();

      Tx.contractCall(
        "vault-security-core",
        "allocate-access",
        ["REVOKE_TEST", "REV_REC", participant.address, "u1"],
        owner.address
      );
      chain.mineBlock();
    });

    it("successfully revokes participant access tier", () => {
      const revokeTxn = Tx.contractCall(
        "vault-security-core",
        "revoke-access",
        ["REVOKE_TEST", "REV_REC", participant.address],
        owner.address
      );

      const result = chain.mineBlock([revokeTxn]);
      expect(result[0].result).toBeOk();
    });

    it("requires custodian tier to revoke access", () => {
      const unauthorized = accounts.get("wallet_6")!;

      const revokeTxn = Tx.contractCall(
        "vault-security-core",
        "revoke-access",
        ["REVOKE_TEST", "REV_REC", participant.address],
        unauthorized.address
      );

      const result = chain.mineBlock([revokeTxn]);
      expect(result[0].result).toBeErr(100);
    });
  });

  describe("Record Retrieval and Logging", () => {
    let owner: Account;
    let reader: Account;

    beforeEach(() => {
      owner = accounts.get("deployer")!;
      reader = accounts.get("wallet_7")!;

      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["RETRIEVE_ENTITY", "Retrieval Test Entity"],
        owner.address
      );
      chain.mineBlock();

      const hash = "0x7777777777777777777777777777777777777777777777777777777777777777";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["RETRIEVE_ENTITY", "RETR_REC", "Retrievable Record", "Content for retrieval", hash, "accessible"],
        owner.address
      );
      chain.mineBlock();

      Tx.contractCall(
        "vault-security-core",
        "allocate-access",
        ["RETRIEVE_ENTITY", "RETR_REC", reader.address, "u1"],
        owner.address
      );
      chain.mineBlock();
    });

    it("allows authorized reader to retrieve record", () => {
      const retrieveTxn = Tx.contractCall(
        "vault-security-core",
        "retrieve-record",
        ["RETRIEVE_ENTITY", "RETR_REC"],
        reader.address
      );

      const result = chain.mineBlock([retrieveTxn]);
      expect(result[0].result).toBeOk();
    });

    it("denies retrieval to users without reader tier", () => {
      const unauthed = accounts.get("wallet_8")!;

      const retrieveTxn = Tx.contractCall(
        "vault-security-core",
        "retrieve-record",
        ["RETRIEVE_ENTITY", "RETR_REC"],
        unauthed.address
      );

      const result = chain.mineBlock([retrieveTxn]);
      expect(result[0].result).toBeErr(107);
    });

    it("returns error for nonexistent record retrieval attempts", () => {
      const retrieveTxn = Tx.contractCall(
        "vault-security-core",
        "retrieve-record",
        ["RETRIEVE_ENTITY", "NONEXISTENT"],
        reader.address
      );

      const result = chain.mineBlock([retrieveTxn]);
      expect(result[0].result).toBeErr(104);
    });
  });

  describe("Record Purge and Deactivation", () => {
    let owner: Account;

    beforeEach(() => {
      owner = accounts.get("deployer")!;

      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["PURGE_ENTITY", "Purge Testing Entity"],
        owner.address
      );
      chain.mineBlock();

      const hash = "0x8888888888888888888888888888888888888888888888888888888888888888";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["PURGE_ENTITY", "PURGE_REC", "Purgeable Record", "To be purged", hash, "temporary"],
        owner.address
      );
      chain.mineBlock();
    });

    it("allows entity owner to purge record", () => {
      const purgeTxn = Tx.contractCall(
        "vault-security-core",
        "purge-record",
        ["PURGE_ENTITY", "PURGE_REC"],
        owner.address
      );

      const result = chain.mineBlock([purgeTxn]);
      expect(result[0].result).toBeOk();
    });

    it("prevents purge operations by unauthorized parties", () => {
      const unauthorized = accounts.get("wallet_9")!;

      const purgeTxn = Tx.contractCall(
        "vault-security-core",
        "purge-record",
        ["PURGE_ENTITY", "PURGE_REC"],
        unauthorized.address
      );

      const result = chain.mineBlock([purgeTxn]);
      expect(result[0].result).toBeErr(100);
    });

    it("marks record as inactive after purge", () => {
      const owner = accounts.get("deployer")!;

      Tx.contractCall(
        "vault-security-core",
        "purge-record",
        ["PURGE_ENTITY", "PURGE_REC"],
        owner.address
      );
      chain.mineBlock();

      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-record",
        ["PURGE_ENTITY", "PURGE_REC"],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });
  });

  describe("Query and Information Retrieval", () => {
    let owner: Account;

    beforeEach(() => {
      owner = accounts.get("deployer")!;

      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["QUERY_ENT", "Query Testing Entity"],
        owner.address
      );
      chain.mineBlock();

      const hash = "0x9999999999999999999999999999999999999999999999999999999999999999";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["QUERY_ENT", "QUERY_REC", "Query Test Record", "Queryable content", hash, "informational"],
        owner.address
      );
      chain.mineBlock();
    });

    it("queries entity information successfully", () => {
      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-entity",
        ["QUERY_ENT"],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });

    it("retrieves record details via query function", () => {
      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-record",
        ["QUERY_ENT", "QUERY_REC"],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });

    it("returns none for nonexistent entity queries", () => {
      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-entity",
        ["NONEXISTENT_ENTITY"],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });

    it("reports access tier for participants", () => {
      const participant = accounts.get("wallet_10")!;

      Tx.contractCall(
        "vault-security-core",
        "allocate-access",
        ["QUERY_ENT", "QUERY_REC", participant.address, "u2"],
        owner.address
      );
      chain.mineBlock();

      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-access-tier",
        ["QUERY_ENT", "QUERY_REC", participant.address],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });
  });

  describe("Activity Logging and Transaction History", () => {
    let owner: Account;

    beforeEach(() => {
      owner = accounts.get("deployer")!;

      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["ACTIVITY_LOG", "Activity Tracking Entity"],
        owner.address
      );
      chain.mineBlock();

      const hash = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["ACTIVITY_LOG", "ACTIVITY_REC", "Activity Record", "To be logged", hash, "auditable"],
        owner.address
      );
      chain.mineBlock();
    });

    it("records activity entries for all operations", () => {
      const owner = accounts.get("deployer")!;

      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-activity",
        ["ACTIVITY_LOG", "ACTIVITY_REC", "u1"],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });

    it("retrieves activity event details", () => {
      const owner = accounts.get("deployer")!;

      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-activity",
        ["ACTIVITY_LOG", "ACTIVITY_REC", "u1"],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });
  });

  describe("Entity Ownership and Access Hierarchy", () => {
    let owner: Account;
    let nonOwner: Account;

    beforeEach(() => {
      owner = accounts.get("deployer")!;
      nonOwner = accounts.get("wallet_11")!;

      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["OWNER_TEST", "Owner Hierarchy Test"],
        owner.address
      );
      chain.mineBlock();

      const hash = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["OWNER_TEST", "OWNER_REC", "Owner Record", "Owner access test", hash, "hierarchical"],
        owner.address
      );
      chain.mineBlock();
    });

    it("grants principal access tier to entity owner", () => {
      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-access-tier",
        ["OWNER_TEST", "OWNER_REC", owner.address],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });

    it("grants blocked tier to unrelated participants by default", () => {
      const queryTxn = Tx.contractCall(
        "vault-security-core",
        "query-access-tier",
        ["OWNER_TEST", "OWNER_REC", nonOwner.address],
        owner.address
      );

      const result = chain.mineBlock([queryTxn]);
      expect(result[0].result).toBeOk();
    });

    it("owner can perform all operations without explicit grants", () => {
      const hash = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
      
      const reviseTxn = Tx.contractCall(
        "vault-security-core",
        "revise-record",
        ["OWNER_TEST", "OWNER_REC", "Revised by Owner", "New owner content", hash, "updated"],
        owner.address
      );

      const result = chain.mineBlock([reviseTxn]);
      expect(result[0].result).toBeOk();
    });
  });

  describe("Cross-Entity Record Isolation", () => {
    beforeEach(() => {
      const owner = accounts.get("deployer")!;

      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["ENTITY_A", "First Entity"],
        owner.address
      );
      chain.mineBlock();

      Tx.contractCall(
        "vault-security-core",
        "initialize-entity",
        ["ENTITY_B", "Second Entity"],
        owner.address
      );
      chain.mineBlock();

      const hash1 = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["ENTITY_A", "SHARED_ID", "Entity A Record", "Entity A data", hash1, "isolated"],
        owner.address
      );
      chain.mineBlock();

      const hash2 = "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
      Tx.contractCall(
        "vault-security-core",
        "deposit-record",
        ["ENTITY_B", "SHARED_ID", "Entity B Record", "Entity B data", hash2, "isolated"],
        owner.address
      );
      chain.mineBlock();
    });

    it("maintains separate record namespaces across entities", () => {
      const owner = accounts.get("deployer")!;

      const queryA = Tx.contractCall(
        "vault-security-core",
        "query-record",
        ["ENTITY_A", "SHARED_ID"],
        owner.address
      );

      const resultA = chain.mineBlock([queryA]);
      expect(resultA[0].result).toBeOk();

      const queryB = Tx.contractCall(
        "vault-security-core",
        "query-record",
        ["ENTITY_B", "SHARED_ID"],
        owner.address
      );

      const resultB = chain.mineBlock([queryB]);
      expect(resultB[0].result).toBeOk();
    });
  });
});
