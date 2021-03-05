import { step } from 'mocha-steps';
import * as assert from "assert";
import { GetAddressUnspentOutputsResponse, GetBlockchainInfoResponse, GrpcClient, SlpAction, SlpTransactionInfo } from "grpc-bchrpc-node";
import { PrivateKey, Networks, Transaction, Script, Address } from "bitcore-lib-cash";
import * as bchaddrjs from "bchaddrjs-slp";
import { BitcoinRpcClient } from "../src/rpc";
import { Big } from "big.js";
import * as mdm from "slp-mdm";

// setup RPC clients (used primarily for generating blocks only)
const rpcClient = require('bitcoin-rpc-promise');
const bchd2Rpc = new rpcClient('http://bitcoin:password@0.0.0.0:18334') as BitcoinRpcClient;

// setup gRPC client (used for getting info)
const bchd1Grpc = new GrpcClient({ url: "localhost:18335", rootCertPath: "./rpc.bchd1.cert", testnet: true });

// private key for the mining address (address is stored in bchd.conf)
//
// NOTE: bchd doesn't have generatetoaddress, only generate is available.
//
const privKey1 = new PrivateKey("cPgxbS8PaxXoU9qCn1AKqQzYwbRCpizbsG98xU2vZQzyZCJt4NjB", Networks.testnet);
const wallet1 = {
  _privKey: privKey1,
  address: privKey1.toAddress().toString(),
  regtestAddress: bchaddrjs.toRegtestAddress(privKey1.toAddress().toString()),
  wif: privKey1.toWIF(),
  pubKey: privKey1.toPublicKey()
};

// private key for creating transactions (a small amount separate from the mining rewards)
const privKey2 = new PrivateKey(undefined, Networks.testnet);
const wallet2 = {
  _privKey: privKey2,
  address: privKey2.toAddress().toString(),
  regtestAddress: bchaddrjs.toRegtestAddress(privKey2.toAddress().toString()),
  wif: privKey2.toWIF(),
  pubKey: privKey2.toPublicKey()
};

// private key for sending slp tokens
const privKey3 = new PrivateKey(undefined, Networks.testnet);
const wallet3 = {
  _privKey: privKey3,
  address: privKey3.toAddress().toString(),
  regtestAddress: bchaddrjs.toRegtestAddress(privKey3.toAddress().toString()),
  wif: privKey3.toWIF(),
  pubKey: privKey3.toPublicKey()
};

describe("slp gRPC API checks", () => {
  step("bchd1 ready", async (): Promise<void> => {
    const info1 = await bchd1Grpc.getBlockchainInfo();
    assert.strictEqual(info1.getBitcoinNet(), GetBlockchainInfoResponse.BitcoinNet.REGTEST);
    // console.log(`bchd1 on block ${info1.getBestHeight()}`);

    const res = await bchd2Rpc.getPeerInfo();
    assert.strictEqual(typeof res, "object");
    assert.ok(res.length === 1);

    const info2 = await bchd2Rpc.getBlockchainInfo();
    // console.log(`bchd2 on block ${info2.blocks}`);

    assert.strictEqual(info1.getBestHeight(), info2.blocks);
  });

  let resBal: GetAddressUnspentOutputsResponse;
  step("generate block to address", async () => {

    // get balance for address
    resBal = await bchd1Grpc.getAddressUtxos({ address: wallet1.regtestAddress, includeMempool: true });
    while (resBal.getOutputsList().length < 100) {
      await bchd2Rpc.generate(1);
      resBal = await bchd1Grpc.getAddressUtxos({ address: wallet1.regtestAddress, includeMempool: true });
    }
    // console.log(`${resBal.getOutputsList().length} outputs (balance: ${resBal.getOutputsList().reduce((p,c,i) => p += c.getValue() / 10**8, 0)} TBCH)`);

    assert.ok(1);
  });

  // a variable to keep track of the last unspent bch outpoint in wallet2
  let prevOutBch: { txid: string, vout: number, satoshis: number };

  // send a small amount from mining rewards to wallet2 address
  step("send to wallet2", async () => {

    // grab the last unspent coin on the mining address (the aged coin)
    // NOTE: mined outputs require 100 block aging before they can be spent
    const output = resBal.getOutputsList()[resBal.getOutputsList().length-1]!;

    // using bitcore-lib to build a transaction
    const txn = new Transaction();

    // spend the mined output
    txn.addInput(new Transaction.Input.PublicKeyHash({
      output: new Transaction.Output({
        script: Script.buildPublicKeyHashOut(new Address(wallet1.address)),
        satoshis: output.getValue()
      }),
      prevTxId: Buffer.from(output.getOutpoint()!.getHash_asU8()).reverse(),
      outputIndex: output.getOutpoint()!.getIndex(),
      script: Script.empty()
    }));

    // send to wallet2 p2pkh (less a small fee)
    const sendSatoshis = output.getValue() - 200;
    txn.addOutput(new Transaction.Output({
      script: new Script(new Address(wallet2.address)),
      satoshis: sendSatoshis
    }));

    // sign
    txn.sign(wallet1._privKey);

    // serialize
    const txnHex = txn.serialize();

    // broadcast
    const res = await bchd1Grpc.submitTransaction({ txnHex });
    assert.ok(res.getHash_asU8().length === 32);

    // store prevOut for use in the next step
    prevOutBch = {
      txid: Buffer.from(res.getHash_asU8()).reverse().toString("hex"),
      vout: 0,
      satoshis: sendSatoshis
    };

    // check gRPC server mempool
    const resTx = await bchd1Grpc.getTransaction({ hash: prevOutBch.txid, reversedHashOrder: true, includeTokenMetadata: true });

    // check token metadata
    assert.ok(resTx.getTokenMetadata() === undefined);
    assert.ok(resTx.getTransaction()!.getOutputsList()[0].getSlpToken() === undefined);
    assert.ok(resTx.getTransaction()!.getOutputsList()[0].getValue() === sendSatoshis);

    // check slp transaction info
    const info = resTx.getTransaction()!.getSlpTransactionInfo()!;
    assert.ok(info.getValidityJudgement() === SlpTransactionInfo.ValidityJudgement.UNKNOWN_OR_INVALID);
    assert.ok(info.getSlpAction() === SlpAction.NON_SLP);
  });

  let tokenMetadata: { name: string, ticker: string, decimals: number, url: string, hashHex: string };
  let prevOutSlp: { tokenId: string, txid: string, vout: number, amount: Big };

  step("SlpAction: SLP_V1_GENESIS (with baton)", async () => {

    // using bitcore-lib to build a transaction
    const txn = new Transaction();

    // add bch input
    txn.addInput(new Transaction.Input.PublicKeyHash({
      output: new Transaction.Output({
        script: Script.buildPublicKeyHashOut(new Address(wallet2.address)),
        satoshis: prevOutBch.satoshis
      }),
      prevTxId: Buffer.from(prevOutBch.txid, "hex"),
      outputIndex: prevOutBch.vout,
      script: Script.empty()
    }));

    // create genesis metadata output
    tokenMetadata = { name: "type 1 test", ticker: "t1t", decimals: 9, url: "test.com", hashHex: "" };
    const slpGenesisOpReturn = mdm.TokenType1.genesis(tokenMetadata.ticker, tokenMetadata.name, tokenMetadata.url, tokenMetadata.hashHex, tokenMetadata.decimals, 2, new mdm.BN(1337));
    txn.addOutput(new Transaction.Output({
      script: slpGenesisOpReturn,
      satoshis: 0,
    }));

    // create token output
    txn.addOutput(new Transaction.Output({
      script: new Script(new Address(wallet3.address)),
      satoshis: 546
    }));

    // create mint baton output
    txn.addOutput(new Transaction.Output({
      script: new Script(new Address(wallet3.address)),
      satoshis: 546
    }));

    // create bch change output
    txn.addOutput(new Transaction.Output({
      script: new Script(new Address(wallet2.address)),
      satoshis: prevOutBch.satoshis - 546 * 2 - 500
    }));

    // sign
    txn.sign(wallet2._privKey);

    // broadcast
    const txnHex = txn.serialize();
    const res = await bchd1Grpc.submitTransaction({ txnHex });
    assert.ok(res.getHash_asU8().length === 32);

    // store prevOutBch for use in the next step
    prevOutBch = {
      txid: Buffer.from(res.getHash_asU8()).reverse().toString("hex"),
      vout: 3,
      satoshis: prevOutBch.satoshis - 546 * 2 - 500
    };

    // store prevOutSlp for use in the next step
    // TODO

    // do gRPC server data checks
    const resTx = await bchd1Grpc.getTransaction({ hash: prevOutBch.txid, reversedHashOrder: true, includeTokenMetadata: true });

    // check token metadata
    const tm = resTx.getTokenMetadata()!.getType1()!;
    assert.ok(Buffer.from(tm.getTokenName_asU8()).toString("utf-8") === tokenMetadata.name);
    assert.ok(Buffer.from(tm.getTokenTicker_asU8()).toString("utf-8") === tokenMetadata.ticker);
    assert.ok(Buffer.from(tm.getTokenDocumentUrl_asU8()).toString("utf-8") === tokenMetadata.url);
    assert.ok(tm.getDecimals() === tokenMetadata.decimals);
    assert.ok(Buffer.from(tm.getTokenDocumentHash_asU8()).toString("hex") === tokenMetadata.hashHex);
    assert.ok(Buffer.from(resTx.getTokenMetadata()!.getTokenId_asU8()).toString("hex") === prevOutBch.txid);
    assert.ok(tm.getMintBatonVout() === 2);
    assert.ok(Buffer.from(tm.getMintBatonTxid_asU8()).reverse().toString("hex") === prevOutBch.txid);  // TODO: rename Txid tp Hash

    // check txn output slp transction info
    const info = resTx.getTransaction()!.getSlpTransactionInfo()!;
    assert.ok(Buffer.from(info.getTokenId_asU8()).toString("hex") === prevOutBch.txid);
    assert.ok(info.getValidityJudgement() === SlpTransactionInfo.ValidityJudgement.VALID);
    assert.ok(info.getSlpAction() === SlpAction.SLP_V1_GENESIS);

    // assert.ok(tx.)
    // check individual slp token input/output values

    // check minting baton

  });

  // step("submit an slp send transaction", async () => {
  //   // todo...
  //   assert.ok(0);
  // });

  // step("submit an slp mint transaction", async () => {
  //   // todo...
  //   assert.ok(0);
  // });

  // step("GetTransaction: check tokenmetadata for mempool token type 1")

  // step("GetTransaction: check tokenmetadata for mempool group nft")

  // step("GetTransaction: check tokenmetadata for mempool nft child")
});
