//! The alloy adapter against a real HTTP JSON-RPC server (Epic E).
//!
//! Unit tests use `FakeChain`, which never touches the node's wire format. This
//! test serves canned responses in the exact shapes geth-compatible nodes
//! return, so request encoding (by-hash block ids, full transactions),
//! response decoding, and failure classification and retry are all exercised
//! through `AlloyArchiveRpc` itself.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use alloy_primitives::{address, b256, Address, Bytes, B256};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chain_enrich::decode::{TRANSFER_TOPIC, V2_SWAP_TOPIC};
use chain_enrich::{AlloyArchiveRpc, ArchiveRpc, CallOutcome, RpcError, StateAt};
use resilience::Backoff;
use serde_json::{json, Value};

const BLOCK: B256 = b256!("1111111111111111111111111111111111111111111111111111111111111111");
const PARENT: B256 = b256!("2222222222222222222222222222222222222222222222222222222222222222");
const TX: B256 = b256!("3333333333333333333333333333333333333333333333333333333333333333");
const FROM: Address = address!("00000000000000000000000000000000000000a1");
const TO: Address = address!("00000000000000000000000000000000000000b2");
const TOKEN: Address = address!("00000000000000000000000000000000000000c3");
const ZERO32: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// What the server should do with the next `eth_call`s, in order; once the
/// script is empty, calls return a 32-byte `18`.
#[derive(Clone)]
enum Scripted {
    Http(StatusCode),
    Error(i64, &'static str),
}

#[derive(Default)]
struct Server {
    requests: Mutex<Vec<Value>>,
    script: Mutex<Vec<Scripted>>,
}

fn bloom() -> String {
    format!("0x{}", "00".repeat(256))
}

fn block_json() -> Value {
    json!({
        "hash": BLOCK, "parentHash": PARENT,
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "miner": Address::ZERO, "stateRoot": ZERO32, "transactionsRoot": ZERO32,
        "receiptsRoot": ZERO32, "logsBloom": bloom(), "difficulty": "0x0",
        "number": "0x121eac0", "gasLimit": "0x1c9c380", "gasUsed": "0x5208",
        "timestamp": "0x6553f100", "extraData": "0x", "mixHash": ZERO32,
        "nonce": "0x0000000000000000", "baseFeePerGas": "0x1", "size": "0x220",
        "uncles": [],
        "transactions": [{
            "type": "0x0", "chainId": "0x1", "nonce": "0x7", "gasPrice": "0x4a817c800",
            "gas": "0x30d40", "to": TO, "value": "0x0", "input": "0x",
            "v": "0x25",
            "r": "0x1b5e176d927f8e9ab405058b2d2457392da3e20f328b16ddabcebc33eaac5fea",
            "s": "0x4ba69724e8f69de52f0125ad8b3c5c2cef33019bac3249e2c0a2192766d1721c",
            "hash": TX, "blockHash": BLOCK, "blockNumber": "0x121eac0",
            "transactionIndex": "0x0", "from": FROM
        }]
    })
}

fn receipts_json() -> Value {
    let amount = format!("0x{:064x}", 5u64);
    let swap = format!("0x{}", format!("{:064x}", 1u64).repeat(4));
    let log = |index: &str, topics: Value, data: &str| {
        json!({
            "address": TOKEN, "topics": topics, "data": data,
            "blockNumber": "0x121eac0", "transactionHash": TX, "transactionIndex": "0x0",
            "blockHash": BLOCK, "logIndex": index, "removed": false
        })
    };
    json!([{
        "type": "0x0", "status": "0x1", "cumulativeGasUsed": "0x1d4c0",
        "logs": [
            log("0x0", json!([TRANSFER_TOPIC, FROM.into_word(), TO.into_word()]), &amount),
            log("0x1", json!([V2_SWAP_TOPIC, FROM.into_word(), TO.into_word()]), &swap),
        ],
        "logsBloom": bloom(), "transactionHash": TX, "transactionIndex": "0x0",
        "blockHash": BLOCK, "blockNumber": "0x121eac0", "gasUsed": "0x1d4c0",
        "effectiveGasPrice": "0x4a817c800", "from": FROM, "to": TO,
        "contractAddress": null
    }])
}

async fn rpc(State(server): State<Arc<Server>>, Json(request): Json<Value>) -> Response {
    server.requests.lock().unwrap().push(request.clone());
    let id = request["id"].clone();
    let ok =
        |result: Value| Json(json!({"jsonrpc": "2.0", "id": id, "result": result})).into_response();
    match request["method"].as_str().unwrap_or_default() {
        "eth_chainId" => ok(json!("0x1")),
        "eth_getBlockByHash" if request["params"][0] == json!(BLOCK) => ok(block_json()),
        "eth_getBlockByHash" => ok(Value::Null),
        "eth_getBlockReceipts" => ok(receipts_json()),
        "eth_call" => {
            let next = {
                let mut script = server.script.lock().unwrap();
                (!script.is_empty()).then(|| script.remove(0))
            };
            match next {
                None => ok(json!(format!("0x{:064x}", 18))),
                Some(Scripted::Http(status)) => (status, "busy").into_response(),
                Some(Scripted::Error(code, message)) => Json(json!({
                    "jsonrpc": "2.0", "id": id,
                    "error": {"code": code, "message": message}
                }))
                .into_response(),
            }
        }
        other => panic!("unexpected method {other}"),
    }
}

async fn serve(script: Vec<Scripted>) -> (AlloyArchiveRpc, Arc<Server>) {
    let server = Arc::new(Server {
        script: Mutex::new(script),
        ..Server::default()
    });
    let app = Router::new()
        .route("/", post(rpc))
        .with_state(Arc::clone(&server));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = AlloyArchiveRpc::new(url.parse().unwrap(), Duration::from_secs(5)).with_backoff(
        Backoff::new(
            Duration::from_millis(1),
            Duration::from_millis(1),
            Duration::from_millis(1),
            3,
        )
        .without_jitter(),
    );
    (client, server)
}

fn calls(server: &Server) -> Vec<Value> {
    server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["method"] == "eth_call")
        .cloned()
        .collect()
}

fn decimals() -> Bytes {
    Bytes::from_static(&[0x31, 0x3c, 0xe5, 0x67])
}

#[tokio::test]
async fn blocks_and_receipts_decode_from_the_node_wire_format() {
    let (rpc, server) = serve(Vec::new()).await;
    assert_eq!(rpc.chain_id().await.unwrap(), 1);

    let block = rpc.block(BLOCK).await.unwrap().expect("known block");
    assert_eq!(
        (block.number, block.hash, block.parent_hash),
        (0x121eac0, BLOCK, PARENT)
    );
    assert_eq!(block.timestamp, 0x6553f100);
    assert_eq!(block.txs.len(), 1);
    assert_eq!(
        (block.txs[0].hash, block.txs[0].from, block.txs[0].to),
        (TX, FROM, Some(TO))
    );

    let receipts = rpc.receipts(BLOCK).await.unwrap().expect("receipts");
    assert_eq!(receipts.len(), 1);
    let r = &receipts[0];
    assert!(r.success);
    assert_eq!((r.gas_used, r.effective_gas_price), (0x1d4c0, 0x4a817c800));
    assert_eq!(r.logs.len(), 2);
    assert_eq!(r.logs[0].topics[0], TRANSFER_TOPIC);
    assert_eq!(r.logs[1].data.len(), 128);

    assert!(rpc.block(B256::repeat_byte(9)).await.unwrap().is_none());

    // The block was asked for with full transactions.
    let requests = server.requests.lock().unwrap();
    let get_block = requests
        .iter()
        .find(|r| r["method"] == "eth_getBlockByHash")
        .unwrap();
    assert_eq!(get_block["params"][1], json!(true));
}

#[tokio::test]
async fn calls_read_state_by_block_hash() {
    let (rpc, server) = serve(Vec::new()).await;
    let outcome = rpc
        .call(TOKEN, decimals(), StateAt::Block(BLOCK))
        .await
        .unwrap();
    let CallOutcome::Returned(bytes) = outcome else {
        panic!("expected a return, got {outcome:?}");
    };
    assert_eq!(bytes[31], 18);

    let call = &calls(&server)[0];
    assert_eq!(call["params"][0]["to"], json!(TOKEN));
    // A hash, never a number: a reorg cannot answer from a sibling block.
    assert_eq!(call["params"][1]["blockHash"], json!(BLOCK), "{call}");
}

#[tokio::test]
async fn a_revert_is_an_answer_and_is_not_retried() {
    let (rpc, server) = serve(vec![Scripted::Error(3, "execution reverted")]).await;
    let outcome = rpc.call(TOKEN, decimals(), StateAt::Latest).await.unwrap();
    assert_eq!(outcome, CallOutcome::Reverted);
    assert_eq!(calls(&server).len(), 1);

    let (rpc, _) = serve(vec![Scripted::Error(-32000, "execution reverted")]).await;
    assert_eq!(
        rpc.call(TOKEN, decimals(), StateAt::Latest).await.unwrap(),
        CallOutcome::Reverted
    );
}

#[tokio::test]
async fn a_pruned_node_is_named_and_not_retried() {
    let (rpc, server) = serve(vec![Scripted::Error(
        -32000,
        "missing trie node 5e3a... (path ) state 0x... is not available",
    )])
    .await;
    let err = rpc
        .call(TOKEN, decimals(), StateAt::Block(BLOCK))
        .await
        .unwrap_err();
    assert!(matches!(err, RpcError::NotArchive { .. }), "{err}");
    assert_eq!(calls(&server).len(), 1);
}

#[tokio::test]
async fn rate_limits_and_server_errors_are_retried_within_budget() {
    let (rpc, server) = serve(vec![
        Scripted::Http(StatusCode::TOO_MANY_REQUESTS),
        Scripted::Http(StatusCode::BAD_GATEWAY),
    ])
    .await;
    assert!(matches!(
        rpc.call(TOKEN, decimals(), StateAt::Latest).await.unwrap(),
        CallOutcome::Returned(_)
    ));
    assert_eq!(calls(&server).len(), 3);

    let (rpc, server) = serve(vec![Scripted::Http(StatusCode::SERVICE_UNAVAILABLE); 5]).await;
    let err = rpc
        .call(TOKEN, decimals(), StateAt::Latest)
        .await
        .unwrap_err();
    assert!(err.is_transient(), "{err}");
    assert_eq!(calls(&server).len(), 3, "the attempt budget is 3");
}

#[tokio::test]
async fn a_rejected_credential_fails_at_once() {
    let (rpc, server) = serve(vec![Scripted::Http(StatusCode::UNAUTHORIZED)]).await;
    let err = rpc
        .call(TOKEN, decimals(), StateAt::Latest)
        .await
        .unwrap_err();
    assert!(matches!(err, RpcError::Permanent { .. }), "{err}");
    assert_eq!(calls(&server).len(), 1);
}

#[tokio::test]
async fn the_endpoint_never_appears_in_debug_output() {
    let rpc = AlloyArchiveRpc::new(
        "https://eth.example/v2/SECRET-KEY".parse().unwrap(),
        Duration::from_secs(1),
    );
    assert!(!format!("{rpc:?}").contains("SECRET-KEY"));
}
