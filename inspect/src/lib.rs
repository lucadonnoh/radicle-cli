use std::ffi::OsString;

use anyhow::anyhow;
use std::sync::Arc;
use ethers::prelude::{Address, Http, Provider, SignerMiddleware, U256, Middleware};
use ethers::prelude::builders::ContractCall;
use ethers::prelude::abigen;
use ethers::prelude::maybe;
use ethers::contract::{AbiError, Contract, ContractError};
use ethers::abi::{Abi, Detokenize, ParamType, SolStruct, AbiEncode};
use ethers::types::{U128, TransactionRequest, Bytes, Eip1559TransactionRequest};
use ethers::types::transaction::eip2718::TypedTransaction;
use ethers::signers::Signer;
use ethers::types::transaction::eip2930::AccessList;
use librad::git::identities::local::LocalIdentity;
use librad::git::Storage;

use rad_common::ethereum::{ProviderOptions, SignerOptions};
use rad_common::{ethereum, keys, person, profile, seed};
use rad_terminal::args::{Args, Error, Help};
use rad_terminal::components as term;

use crate::resolver::PublicResolver;

pub mod resolver;

pub const HELP: Help = Help {
    name: "ens",
    description: env!("CARGO_PKG_DESCRIPTION"),
    version: env!("CARGO_PKG_VERSION"),
    usage: r#"
Usage

    rad ens               [<option>...]
    rad ens --setup       [<option>...] [--rpc-url <url>] --ledger-hdpath <hd-path>
    rad ens --setup       [<option>...] [--rpc-url <url>] --keystore <file>
    rad ens --setup       [<option>...] [--rpc-url <url>] --walletconnect
    rad ens [<operation>] [<option>...]

    If no operation is specified, `--show` is implied.

Operations

    --show                       Show ENS data for your local radicle identity
    --setup [<name>]             Associate your local identity with an ENS name
    --set-local <name>           Set an ENS name for your local radicle identity

Options

    --help                       Print help

Wallet options

    --rpc-url <url>              JSON-RPC URL of Ethereum node (eg. http://localhost:8545)
    --ledger-hdpath <hdpath>     Account derivation path when using a Ledger hardware device
    --keystore <file>            Keystore file containing encrypted private key (default: none)
    --walletconnect              Use WalletConnect

Environment variables

    ETH_RPC_URL  Ethereum JSON-RPC URL (overwrite with '--rpc-url')
    ETH_HDPATH   Hardware wallet derivation path (overwrite with '--ledger-hdpath')
"#,
};

#[derive(Debug)]
pub enum Operation {
    Show,
    Setup(Option<String>),
    /*
    SetLocal(String),
    */
    DripShow,
    GiveCreate
}

#[derive(Debug)]
pub struct Options {
    pub operation: Operation,
    pub provider: ethereum::ProviderOptions,
    pub signer: ethereum::SignerOptions,
}

impl Args for Options {
    fn from_args(args: Vec<OsString>) -> anyhow::Result<(Self, Vec<OsString>)> {
        use lexopt::prelude::*;

        let parser = lexopt::Parser::from_args(args);
        let (provider, parser) = ProviderOptions::from(parser)?;
        let (signer, mut parser) = SignerOptions::from(parser)?;
        let mut operation = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Long("setup") if operation.is_none() => {
                    let val = parser.value().ok();
                    let name = if let Some(val) = val {
                        Some(
                            val.into_string()
                                .map_err(|_| anyhow!("invalid ENS name specified"))?,
                        )
                    } else {
                        None
                    };
                    operation = Some(Operation::Setup(name));
                }
                /*
                Long("set-local") if operation.is_none() => {
                    let val = parser.value().ok();
                    if let Some(name) = val {
                        operation = Some(Operation::SetLocal(
                            name.into_string()
                                .map_err(|_| anyhow!("invalid ENS name specified"))?,
                        ));
                    } else {
                        return Err(anyhow!("an ENS name must be specified"));
                    }
                }
                */
                Long("show") if operation.is_none() => {
                    operation = Some(Operation::Show);
                }
                Long("drip-show") if operation.is_none() => {
                    operation = Some(Operation::DripShow);
                }
                Long("give-create") if operation.is_none() => {
                    operation = Some(Operation::GiveCreate);
                }
                Long("help") => {
                    return Err(Error::Help.into());
                }
                _ => return Err(anyhow!(arg.unexpected())),
            }
        }

        Ok((
            Options {
                operation: operation.unwrap_or(Operation::Show),
                provider,
                signer,
            },
            vec![],
        ))
    }
}

pub fn run(options: Options) -> anyhow::Result<()> {
    let profile = profile::default()?;
    let sock = keys::ssh_auth_sock();
    let (_, storage) = keys::storage(&profile, sock)?;
    let rt = tokio::runtime::Runtime::new()?;
    let id = person::local(&storage)?;

    match options.operation {
        Operation::Show => {
            if let Some(person) = person::verify(&storage, &id.urn())? {
                term::success!("Your local identity is {}", term::format::dim(id.urn()));

                if let Some(ens) = person.payload().get_ext::<person::Ens>()? {
                    term::success!(
                        "Your local identity is associated with ENS name {}",
                        term::format::highlight(ens.name)
                    );
                } else {
                    term::warning("Your local identity is not associated with an ENS name");
                }
            }
        }
        Operation::Setup(name) => {
            term::headline(&format!(
                "Associating local 🌱 identity {} with ENS",
                term::format::highlight(&id.urn()),
            ));
            let name = term::text_input("ENS name", name)?;
            let provider = ethereum::provider(options.provider)?;
            let signer_opts = options.signer;
            let (wallet, provider) = rt.block_on(ethereum::get_wallet(signer_opts, provider))?;
            rt.block_on(setup(&name, id, provider, wallet, &storage))?;
        }
        Operation::DripShow => {
            let addr = "0x750700D592178da5762254CC5eef195415bdC55D"; //TODO: change
            let provider = ethereum::provider(options.provider)?;
            let signer_opts = options.signer;
            let (wallet, provider) = rt.block_on(ethereum::get_wallet(signer_opts, provider))?;
            rt.block_on(drip(&addr, provider, wallet, &storage))?;

        }
        Operation::GiveCreate => {
            let addr = "0x73043143e0a6418cc45d82d4505b096b802fd365"; // DaiDripsHub
            let provider = ethereum::provider(options.provider)?;
            let signer_opts = options.signer;
            let (wallet, provider) = rt.block_on(ethereum::get_wallet(signer_opts, provider))?;
            rt.block_on(give_create(&addr, provider, wallet, &storage))?;
        }
        /*
        Operation::SetLocal(name) => set_ens_payload(&name, &storage)?,
        */
        
    }

    Ok(())
}
/*
fn set_ens_payload(name: &str, storage: &Storage) -> anyhow::Result<()> {
    term::info!("Setting ENS name for local 🌱 identity");

    if term::confirm(format!(
        "Associate local identity with ENS name {}?",
        term::format::highlight(&name)
    )) {
        let doc = person::set_ens_payload(
            person::Ens {
                name: name.to_owned(),
            },
            storage,
        )?;

        term::success!("Local identity successfully updated with ENS name {}", name);
        term::blob(serde_json::to_string(&doc.payload())?);
    }
    Ok(())
}
*/

const CONTRACT_TOKEN_TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/abis/ContractTokenTemplate.json"
));

async fn drip(
    addr: &str,
    provider: Provider<Http>,
    signer: ethereum::Wallet,
    storage: &Storage,
) -> anyhow::Result<()> {
    term::info!("inspecting contract at {}", addr);
    let address = addr.parse::<Address>()?;
    let abi = serde_json::from_str::<Abi>(CONTRACT_TOKEN_TEMPLATE)?;
    let contract = Contract::new(address, abi, provider);
    let community_name: String = contract.method::<_, String>("name", ())?.call().await?;
    term::info!("community name: {}", community_name);

    let token_id: U256 = U256::one();

    let (timeMinted, amt, lastBalance, lastUpdate) = contract.method::<_, (u64, u128, u128, u64)>("nfts", token_id)?.call().await?;
    let ether_amt = amt as f64 / u128::pow(10, 18) as f64;
    term::info!("DAI streamed per second: {}", ether_amt);
    let ether_last_balance = lastBalance as f64 / u128::pow(10, 18) as f64;
    term::info!("last balance: {}", ether_last_balance);
    term::info!("last update: {}", lastUpdate);
    term::info!("time minted: {}", timeMinted);
    Ok(())
}

const DAI_DRIPS_HUB: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/abis/DaiDripsHub.json"
));

async fn give_create(
    addr: &str,
    provider: Provider<Http>,
    signer: ethereum::Wallet,
    storage: &Storage,
) -> anyhow::Result<()> {
    term::info!("sending funds to {}", addr);
    let address = addr.parse::<Address>()?;
    let abi = serde_json::from_str::<Abi>(DAI_DRIPS_HUB)?;
    //let contract = Contract::new(address, abi, provider);

    term::info!("path: {}", concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/abis/DaiDripsHub.json")
    );

    
    let amount : u128 = 10;

    abigen!(MyContract, "../abis/DaiDripsHub.json");

    let client = Arc::new(SignerMiddleware::new(provider, signer));

    //let my_contract = MyContract::new(address, client);
    //let tx_request = my_contract.give(Address::from_low_u64_be(69), amount).tx;
    //let signed_tx = signer.sign_transaction(&tx_request).await?;
    //term::info!("signed tx: {:?}", signed_tx);
    //let pending = my_contract.give(Address::from_low_u64_be(69), amount).send().await?.await?;
    
    const donnoh_addr : &str = "0x33d66941465ac776c38096cb1bc496c673ae7390";
    let bytes = GiveCall::encode(GiveCall {receiver: Address::from_low_u64_be(69), amt: amount});
    term::info!("bytes: {:?}", bytes);
    let tx = Eip1559TransactionRequest::new().to(address).from(donnoh_addr.parse::<Address>()?).data(bytes);

    let mut typed_tx = TypedTransaction::Eip1559(tx);
    client.fill_transaction(&mut typed_tx, None).await?;
    let gas_price = maybe(typed_tx.gas_price(), client.get_gas_price()).await?;
    typed_tx.set_gas(200000);
    typed_tx.set_gas_price(gas_price);
    term::info!("tx: {:?}", typed_tx);
    let signed_tx = client.sign_transaction(&typed_tx, donnoh_addr.parse::<Address>()?).await?;
    //term::info!("bytes {:?}", Bytes::from(signed_tx.to_vec()));
    //let pending_tx = client.send_raw_transaction(typed_tx.rlp_signed(1 as u64, &signed_tx)).await?;
    typed_tx.set_access_list(AccessList::from(vec![]));
    typed_tx.set_gas_price(gas_price * 2);
    let hex = typed_tx.rlp_signed(1 as u64, &signed_tx);
    term::info!("{}", format!("{:x}", hex));
    let pending_tx = client.send_raw_transaction(hex).await?;
    //let pending_tx = client.send_raw_transaction(Bytes::from(signed_tx.to_vec())).await?;
    //let pending_tx = client.send_transaction(tx, None).await?;

    
    //let paused : bool = contract.method::<_, bool>("paused", ())?.call().await?;
    //term::info!("is paused: {}", paused); // works

    /*
    let call = contract.method::<_, ()>("give", (Address::from_low_u64_be(69), amount))?; // doesn't work
    term::info!("calling give");
    let pending_tx = call.send().await?;
    let tx_hash = *pending_tx;
    term::info!("tx hash: {}", tx_hash);
    let receipt = pending_tx.confirmations(1).await?;
    */
    Ok(())
}

async fn setup(
    name: &str,
    id: LocalIdentity,
    provider: Provider<Http>,
    signer: ethereum::Wallet,
    storage: &Storage,
) -> anyhow::Result<()> {
    let urn = id.urn();
    let signer = SignerMiddleware::new(provider, signer);
    let radicle_name = name.ends_with(ethereum::RADICLE_DOMAIN);
    let resolver = match PublicResolver::get(name, signer).await {
        Ok(resolver) => resolver,
        Err(err) => {
            if let resolver::Error::NameNotFound { .. } = err {
                return Err(Error::WithHint {
                    err: err.into(),
                    hint: if radicle_name {
                        "The name must be registered with ENS to continue. Go to https://app.radicle.network/register to register."
                    } else {
                        "The name must be registered with ENS to continue. Go to https://app.ens.domains to register."
                    }
                }
                .into());
            } else {
                return Err(err.into());
            }
        }
    };

    let seed_host = if let Ok(seed_url) = seed::get_seed(seed::Scope::Any) {
        seed_url.host_str().map(|s| s.to_owned())
    } else {
        None
    };
    let seed_host = term::text_input("Seed host", seed_host)?;
    let seed_url = url::Url::parse(&format!("https://{}", seed_host))?;

    let spinner = term::spinner("Querying seed...");
    let seed_id = match seed::get_seed_id(seed_url) {
        Ok(id) => {
            spinner.clear();
            term::text_input("Seed ID", Some(id))?
        }
        Err(err) => {
            spinner.failed();
            return Err(anyhow!("error querying seed: {}", err));
        }
    };
    let address_current = resolver.address(name).await?;
    let address: Option<Address> =
        term::text_input_optional("Address", address_current.map(ethereum::hex))?;

    let github_current = resolver.text(name, "com.github").await?;
    let github: Option<String> =
        term::text_input_optional("GitHub handle", github_current.clone())?;

    let twitter_current = resolver.text(name, "com.twitter").await?;
    let twitter: Option<String> =
        term::text_input_optional("Twitter handle", twitter_current.clone())?;

    let mut calls = vec![
        resolver
            .set_text(
                name,
                resolver::RADICLE_SEED_ID_KEY,
                &seed_id.default_encoding(),
            )?
            .calldata()
            .unwrap(), // Safe because we have call data.
        resolver
            .set_text(name, resolver::RADICLE_SEED_HOST_KEY, &seed_host)?
            .calldata()
            .unwrap(),
        resolver
            .set_text(name, resolver::RADICLE_ID_KEY, &urn.to_string())?
            .calldata()
            .unwrap(),
    ];

    if let Some(address) = address {
        if address_current.map_or(true, |a| a != address) {
            calls.push(resolver.set_address(name, address)?.calldata().unwrap());
        }
    }
    if let Some(github) = github {
        if github_current.map_or(true, |g| g != github) {
            calls.push(
                resolver
                    .set_text(name, "com.github", &github)?
                    .calldata()
                    .unwrap(),
            );
        }
    }
    if let Some(twitter) = twitter {
        if twitter_current.map_or(true, |t| t != twitter) {
            calls.push(
                resolver
                    .set_text(name, "com.twitter", &twitter)?
                    .calldata()
                    .unwrap(),
            );
        }
    }

    let call = resolver.multicall(calls)?.gas(21000);
    ethereum::transaction(call).await?;

    let spinner = term::spinner("Updating local identity...");
    match person::set_ens_payload(
        person::Ens {
            name: name.to_owned(),
        },
        storage,
    ) {
        Ok(doc) => {
            spinner.finish();
            term::blob(serde_json::to_string(&doc.payload())?);
        }
        Err(err) => {
            spinner.failed();
            return Err(err);
        }
    }

    term::info!(
        "Successfully associated local 🌱 identity with {}",
        term::format::highlight(name)
    );

    term::blank();
    term::tip!("To view your profile, visit:");
    term::indented(&term::format::secondary(format!(
        "https://app.radicle.network/{}",
        name
    )));

    Ok(())
}

