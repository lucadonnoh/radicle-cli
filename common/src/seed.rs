use std::ffi::OsString;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, Context as _, Result};
use librad::crypto::peer::PeerId;
use librad::git::Urn;
use url::{Host, Url};

use rad_terminal::args::{self, Args};

use crate::{git, project};

pub const CONFIG_SEED_KEY: &str = "rad.seed";
pub const CONFIG_PEER_KEY: &str = "rad.peer";
pub const DEFAULT_SEEDS: &[&str] = &[
    "pine.radicle.garden",
    "willow.radicle.garden",
    "maple.radicle.garden",
];
pub const DEFAULT_SEED_API_PORT: u16 = 8777;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Scope<'a> {
    Local(&'a Path),
    Global,
    Any,
}

#[derive(serde::Deserialize)]
pub struct CommitHeader {
    pub summary: String,
}

#[derive(serde::Deserialize)]
pub struct Commit {
    pub header: CommitHeader,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub host: Host,
    pub port: Option<u16>,
}

impl Address {
    /// ```
    /// use std::str::FromStr;
    /// use rad_common::seed as seed;
    ///
    /// let addr = seed::Address::from_str("willow.radicle.garden").unwrap();
    /// assert_eq!(addr.url().to_string(), "https://willow.radicle.garden/");
    ///
    /// let addr = seed::Address::from_str("localhost").unwrap();
    /// assert_eq!(addr.url().to_string(), "https://localhost/");
    ///
    /// let addr = seed::Address::from_str("127.0.0.1").unwrap();
    /// assert_eq!(addr.url().to_string(), "http://127.0.0.1/");
    /// ```
    pub fn url(&self) -> Url {
        match self.host {
            url::Host::Domain(_) => Url::parse(&format!("https://{}", self)).unwrap(),
            _ => Url::parse(&format!("http://{}", self)).unwrap(),
        }
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(port) = self.port {
            write!(f, "{}:{}", self.host, port)
        } else {
            write!(f, "{}", self.host)
        }
    }
}

impl FromStr for Address {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once(':') {
            Some((host, port)) => {
                let host = Host::parse(host)?;
                let port = Some(port.parse()?);

                Ok(Self { host, port })
            }
            None => {
                let host = Host::parse(s)?;

                Ok(Self { host, port: None })
            }
        }
    }
}

#[derive(Default, Debug, Clone)]
pub struct SeedOptions(pub Option<Address>);

impl Args for SeedOptions {
    fn from_args(args: Vec<OsString>) -> anyhow::Result<(Self, Vec<OsString>)> {
        use lexopt::prelude::*;

        let mut parser = lexopt::Parser::from_args(args);
        let mut seed: Option<Address> = None;
        let mut unparsed = Vec::new();

        while let Some(arg) = parser.next()? {
            match arg {
                Long("seed") if seed.is_none() => {
                    let value = parser.value()?;
                    let value = value.to_string_lossy();
                    let value = value.as_ref();
                    let addr =
                        Address::from_str(value).context("invalid host specified for `--seed`")?;

                    seed = Some(addr);
                }
                _ => unparsed.push(args::format(arg)),
            }
        }
        Ok((SeedOptions(seed), unparsed))
    }
}

pub fn get_seed(scope: Scope) -> Result<Url, anyhow::Error> {
    let (path, args) = match scope {
        Scope::Any => (Path::new("."), vec!["config", CONFIG_SEED_KEY]),
        Scope::Local(path) => (path, vec!["config", "--local", CONFIG_SEED_KEY]),
        Scope::Global => (Path::new("."), vec!["config", "--global", CONFIG_SEED_KEY]),
    };
    let output = git::git(path, args).context("failed to lookup seed configuration")?;
    let url =
        Url::parse(&output).context(format!("`{}` is not set to a valid URL", CONFIG_SEED_KEY))?;

    Ok(url)
}

pub fn set_seed(seed: &Url, scope: Scope) -> Result<(), anyhow::Error> {
    let seed = seed.as_str();
    let (path, args) = match scope {
        Scope::Any => (Path::new("."), vec!["config", CONFIG_SEED_KEY, seed]),
        Scope::Local(path) => (path, vec!["config", "--local", CONFIG_SEED_KEY, seed]),
        Scope::Global => (
            Path::new("."),
            vec!["config", "--global", CONFIG_SEED_KEY, seed],
        ),
    };

    git::git(path, args)
        .map(|_| ())
        .context("failed to save seed configuration")
}

pub fn set_peer_seed(seed: &Url, peer_id: &PeerId) -> Result<(), anyhow::Error> {
    let seed = seed.as_str();
    let path = Path::new(".");
    let key = format!("{}.{}.seed", CONFIG_PEER_KEY, peer_id.default_encoding());
    let args = ["config", "--local", &key, seed];

    git::git(path, args)
        .map(|_| ())
        .context("failed to save seed configuration")
}

pub fn get_peer_seed(peer_id: &PeerId) -> Result<Url, anyhow::Error> {
    let path = Path::new(".");
    let key = format!("{}.{}.seed", CONFIG_PEER_KEY, peer_id.default_encoding());
    let args = ["config", &key];

    let output = git::git(path, args).context("failed to lookup seed configuration")?;
    let url = Url::parse(&output).context(format!("`{}` is not set to a valid URL", key))?;

    Ok(url)
}

pub fn get_seed_id(mut seed: Url) -> Result<PeerId, anyhow::Error> {
    seed.set_port(Some(DEFAULT_SEED_API_PORT)).unwrap();
    seed = seed.join("/v1/peer")?;

    let agent = ureq::Agent::new();
    let obj: serde_json::Value = agent.get(seed.as_str()).call()?.into_json()?;

    let id = obj
        .get("id")
        .ok_or(anyhow!("missing 'id' in seed API response"))?
        .as_str()
        .ok_or(anyhow!("'id' is not a string"))?;
    let id = PeerId::from_default_encoding(id)?;

    Ok(id)
}

pub fn get_commit(
    mut seed: Url,
    project: &Urn,
    commit: &git2::Oid,
) -> Result<Commit, anyhow::Error> {
    seed.set_port(Some(DEFAULT_SEED_API_PORT)).unwrap();
    seed = seed.join(&format!("/v1/projects/{}/commits/{}", project, commit))?;

    let agent = ureq::Agent::new();
    let val: serde_json::Value = agent.get(seed.as_str()).call()?.into_json()?;
    let commit = serde_json::from_value(val)?;

    Ok(commit)
}

pub fn get_remotes(
    mut seed: Url,
    project: &Urn,
) -> Result<Vec<project::RemoteMetadata>, anyhow::Error> {
    seed.set_port(Some(DEFAULT_SEED_API_PORT)).unwrap();
    seed = seed.join(&format!("/v1/projects/{}/remotes", project))?;

    let agent = ureq::Agent::new();
    let val: serde_json::Value = agent.get(seed.as_str()).call()?.into_json()?;
    let response = serde_json::from_value(val)?;

    Ok(response)
}

pub fn push_delegate(
    repo: &Path,
    seed: &Url,
    delegate: &Urn,
    peer_id: PeerId,
) -> Result<String, anyhow::Error> {
    let delegate_id = delegate.encode_id();
    let url = seed.join(&delegate_id)?;

    git::git(
        repo,
        [
            "push",
            "--signed",
            url.as_str(),
            &format!(
                "refs/namespaces/{}/refs/rad/*:refs/remotes/{}/rad/*",
                delegate_id,
                peer_id.default_encoding()
            ),
        ],
    )
}

pub fn push_identity(
    repo: &Path,
    seed: &Url,
    urn: &Urn,
    peer_id: &PeerId,
) -> Result<String, anyhow::Error> {
    let id = urn.encode_id();
    let url = seed.join(&id)?;

    git::git(
        repo,
        [
            "push",
            "--signed",
            "--atomic",
            url.as_str(),
            &format!(
                "refs/namespaces/{}/refs/rad/id:refs/remotes/{}/rad/id",
                id,
                peer_id.default_encoding()
            ),
        ],
    )
}

pub fn push_refs(
    repo: &Path,
    seed: &Url,
    project: &Urn,
    peer_id: PeerId,
) -> Result<String, anyhow::Error> {
    let project_id = project.encode_id();
    let url = seed.join(&project_id)?;

    git::git(
        repo,
        [
            "push",
            "--signed",
            "--atomic",
            url.as_str(),
            &format!(
                "refs/namespaces/{}/refs/rad/ids/*:refs/remotes/{}/rad/ids/*",
                project_id, peer_id
            ),
            &format!(
                "refs/namespaces/{}/refs/rad/self:refs/remotes/{}/rad/self",
                project_id, peer_id
            ),
            &format!(
                "refs/namespaces/{}/refs/rad/signed_refs:refs/remotes/{}/rad/signed_refs",
                project_id, peer_id
            ),
            &format!(
                "+refs/namespaces/{}/refs/heads/*:refs/remotes/{}/heads/*",
                project_id, peer_id
            ),
        ],
    )
}

pub fn fetch_identity(repo: &Path, seed: &Url, urn: &Urn) -> Result<String, anyhow::Error> {
    let id = urn.encode_id();
    let url = seed.join(&id)?;

    git::git(
        repo,
        [
            "fetch",
            "--verbose",
            "--atomic",
            url.as_str(),
            &format!("refs/rad/id:refs/namespaces/{}/refs/rad/id", id),
            &format!("refs/rad/ids/*:refs/namespaces/{}/refs/rad/ids/*", id),
        ],
    )
}

pub fn fetch_peers(
    repo: &Path,
    seed: &Url,
    project: &Urn,
    remotes: impl IntoIterator<Item = PeerId>,
) -> Result<String, anyhow::Error> {
    let project_id = project.encode_id();
    let url = seed.join(&project_id)?;
    let mut args = Vec::new();

    args.extend(["fetch", "--verbose", "--force", "--atomic", url.as_str()].map(|s| s.to_string()));
    args.extend(remotes.into_iter().map(|remote| {
        format!(
            "refs/remotes/{}/*:refs/namespaces/{}/refs/remotes/{}/*",
            remote, project_id, remote
        )
    }));

    git::git(repo, args)
}
