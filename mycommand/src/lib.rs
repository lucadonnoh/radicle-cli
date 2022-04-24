use std::ffi::OsString;

use rad_common::{keys, profile, project};
use rad_terminal::args::{Args, Error, Help};
use rad_terminal::components as term;

pub const HELP: Help = Help {
    name: "mycommand",
    description: env!("CARGO_PKG_DESCRIPTION"),
    version: env!("CARGO_PKG_VERSION"),
    usage: r#"
Usage

    rad mycommand [<option>...]

Options

    --help    Print help
"#,
};

pub struct Options {}

impl Args for Options {
    fn from_args(_args: Vec<OsString>) -> anyhow::Result<(Self, Vec<OsString>)> {
        use lexopt::prelude::*;

        let mut parser = lexopt::Parser::from_env();

        if let Some(arg) = parser.next()? {
            match arg {
                Long("help") => {
                    return Err(Error::Help.into());
                }
                _ => return Err(anyhow::anyhow!(arg.unexpected())),
            }
        }

        Ok((Options {}, vec![]))
    }
}

pub fn run(_options: Options) -> anyhow::Result<()> {
    let profile = profile::default()?;
    let sock = keys::ssh_auth_sock();
    let (_, storage) = keys::storage(&profile, sock)?;
    let projs = project::list(&storage)?;
    let mut table = term::Table::default();

    for (urn, meta, head) in projs {
        let head = head
            .map(|h| format!("{:.7}", h.to_string()))
            .unwrap_or_else(String::new);

        table.push([
            term::format::bold("blabla"),
            term::format::tertiary(urn),
            term::format::secondary(head),
            term::format::italic(meta.description),
        ]);
    }
    table.render();

    Ok(())
}
