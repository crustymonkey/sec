extern crate chrono;
#[macro_use] extern crate log;

mod lib;

use anyhow::Result;
use clap::{Parser, Subcommand};
use lib::crypto::{gen_iv, encrypt_w_iv, decrypt_w_iv};
use rpassword::prompt_password;
use std::fs::File;
use std::io::{Read, stdin, stdout, Write};

#[derive(Subcommand)]
enum Commands {
    /// Encrypt the given file
    Enc {
        #[clap(help="Specify the file to read from. If '-', will read from \
            stdin")]
        infile: String,
        #[clap(short, long, default_value="-",
            help="Specify the file to write the output to. \
            If not specified or is '-', the output will be written to \
            stdout")]
        outfile: String,
    },
    /// Decrypt the given file
    Dec {
        #[clap(help="Specify the file to read from. If '-', will read from \
            stdin")]
        infile: String,
        #[clap(short, long, default_value="-",
            help="Specify the file to write the output to. \
            If not specified or is '-', the output will be written to \
            stdout")]
        outfile: String,
    }
}

#[derive(Parser)]
#[clap(author="Jay Deiman", version, about="", long_about=None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
    #[clap(short='D', long)]
    debug: bool,
}

static LOGGER: GlobalLogger = GlobalLogger;

struct GlobalLogger;

/// This implements the logging to stderr from the `log` crate
impl log::Log for GlobalLogger {
    fn enabled(&self, meta: &log::Metadata) -> bool {
        return meta.level() <= log::max_level();
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let d = chrono::Local::now();
            eprintln!(
                "{} - {} - {}:{} {} - {}",
                d.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                record.level(),
                record.file().unwrap(),
                record.line().unwrap(),
                record.target(),
                record.args(),
            );
        }
    }

    fn flush(&self) {}
}

/// Create a set of CLI args via the `clap` crate and return the matches
fn get_args() -> Args {
    return Args::parse();
}

/// Set the global logger from the `log` crate
fn setup_logging(args: &Args) {
    let l = if args.debug {
        log::LevelFilter::Debug
    } else {
        log::LevelFilter::Info
    };

    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(l);
}

fn get_pass(double_check: bool) -> String {
    let mut ret: String;
    loop {
        ret = prompt_password("Passphrase: ").unwrap();
        if double_check {
            let verify = prompt_password("Passphrase again: ").unwrap();
            if verify == ret {
                break;
            }
            println!("Passphrases did not match, try again");
        } else {
            break;
        }
    }

    return ret;
}

fn read_file(f: &str) -> Result<Vec<u8>> {
    let mut ret: Vec<u8> = vec![];
    if f == "-" {
        // Read from stdin
        let n = stdin().read_to_end(&mut ret)?;
        debug!("Read {} bytes from stdin", n);
        return Ok(ret);
    } 

    let mut file = File::open(f)?;
    let n = file.read_to_end(&mut ret)?;
    debug!("Read {} bytes from {}", n, f);

    return Ok(ret);
}

fn write_file(content: &[u8], f: &str) -> Result<()> {
    if f == "-" {
        stdout().write_all(content)?;
        return Ok(());
    }

    let mut file = File::create(f)?;
    file.write_all(content)?;
    file.flush()?;
    
    return Ok(());
}

fn encrypt(passphrase: String, infile: &str, outfile: &str) {
    let key = passphrase.as_bytes();
    let iv = gen_iv();

    let contents = read_file(infile).expect(
        &format!("Failed to read from {}", infile));
    
    let encrypted = encrypt_w_iv(&contents, key, &iv)
        .expect("Failed to encrypt the contents");

    write_file(&encrypted, outfile)
        .expect(&format!("Failed to write to: {}", outfile));
}

fn decrypt(passphrase: String, infile: &str, outfile: &str) {
    let key = passphrase.as_bytes();

    let contents = read_file(infile).expect(
        &format!("Failed to read from {}", infile));
    let decrypted = decrypt_w_iv(&contents, key)
        .expect("Failed to decrypt the contents");
    debug!("Got decrypted output: {}", String::from_utf8(decrypted.clone()).unwrap());
    
    write_file(&decrypted, outfile)
        .expect(&format!("Failed to write to: {}", outfile));
}

fn main() {
    let args = get_args();
    setup_logging(&args);

    match &args.command {
        Commands::Enc { infile, outfile } => {
            let passphrase = get_pass(true);
            encrypt(passphrase, infile, outfile);
        },
        Commands::Dec { infile, outfile } => {
            let passphrase = get_pass(false);
            decrypt(passphrase, infile, outfile);
        },
    }
}
