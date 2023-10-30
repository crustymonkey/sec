extern crate chrono;
#[macro_use]
extern crate log;

mod lib;

use anyhow::Result;
use clap::{Parser, Subcommand};
use lib::crypto::{
    self,
    decrypt_w_iv,
    encrypt_w_iv,
    gen_iv,
    get_iv_from_enc,
    IV_LEN,
};
use rpassword::prompt_password;
use std::fs::{File, metadata};
use std::io::{stdin, stdout, Read, Write, BufReader, BufRead};

const BUF_SIZE: usize = 4096;

#[derive(Subcommand)]
enum Commands {
    /// Encrypt the given file
    Enc {
        #[clap(help = "Specify the file to read from. If '-', will read from \
            stdin")]
        infile: String,
        #[clap(
            short,
            long,
            default_value = "-",
            help = "Specify the file to write the output to. \
            If not specified or is '-', the output will be written to \
            stdout"
        )]
        outfile: String,
        #[clap(short, long, help="Show a progress bar while encrypting")]
        progress: bool,
    },
    /// Decrypt the given file
    Dec {
        #[clap(help = "Specify the file to read from. If '-', will read from \
            stdin")]
        infile: String,
        #[clap(
            short,
            long,
            default_value = "-",
            help = "Specify the file to write the output to. \
            If not specified or is '-', the output will be written to \
            stdout"
        )]
        outfile: String,
        #[clap(short, long, help="Show a progress bar while decrypting")]
        progress: bool,
    },
}

#[derive(Parser)]
#[clap(author="Jay Deiman", version, about="", long_about=None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
    #[clap(short = 'D', long)]
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

fn encrypt(
    passphrase: String,
    infile: &str,
    outfile: &str,
    progress: &bool,
) -> Result<()> {
    let key = passphrase.as_bytes();
    let iv = gen_iv();
    let mut buf = [0_u8; BUF_SIZE];
    let inf: Box<dyn Read>;
    let mut outf: Box<dyn Write>;
    let mut inf_size: u64 = BUF_SIZE as u64 + 1;

    if infile == "-" {
        inf = Box::new(stdin());
    } else {
        inf = Box::new(File::open(infile)?);
        inf_size = metadata(infile).unwrap().len();
    }

    if outfile == "-" {
        outf = Box::new(stdout());
    } else {
        outf = Box::new(File::create(outfile)?);
    }

    let mut reader = BufReader::new(inf);
    let mut lcount: u64 = 0;

    loop {
        let count = reader.read(&mut buf)?;
        if count == 0 {
            break;
        }

        let encrypted: Vec<u8>;
        if lcount == 0 {
            encrypted = encrypt_w_iv(&buf[..count], key, &iv)?;
        } else {
            encrypted = crypto::encrypt(&buf[..count], key, &iv)?;
        }

        outf.write(&encrypted)?;
        lcount += 1;
    }

    outf.flush()?;

    return Ok(());
}

fn decrypt(
    passphrase: String,
    infile: &str,
    outfile: &str,
    progress: &bool,
) -> Result<()> {
    let key = passphrase.as_bytes();

    let mut buf = [0_u8; BUF_SIZE];
    let mut bclone = [0_u8; BUF_SIZE];
    let inf: Box<dyn Read>;
    let mut outf: Box<dyn Write>;
    let mut inf_size: u64 = BUF_SIZE as u64 + 1;

    if infile == "-" {
        inf = Box::new(stdin());
    } else {
        inf = Box::new(File::open(infile)?);
        inf_size = metadata(infile).unwrap().len();
    }

    if outfile == "-" {
        outf = Box::new(stdout());
    } else {
        outf = Box::new(File::create(outfile)?);
    }

    let mut reader = BufReader::new(inf);
    let mut lcount: u64 = 0;
    let mut iv: &[u8] = &[0_u8; IV_LEN];

    loop {
        let count = reader.read(&mut buf)?;
        if count == 0 {
            break;
        }

        if lcount == 0 {
            // We have to extract the IV on the first part of the loop
            bclone = buf.clone();
            let res = get_iv_from_enc(&bclone[..count]);
            // Set the iv value here;
            iv = res.0;

            let decrypted = crypto::decrypt(res.1, key, iv)?;

            outf.write(&decrypted)?;
        } else {
            let decrypted = crypto::decrypt(&buf[..count], key, iv)?;

            outf.write(&decrypted)?;
        }

        lcount += 1
    }

    outf.flush().expect("Failed to flush the buffer");

    return Ok(());
}

fn main() {
    let args = get_args();
    setup_logging(&args);

    match &args.command {
        Commands::Enc { infile, outfile, progress } => {
            //let passphrase = get_pass(true);
            let passphrase = "test".to_string();
            encrypt(passphrase, infile, outfile, progress).unwrap();
        }
        Commands::Dec { infile, outfile, progress } => {
            //let passphrase = get_pass(false);
            let passphrase = "test".to_string();
            match decrypt(passphrase, infile, outfile, progress) {
                Ok(_) => println!("OK"),
                Err(e) => println!("Error: {e}"),
            };
        }
    }
}
