extern crate chrono;
#[macro_use]
extern crate log;

mod clib;

use anyhow::Result;
use clap::{Parser, Subcommand};
use clib::crypto::{
    self,
    encrypt_w_iv,
    gen_iv,
    IV_LEN,
};
use indicatif::{ProgressBar, ProgressStyle};
use rpassword::prompt_password;
use std::fs::{File, metadata};
use std::io::{stdin, stdout, Read, Write, BufReader};

const BUF_SIZE: usize = 4096;
const GCM_SIZE: usize = 16;
const PROGESS_TPL: &str = "[{elapsed_precise}] {bytes}/{total_bytes} \
    {wide_bar:50.cyan/blue}";

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

/// This assures that the read buffer is filled to capacity before returning
/// so that the encryption/decryption alignment is correct
fn fill_buf(
    buf: &mut [u8],
    reader: &mut BufReader<Box<dyn Read>>,
) -> Result<usize> {
    let to_read = BUF_SIZE + GCM_SIZE;
    let mut overall_count = 0;
    while overall_count < to_read {
        let count = reader.read(&mut buf[overall_count..])?;
        if count == 0 {
            return Ok(overall_count);
        }
        overall_count += count;
    }

    return Ok(overall_count);
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
    let mut inf_size: u64 = 0;

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
    let mut bar: Option<ProgressBar> = None;
    if *progress {
        if inf_size == 0 {
            // Reading from stdin, use a spinner
            bar = Some(ProgressBar::new_spinner());
        } else {
            bar = Some(ProgressBar::new(inf_size));
            bar.as_mut().unwrap().set_style(
                ProgressStyle::with_template(PROGESS_TPL)
                .unwrap()
                .progress_chars("#-")
            );
        }
    }

    loop {
        let count = fill_buf(&mut buf, &mut reader)?;
        if count == 0 {
            break;
        }

        if *progress {
            bar.as_mut().unwrap().inc(count as u64);
        }

        let encrypted: Vec<u8>;
        if lcount == 0 {
            encrypted = encrypt_w_iv(&buf[..count], key, &iv)?;
        } else {
            encrypted = crypto::encrypt(&buf[..count], key, &iv)?;
        }

        debug!("Writing {} bytes", encrypted.len());
        outf.write(&encrypted)?;
        lcount += 1;
    }

    if *progress {
        bar.unwrap().finish();
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

    // We have to extract the GCM padding in addition to the actual encrypted
    // content with each read.
    let mut buf = [0_u8; BUF_SIZE + GCM_SIZE];
    let inf: Box<dyn Read>;
    let mut outf: Box<dyn Write>;
    let mut inf_size: u64 = 0;

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
    let mut iv = [0_u8; IV_LEN];
    reader.read_exact(&mut iv)?;

    let mut bar: Option<ProgressBar> = None;
    if *progress {
        if inf_size == 0 {
            // Reading from stdin, use a spinner
            bar = Some(ProgressBar::new_spinner());
        } else {
            bar = Some(ProgressBar::new(inf_size));
            bar.as_mut().unwrap().set_style(
                ProgressStyle::with_template(PROGESS_TPL)
                .unwrap()
                .progress_chars("#-")
            );
        }
    }
    if *progress {
        bar.as_mut().unwrap().inc(IV_LEN as u64);
    }

    loop {
        let count = fill_buf(&mut buf, &mut reader)?;
        //let count = reader.read(&mut buf)?;
        if count == 0 {
            break;
        }

        if *progress {
            bar.as_mut().unwrap().inc(count as u64);
        }

        debug!("Calling decrypt on {count} bytes");
        let decrypted = crypto::decrypt(&buf[..count], key, &iv)?;
        outf.write(&decrypted)?;
    }

    if *progress {
        bar.unwrap().finish();
    }

    outf.flush().expect("Failed to flush the buffer");

    return Ok(());
}

fn main() {
    let args = get_args();
    setup_logging(&args);

    match &args.command {
        Commands::Enc { infile, outfile, progress } => {
            let passphrase = get_pass(true);
            encrypt(passphrase, infile, outfile, progress).unwrap();
        }
        Commands::Dec { infile, outfile, progress } => {
            let passphrase = get_pass(false);
            match decrypt(passphrase, infile, outfile, progress) {
                Ok(_) => println!("OK"),
                Err(e) => println!("Error: {e}"),
            };
        }
    }
}
