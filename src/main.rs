use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};

use aes_gcm::Key;
use clap::{arg, command};
use rand::Rng;
use std::fs;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::io::{self, BufRead};
use typenum::U12;

// https://docs.rs/aes-gcm/latest/aes_gcm/

/*
encrypt text from   *filepath in cmdargs
                    *text in cmdargs
                    => XOR

decrypt text from   *filepath in cmdargs
                    *text in cmdargs
                    => XOR

write result to     *console output
                    *filepath explicit
                    *filepath (same as input path)

decryption and encryption XOR


cargo run -- -f <path> -e -t <path>         //encrypts text from file path and exports to file path
cargo run -- -f <path> -d -o                //decrypts text from file path and overwrites same file with result
cargo run -- -i <textplatzhalter> -d -c      //decrypts text from command line args and exports to console


f <path> = filepath
i <text> = input
t <path> = target path
e = encryption true
d = decryption true
o = overwrite file true
c = console export true
k <path> = filepath to encryption details

file das key und nonce enthält zum entschlüsseln
beim verschlüsseln benutzten key und nonce abspeichern in file
zeile für zeile dann einlesen und als key und nonce object serialisieren

*/

fn main() {
    //command line args parsing
    let matches = command!()
        .arg(
            arg!(
                -f --filepath <FILE> "Sets a file path to read from"
            )
            .required(false),
        )
        .arg(
            arg!(
                -i --inputtext <text> "provides text input to operate with"
            )
            .required(false),
        )
        .arg(
            arg!(
                -t --targetfilepath <FILE> "Sets a file path to write to"
            )
            .required(false),
        )
        .arg(
            arg!(
                -k --cryptographicparams <FILE> "file with key and nonce"
            )
            .required(false),
        )
        .arg(
            arg!(
            -e --encrypt "enable encryption"
            )
            .required(false),
        )
        .arg(
            arg!(
            -d --decrypt "enable decryption"
            )
            .required(false),
        )
        .arg(
            arg!(
            -o --overwrite "overwrite input file"
            )
            .required(false),
        )
        .arg(
            arg!(
            -c --console "enable console output "
            )
            .required(false),
        )
        .get_matches();

    let mut file_path_source = String::new();
    let mut file_path_target = String::new();
    let mut inputtext = String::new();
    let mut encrypt = false;
    let mut decrypt = false;
    let mut overwrite = false;
    let mut console_export = false;
    let mut crypto_file_path = String::new();

    if let Some(path) = matches.get_one::<String>("filepath") {
        println!("Reading from file: {path}");
        file_path_source = path.clone();
    }
    if let Some(text) = matches.get_one::<String>("inputtext") {
        println!("Reading from console: {text}");
        inputtext = text.clone();
    }
    if let Some(path) = matches.get_one::<String>("targetfilepath") {
        println!("Writing to file: {path}");
        file_path_target = path.clone();
    }

    if let Some(flag) = matches.get_one::<bool>("decrypt") {
        println!("decrypt: {flag}");
        decrypt = *flag;
    }

    if let Some(flag) = matches.get_one::<bool>("encrypt") {
        println!("encrypt: {flag}");
        encrypt = *flag;
    }

    if let Some(flag) = matches.get_one::<bool>("overwrite") {
        println!("overwrite source file: {flag}");
        overwrite = *flag;
    }

    if let Some(flag) = matches.get_one::<bool>("console") {
        println!("export to console: {flag}");
        console_export = *flag;
    }
    if let Some(path) = matches.get_one::<String>("cryptographicparams") {
        println!("path of cryptographic params file: {path}");
        crypto_file_path = path.clone();
    }

    // potential error source => if nothing is provided does is_empty work / not initialised?
    let file_export = overwrite || !file_path_target.is_empty();
    println!("export? {}", &file_export);
    let file_is_source = !file_path_source.is_empty() && inputtext.is_empty();
    let text_is_source = file_path_source.is_empty() && !inputtext.is_empty();

    if overwrite {
        file_path_target = file_path_source.clone();
    }

    let mut content = String::new();
let mut encrypted_string: Vec<u8> = Vec::new();
    // fill content variable with actual data
    if file_is_source {
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(file_path_source)
            .expect("error opening file");
        file.read_to_string(&mut content)
            .expect("error reading file");
        if decrypt {
            // Dekodiere den Hex-String in Vec<u8>
            encrypted_string = hex::decode(&content).expect("Fehler beim Dekodieren");

        }

    } else if text_is_source {
        content = inputtext;
        if decrypt {
            // Dekodiere den Hex-String in Vec<u8>
            encrypted_string = hex::decode(&content).expect("Fehler beim Dekodieren");
        }
    }

    let mut keystring = String::new();
    let mut noncestring = String::new();

    if encrypt {
        let mut keybytes: [u8; 32] = [0; 32];
        rand::thread_rng().fill(&mut keybytes);
        let key = Key::<Aes256Gcm>::from_slice(&keybytes);
        println!("generated random key byte array is: {:?}", &key);
        keystring = hex::encode(key).to_string();

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        noncestring = hex::encode(nonce).to_string();
        println!("generated random nonce: {:?}", &nonce);

        let cipher = Aes256Gcm::new(key);
        let ciphertext = cipher
            .encrypt(&nonce, content.as_bytes())
            .expect("hundesohn");

        let param = hex::encode(&ciphertext);

        export_data(
            &param,
            file_export,
            console_export,
            &file_path_target,
            encrypt,
            &keystring,
            &noncestring,
        );
    } else if decrypt {
        //create nonce and key from file input
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&crypto_file_path)
            .expect("error opening crypto file");

        let reader = io::BufReader::new(file);
        let mut lines = reader.lines();
        let first_line = match lines.next() {
            Some(Ok(line)) => line,
            Some(Err(e)) => {
                eprintln!("error reading first line - key : {}", e);
                return;
            }
            None => {
                println!("error - file is empty");
                return;
            }
        };
        println!("{}", first_line);
        //first_line = hex::decode(first_line.trim());
        let keybytes_result = hex::decode(first_line.trim());

        let keybytes = match keybytes_result {
            Ok(bytes) => bytes,
            Err(e) => panic!("Fehler beim Dekodieren des Schlüssels: {}", e),
        };

        let key: [u8; 32] = keybytes
            .clone()
            .try_into()
            .expect("error creating key from file details");
        let key: &Key<Aes256Gcm> = &key.into();
        //println!("first line as byte array: {:?}", keybytes);

        let second_line = match lines.next() {
            Some(Ok(line)) => line,
            Some(Err(e)) => {
                eprintln!("error reading second line : {}", e);
                return;
            }
            None => {
                println!("error line is empty");
                return;
            }
        };

        let noncebytes_result = hex::decode(second_line.trim());
        let noncebytes = match noncebytes_result {
            Ok(bytes) => {
                if bytes.len() != 12 {
                    panic!("wrong length: {}", bytes.len());
                }
                bytes
            }
            Err(e) => panic!("error decoding the input: {}", e),
        };
        let nonce: Nonce<U12> = *Nonce::from_slice(&noncebytes);
        //println!("nonce {:?}", nonce);

        let cipher = Aes256Gcm::new(key);

        let ciphertext = encrypted_string;
        //println!("{:?}", ciphertext);
        let plaintext = cipher
            .decrypt(&nonce, &*ciphertext)
            .expect("Entschlüsselung fehlgeschlagen");

        // Konvertiere das Ergebnis in einen String
        let decrypted_string = String::from_utf8(plaintext).expect("Ungültige UTF-8-Sequenz.");

        //println!("Entschlüsselter Text: {:?}", decrypted_string.as_str());

        export_data(
            &decrypted_string,
            file_export,
            console_export,
            &file_path_target,
            encrypt,
            &keystring,
            &noncestring,
        );
    }
}


fn export_data(
    content: &str,
    file_export: bool,
    console_export: bool,
    file_path: &str,
    encrypt: bool,
    key: &str,
    nonce: &str,
) {
    if console_export {
        println!("{}", &content)
    }

    if file_export {
        println!("filepath {}", &file_path);
      //  println!("content: {}", &content);
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .truncate(true)
            .create(true)
            .open(file_path)
            .expect("error handling file: {filePath}");
        file.write_all(content.as_bytes())
            .expect("error while trying to overwrite same file");
    }

    if encrypt {
        let mut file =
            File::create("encryptiondata.txt").expect("error when creating encryptiondata file");
        writeln!(file, "{key}").expect("error writing key to encryption data file");
        writeln!(file, "{nonce}").expect("error writing nonce to encryption data file");
    }
}
