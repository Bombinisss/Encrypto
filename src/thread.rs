use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,// Or `Aes128Gcm`
};
use sha2::{Sha256, Digest};
use std::fs::{self, File};
use std::io::{Write, Read};
use std::path::{Path, PathBuf};

struct FileInfo {
    name: String,
    path: PathBuf,
    size: usize,
    bytes: Vec<u8>,
}

pub fn encrypt_test(user_key: &str, path_str: &str, mode: bool) -> Option<bool> {
    let directory_path = Path::new(path_str);

    let output_file_name = "files.bin";

    if !directory_path.exists() {
        println!("Error: Directory does not exist.");
        return Some(false);
    }

    // Create the output file path by combining directory and filename
    let output_file_path = directory_path.join(output_file_name);

    // Create an empty list to store file information
    let mut file_infos: Vec<FileInfo> = Vec::new();

    // Collect file information recursively
    collect_file_info(directory_path, &mut file_infos).unwrap();

    // Open the output file in the specified directory
    let mut output_file = File::create(output_file_path.clone()).unwrap();

    // Write file information to the file
    if mode {
        write_file_info(&file_infos, &mut output_file).unwrap();
        println!("File information stored in '{}'", output_file_path.display());
    }

    // The encryption key can be generated randomly:
    //let key = Aes256Gcm::generate_key(OsRng);

    let key = string_to_key(user_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    let mut file = File::open(output_file_path.clone()).ok()?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).ok()?;

    if mode == true {
        // Attempt encryption
        let ciphertext = match cipher.encrypt(&nonce, buffer.as_ref()) {
            Ok(ciphertext) => ciphertext,
            Err(_) => return Some(false), // Return false if encryption fails
        };

        print!("{:?}", &ciphertext);

        let mut output_file = File::create(output_file_path.clone()).unwrap();
        output_file.write(&ciphertext).ok()?;
        println!("File information encrypted in '{}'", output_file_path.display());
    }
    else {
        // Attempt decryption
        let ciphertext = match cipher.decrypt(&nonce, buffer.as_ref()) {
            Ok(ciphertext) => ciphertext,
            Err(_) => return Some(false), // Return false if encryption fails
        };

        print!("{:?}", &ciphertext);

        let mut output_file = File::create(output_file_path.clone()).unwrap();
        output_file.write(&ciphertext).ok()?;
        println!("File information decrypted in '{}'", output_file_path.display());
    }

    println!("{}",mode);
    return Some(true)
}

// Function to convert a string into a key
fn string_to_key(s: &str) -> Key<Aes256Gcm> {
    // Create SHA-256 hasher
    let mut hasher = Sha256::new();

    // Hash the input string
    hasher.update(s);

    // Get the resulting hash
    let result = hasher.finalize();

    // Convert the hash into a fixed-size array
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..]);

    Key::<Aes256Gcm>::from(key)
}

fn collect_file_info(path: &Path, file_infos: &mut Vec<FileInfo>) -> Result<(), std::io::Error> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::metadata(&entry.path())?; // Get metadata for each entry

        if metadata.is_dir() {
            collect_file_info(&entry.path(), file_infos)?; // Recursively explore directories
        } else {
            let mut file = File::open(entry.path())?;
            let mut buffer = Vec::new();
            let size = file.read_to_end(&mut buffer)?;

            let file_info = FileInfo {
                name: entry.file_name().to_str().unwrap().to_string(),
                path: entry.path(),
                size,
                bytes: buffer,
            };
            file_infos.push(file_info);
        }
    }
    Ok(())
}

fn write_file_info(file_infos: &[FileInfo], output_file: &mut File) -> Result<(), std::io::Error> {
    for file_info in file_infos {
        let line =format!(
            "{}|{}|{}|{}|{}|",
            file_info.name.len(),file_info.name,file_info.path.display().to_string().len(), file_info.path.display(), file_info.size
        );

        output_file.write_all(line.as_bytes())?;

        // Write bytes directly without formatting
        output_file.write(&file_info.bytes)?;
    }
    Ok(())
}