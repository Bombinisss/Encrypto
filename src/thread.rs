use std::fs::{self, File, OpenOptions};
use std::io::{Write, Read, stderr};
use std::os::windows::fs::FileExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use aes::cipher::consts::U16;
use sha2::{Digest, Sha256};
#[derive(Debug)]
struct FileInfo {
    name: String,
    path: PathBuf,
    size: usize,
    bytes: Vec<u8>,
    name_len: usize,
    path_len: usize,
}

pub fn pack_n_encrypt(path_str: &str, mode: bool, encryption_key: Arc<String>) -> Option<bool> {
    let directory_path = Path::new(path_str);
    if !directory_path.exists() {
        println!("Error: Directory does not exist.");
        return Some(false);
    }

    let packed_file_name = "files.bin";
    let encrypted_file_name = "files.encrypto";
    let packed_file_path = directory_path.join(packed_file_name);
    let encrypted_file_path = directory_path.join(encrypted_file_name);

    // Write file information to the file
    if mode {
        // Create an empty list to store file information
        let mut file_infos: Vec<FileInfo> = Vec::new();
        // Collect file information recursively
        collect_file_info(directory_path, &mut file_infos).unwrap();
        // Open the output file in the specified directory
        let mut output_file = File::create(packed_file_path.clone()).unwrap();
        write_file_info(&file_infos, &mut output_file).unwrap();
        println!("File information stored in '{}'", packed_file_path.display());
        delete_files(file_infos).unwrap();

        encrypt_file(packed_file_path.clone(), encrypted_file_path.clone(), encryption_key);

        match fs::remove_file(packed_file_path.clone()) {
            Ok(_) => println!("File deleted successfully {:?}", packed_file_path.clone()),
            Err(e) => println!("Error deleting file: {}", e),
        }
    }
    else {
        decrypt_file(encrypted_file_path.clone(), packed_file_path.clone(), encryption_key);
        match fs::remove_file(encrypted_file_path.clone()) {
            Ok(_) => println!("File deleted successfully {:?}", encrypted_file_path.clone()),
            Err(e) => println!("Error deleting file: {}", e),
        }

        let mut file = File::open(packed_file_path.clone()).unwrap();
        let mut file_infos: Vec<FileInfo> = Vec::new();
        read_file_info(&mut file_infos, &mut file).ok();

        let mut file = File::open(packed_file_path.clone()).unwrap();
        match read_file_data_n_unpack(&mut file_infos, &mut file) {
            true => {
                println!("File read successfully");
                match fs::remove_file(packed_file_path.clone()) {
                    Ok(_) => println!("File deleted successfully {:?}", packed_file_path.clone()),
                    Err(e) => println!("Error deleting file: {}", e),
                }
            },
            false => println!("Error reading file!"),
        }
    }

    return Some(true)
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
                name_len: 0,
                path_len: 0,
            };
            file_infos.push(file_info);
        }
    }
    Ok(())
}

fn write_file_info(file_infos: &[FileInfo], output_file: &mut File) -> Result<(), std::io::Error> {
    for file_info in file_infos {
        // 4 bytes (u32)
        let name_len = (file_info.name.len() as u32).to_be_bytes();
        // 4 bytes (u32)
        let path_len = (file_info.path.display().to_string().len() as u32).to_be_bytes();
        // 8 bytes (u64)
        let size_bytes = file_info.size.to_be_bytes();

        output_file.write_all(&name_len)?;
        output_file.write_all(file_info.name.as_bytes())?;
        output_file.write_all(&path_len)?;
        output_file.write_all(file_info.path.display().to_string().as_bytes())?;
        output_file.write_all(&size_bytes)?;
    }

    // Write bytes for each file
    for file_info in file_infos {
        output_file.write_all(&file_info.bytes)?;
    }

    Ok(())
}

fn read_file_info(file_infos: &mut Vec<FileInfo>, input_file: &mut File) -> Result<(), std::io::Error> {
    loop {
        let mut name_len_bytes = [0; 4];
        if let Err(_) = input_file.read_exact(&mut name_len_bytes) {
            // If error occurs while reading, it's likely end of file
            break;
        }
        let name_len = u32::from_be_bytes(name_len_bytes);

        let mut name_bytes = vec![0; name_len as usize];
        input_file.read_exact(&mut name_bytes)?;

        let mut path_len_bytes = [0; 4];
        input_file.read_exact(&mut path_len_bytes)?;
        let path_len = u32::from_be_bytes(path_len_bytes);

        let mut path_bytes = vec![0; path_len as usize];
        input_file.read_exact(&mut path_bytes)?;

        let path_str = String::from_utf8(path_bytes).ok().ok_or(stderr());
        let path = path_str.unwrap().as_str().into();

        let mut size_bytes = [0; 8];
        input_file.read_exact(&mut size_bytes)?;
        let size = usize::from_be_bytes(size_bytes);

        let bytes = Vec::new();

        let file_info = FileInfo {
            name: String::from_utf8(name_bytes).ok().ok_or(stderr()).unwrap(),
            path,
            size,
            bytes,
            name_len: name_len as usize,
            path_len: path_len as usize,
        };

        file_infos.push(file_info);
    }

    Ok(())
}

fn read_file_data_n_unpack(file_infos: &Vec<FileInfo>, input_file: &mut File) -> bool {
    let mut temp = [0 ; 1];
    let mut start_pos = 0;
    for file_info in file_infos{

        start_pos += 16 + file_info.name_len + file_info.path_len;
    }
    if start_pos == 0 { return false; }
    start_pos-=1;
    input_file.seek_read(&mut temp, start_pos as u64).expect("Seek read fail!");

    for file_info in file_infos {
        let mut bytes = vec![0; file_info.size];
        if let Err(_) = input_file.read_exact(&mut bytes) {
            // If error occurs while reading, it's likely end of file
            break;
        }

        create_file_from_data(file_info, bytes).unwrap();
    }

    true
}

fn create_file_from_data(file_info: &FileInfo, data: Vec<u8>) -> Result<(), std::io::Error>{
    let mut file = File::create(file_info.path.clone()).unwrap();
    file.write_all(&*data).unwrap();

    Ok(())
}

fn delete_files(file_infos: Vec<FileInfo>) -> Result<(), std::io::Error>{
    for file_info in file_infos {
        match fs::remove_file(file_info.path) {
            Ok(_) => println!("File deleted successfully"),
            Err(e) => println!("Error deleting file: {}", e),
        }
    }

    Ok(())
}

fn string_to_key(s: &str) -> [u8; 32] {
    // Create SHA-256 hasher
    let mut hasher = Sha256::new();

    // Hash the input string
    hasher.update(s);

    // Get the resulting hash
    let result = hasher.finalize();

    // Convert the hash into a fixed-size array
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..]);

    return key;
}

fn encrypt_file(input_file: PathBuf, output_file: PathBuf, encryption_key: Arc<String>) -> Option<bool> {
    let mut file = File::open(input_file.clone()).unwrap();
    let key = string_to_key(encryption_key.as_str());
    let cipher = Aes256::new_from_slice(&key);
    loop {
        let mut buffer = GenericArray::from([0u8; 16]);
        let bytes_read = file.read(&mut buffer).ok()?;

        if bytes_read == 0 {
            break; // Reached end of file
        }
        cipher.clone().expect("REASON").encrypt_block(&mut buffer);

        let output_file_path_clone = output_file.clone(); // Clone output_file_path for each thread
        let thread_join_handle = thread::spawn(move || {
            let temp_file_path = output_file_path_clone.clone();
            append_to_file(temp_file_path, buffer).unwrap();
        });
        thread_join_handle.join().expect("TODO: Thread panicked");
    }

    println!("finished encrypt");
    Some(true)
}

fn decrypt_file(input_file: PathBuf, output_file: PathBuf, encryption_key: Arc<String>) -> Option<bool> {
    let mut file = File::open(input_file.clone()).unwrap();
    let key = string_to_key(encryption_key.as_str());
    let cipher = Aes256::new_from_slice(&key);
    loop {
        let mut buffer = GenericArray::from([0u8; 16]);
        let bytes_read = file.read(&mut buffer).ok()?;

        if bytes_read == 0 {
            break; // Reached end of file
        }
        cipher.clone().expect("REASON").decrypt_block(&mut buffer);

        let output_file_path_clone = output_file.clone(); // Clone output_file_path for each thread
        let thread_join_handle = thread::spawn(move || {
            let temp_file_path = output_file_path_clone.clone();
            append_to_file(temp_file_path, buffer).unwrap();
        });
        thread_join_handle.join().expect("TODO: Thread panicked");
    }

    println!("finished decrypt");
    Some(true)
}

fn append_to_file(filename: PathBuf, data: GenericArray<u8, U16>) -> std::io::Result<()> {
    // Open the file in append mode, creating it if it doesn't exist.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    // Write the data to the file.
    file.write_all(&data)?;

    Ok(())
}