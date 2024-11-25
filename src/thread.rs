use std::fs::{self, OpenOptions};
use std::io::{Write, Read, SeekFrom, Seek, Cursor, ErrorKind};
use std::os::windows::fs::{MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::{io};
use std::collections::HashMap;
use std::thread::sleep;
use std::time::{Duration, Instant};
use aes::{Aes256};
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
use aes::cipher::consts::{U16};
use sha2::{Digest, Sha256};
use thread_manager::ThreadManager;
use array_macro::array;
#[derive(Debug)]
#[derive(Clone)]
struct FileInfo {
    name: String,
    path: PathBuf,
    size: u64,
}

pub fn pack_n_encrypt(path_str: &str, mode: bool, encryption_key: Arc<String>, lock: Arc<Mutex<bool>>) -> bool {
    *lock.lock().unwrap() = true;
    let directory_path = Path::new(path_str);
    if !directory_path.exists() {
        println!("Error: Directory does not exist.");
        *lock.lock().unwrap() = false;
        return false;
    }
    
    let encrypted_file_name = "files.encrypto";
    let encrypted_file_path = directory_path.join(encrypted_file_name);
    
    if mode { //encrypt
        let mut file_infos: Vec<FileInfo> = Vec::new();
        // Collect file information recursively
        collect_file_info(directory_path, &mut file_infos, encrypted_file_name).unwrap();
        if file_infos.len()==0 {
            println!("No files to encrypt!");
            *lock.lock().unwrap() = false;
            return false;
        }

        let header = get_raw_file_info(&file_infos);
        let file_infos_copy: Vec<FileInfo> = file_infos.clone();
        let mut result = false;
        let start_time = Instant::now();
        if !result {} // going around a warning ;)
        result = encrypt_files(encrypted_file_path.clone(), encryption_key.clone(), file_infos, header);
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        println!("Time taken: {:?}", elapsed_time);

        if !result { println!("Error encrypting!"); *lock.lock().unwrap() = false; return false;}
        
        delete_files(file_infos_copy);
    }
    else {
        //check if file exists
        if fs::metadata(encrypted_file_path.clone()).is_err() {
            println!("Encrypted file does not exist!");
            *lock.lock().unwrap() = false;
            return false
        }

        //read header for header size
        let mut header_len = get_header_len(encrypted_file_path.clone(), encryption_key.clone());
        //collect info
        let mut file_infos: Vec<FileInfo> = Vec::new();
        collect_info_from_header(encrypted_file_path.clone(), encryption_key.clone(), &mut file_infos, &mut header_len);
        let mut result = false;
        if !result {} // going around a warning ;)
        //decrypt files
        let start_time = Instant::now();
        result = decrypt_files(encrypted_file_path.clone(), encryption_key.clone(), file_infos, header_len);
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        println!("Time taken: {:?}", elapsed_time);
       
        if !result { println!("Error decrypting!"); *lock.lock().unwrap() = false; return false;}
        
        match fs::remove_file(encrypted_file_path.clone()) {
            Ok(_) => println!("File deleted successfully {:?}", encrypted_file_path.clone()),
            Err(e) => println!("Error deleting file: {}", e),
        }
    }

    *lock.lock().unwrap() = false;
    true
}
fn decrypt_files(input_path: PathBuf, encryption_key: Arc<String>, file_infos: Vec<FileInfo>, header_len: u64) -> bool {
    let key = string_to_key(encryption_key.as_str());
    let cipher = Aes256::new_from_slice(&key);
    let num_threads = num_cpus::get();

    let thread_manager = ThreadManager::<()>::new(num_threads-1);
    let saver_thread_manager = ThreadManager::<()>::new(1);
    let mut header_len_mod = header_len;
    
    for file in file_infos {

        let shared_map: Arc<Mutex<HashMap<u64, Box<[u8; 560000]>>>> = Arc::new(Mutex::new(HashMap::new())); // TODO: Increase size MORE
        let number_of_blocks = div_up(file.size as usize, 560000);
        let output_file = file.path.clone();
        let thread_shared_map = Arc::clone(&shared_map);
        
        saver_thread_manager.execute(move || { //Saver thread which waits for elements in order
            let mut blocks_to_write = number_of_blocks.clone();
            let temp_file_path = output_file.clone();
            let mut counter: u64 = 0;
            let file_size_copy = file.size.clone();
            //ensure dir exists
            if let Some(parent_dir) = Path::new(&temp_file_path.clone()).parent() {
                fs::create_dir_all(parent_dir).unwrap();
            }
            // Open the file in append mode, creating it if it doesn't exist.
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(temp_file_path.clone()).unwrap();

            while blocks_to_write!=0 {
                if thread_shared_map.lock().unwrap().get(&counter).is_none() { continue; }
                let data = **thread_shared_map.lock().unwrap().get(&counter).unwrap();

                if blocks_to_write==1 && file_size_copy%560000!=0 {
                    let x = file_size_copy%560000;
                    if x!=560000 {
                        let mut temp = data.to_vec();
                        temp.truncate(x as usize);
                        file.write_all(&temp).unwrap();
                        counter+=1;
                        blocks_to_write-=1;
                        continue;
                    }
                    // Write the data to the file.
                    file.write_all(&data).unwrap();
                    counter+=1;
                    blocks_to_write-=1;
                    continue;
                }

                // Write the data to the file.
                file.write_all(&data).unwrap();
                thread_shared_map.lock().unwrap().remove(&counter).unwrap();
                counter+=1;
                blocks_to_write-=1;
            }
        });

        
        for i in 0..number_of_blocks {
            let i_clone = i.clone();
            let file_path_clone = input_path.clone();
            let cipher_clone = cipher.clone();
            let thread_shared_map2 = Arc::clone(&shared_map);
            let number_of_blocks_clone = number_of_blocks.clone();
            // Submit job for execution
            thread_manager.execute(move || {
                
                let at = header_len_mod + (i_clone*560000) as u64;
                let mut file_obj = OpenOptions::new()
                    .create(false)
                    .append(false)
                    .read(true)
                    .open(file_path_clone.clone()).unwrap();
                file_obj.seek(SeekFrom::Start(at)).unwrap();

                let mut block: Box<[u8; 560000]> = Box::new([0; 560000]);
                let file_size_copy = file.size.clone();
                let mut read_size = file_size_copy%560000;
                let mut file_obj2;
                if number_of_blocks_clone - i_clone == 1 && read_size !=0 {
                    read_size = (div_up(read_size as usize, 16) as u64) * 16;
                    file_obj2 = file_obj.take(read_size);
                    let _count = file_obj2.read(&mut *block).unwrap();
                }
                else{
                    let _count = file_obj.read(&mut *block).unwrap();
                }
                
                // Convert the original array into an array of GenericArrays
                let mut blocks_16: Box<[GenericArray<u8, U16>; 35000]> = Box::new(array![_ => GenericArray::from([0u8; 16]); 35000]);
                for i in 0..35000 {
                    let start_index = i * 16;
                    let end_index = start_index + 16;
                    let slice = &block[start_index..end_index];
                    let generic_array = GenericArray::clone_from_slice(slice);
                    blocks_16[i] = generic_array;
                }

                cipher_clone.clone().expect("REASON").decrypt_blocks(&mut *blocks_16);
                
                // Convert the array of GenericArrays into a single array of bytes
                let mut finished_array: Box<[u8; 560000]> = Box::new([0; 560000]);
                for i in 0..35000 {
                    let start_index = i * 16;
                    finished_array[start_index..start_index + 16].copy_from_slice(&blocks_16[i]);
                }
                
                thread_shared_map2.lock().unwrap().insert(i_clone as u64, finished_array);
            });
            while thread_manager.job_queue() > 10000000 {
                sleep(Duration::from_millis(10))
            }
        }
        let temp_size = (div_up(file.size as usize, 16) as u64) * 16;
        header_len_mod+=temp_size;
    }

    thread_manager.join();
    saver_thread_manager.join();
    println!("Finished Decrypt");

    true
}
fn collect_file_info(path: &Path, file_infos: &mut Vec<FileInfo>, output_file_name: &str) -> Result<(), io::Error> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let metadata = fs::metadata(&entry.path())?; // Get metadata for each entry

        if metadata.is_dir() {
            collect_file_info(&entry.path(), file_infos, output_file_name)?; // Recursively explore directories
        } else {
            if entry.file_name().to_str().unwrap().to_string()==output_file_name {
                file_infos.clear();
                println!(".encrypto file found - Probably meant to decrypt?");
                return Ok(());
            }

            let file_info = FileInfo {
                name: entry.file_name().to_str().unwrap().to_string(),
                path: entry.path(),
                size: metadata.file_size(),
            };
            file_infos.push(file_info);
        }
    }
    Ok(())
}
fn get_raw_file_info(file_infos: &[FileInfo]) -> Vec<u8> {
    let mut header: Vec<u8> = vec![];
    
    for file_info in file_infos {
        // 4 bytes (u32)
        let name_len = (file_info.name.len() as u32).to_be_bytes();
        // 4 bytes (u32)
        let path_len = (file_info.path.display().to_string().len() as u32).to_be_bytes();
        // 8 bytes (u64)
        let size_bytes = file_info.size.to_be_bytes();

        header.extend_from_slice(&name_len);
        header.extend_from_slice(file_info.name.as_bytes());
        header.extend_from_slice(&path_len);
        header.extend_from_slice(file_info.path.display().to_string().as_bytes());
        header.extend_from_slice(&size_bytes);
    }
    let mut header_with_size_bytes: Vec<u8> = Vec::from((header.len() as u64).to_be_bytes()); // 8 bytes (u64)
    header_with_size_bytes.extend_from_slice(header.as_slice());
    
    header_with_size_bytes
}
fn overwrite_with_zeros(file_info: FileInfo) -> io::Result<()> {
    // Open the file in write-only mode, truncating it if it already exists.
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(file_info.path)?;
    
    let buffer_size = 560000;
    let buffer = vec![0; buffer_size];
    
    let mut bytes_written: u64 = 0;
    while bytes_written < file_info.size {
        let bytes_to_write = std::cmp::min(buffer_size as u64, file_info.size - bytes_written);
        file.write_all(&buffer[0..bytes_to_write as usize])?;
        bytes_written += bytes_to_write;
    }

    Ok(())
}
fn delete_files(file_infos: Vec<FileInfo>) -> bool{
    let mut result = true;
    for file_info in file_infos {
        let r = overwrite_with_zeros(file_info.clone());
        let r2 = fs::remove_file(file_info.path);
        
        if r.is_err()
        {
            println!("Error 0`ing file");
            result = false;
        }
        if r2.is_err()
        {
            println!("Error deleting file");
            result = false;
        }
    }

    println!("Files deleted successfully");
    result
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

    key
}

fn encrypt_files(output_file_path: PathBuf, encryption_key: Arc<String>, file_infos: Vec<FileInfo>, header: Vec<u8>) -> bool {
    
    let key = string_to_key(encryption_key.as_str());
    let cipher = Aes256::new_from_slice(&key);
    let num_threads = num_cpus::get();

    let thread_manager = ThreadManager::<()>::new(num_threads-1);
    let saver_thread_manager = ThreadManager::<()>::new(1);

    // Splitting header into 16-byte parts
    let mut parts: Vec<GenericArray<u8, U16>> = header
        .chunks_exact(16)
        .map(|chunk| {
            let mut arr = GenericArray::from([0u8; 16]);
            arr.copy_from_slice(chunk);
            arr
        })
        .collect();
    // If there are remaining bytes, push them as a separate part
    if !header.is_empty() && header.len() % 16 != 0 {
        let remainder = &header[header.len() - (header.len() % 16)..];
        let mut arr = GenericArray::from([0u8; 16]);
        arr[..remainder.len()].copy_from_slice(remainder);
        parts.push(arr);
    }
    
    for part in parts.iter() {
        let mut temp = part.clone();
        cipher.clone().expect("REASON").encrypt_block(&mut temp);
        
        append_x_to_file16(output_file_path.clone(), temp, 16).unwrap();
    }
    
    drop(parts);

    for file in file_infos {
        
        let shared_map: Arc<Mutex<HashMap<u64, Box<[u8; 560000]>>>> = Arc::new(Mutex::new(HashMap::new())); // TODO: Increase size MORE
        let number_of_blocks = div_up(file.size as usize, 560000);
        let output_file_copy = output_file_path.clone();

        let thread_shared_map = Arc::clone(&shared_map);
        saver_thread_manager.execute(move || { //Saver thread which waits for elements in order
            let mut blocks_to_write = number_of_blocks.clone();
            let temp_file_path = output_file_copy.clone();
            let mut counter: u64 = 0;
            let file_size_copy = file.size.clone();
            //ensure dir exists
            if let Some(parent_dir) = Path::new(&temp_file_path.clone()).parent() {
                fs::create_dir_all(parent_dir).unwrap();
            }
            // Open the file in append mode, creating it if it doesn't exist.
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(temp_file_path.clone()).unwrap();
            
            while blocks_to_write!=0 {
                if thread_shared_map.lock().unwrap().get(&counter).is_none() { continue; }
                let data = **thread_shared_map.lock().unwrap().get(&counter).unwrap();
                
                if blocks_to_write==1 && file_size_copy%560000!=0 {
                    let mut x = file_size_copy%560000;
                    x = (div_up(x as usize, 16) as u64) * 16;
                    if x!=560000 {
                        let mut temp = data.to_vec();
                        temp.truncate(x as usize);
                        file.write_all(&temp).unwrap();
                        counter+=1;
                        blocks_to_write-=1;
                        continue;
                    }
                    // Write the data to the file.
                    file.write_all(&data).unwrap();
                    counter+=1;
                    blocks_to_write-=1;
                    continue;
                }
                
                // Write the data to the file.
                file.write_all(&data).unwrap();
                thread_shared_map.lock().unwrap().remove(&counter).unwrap();
                counter+=1;
                blocks_to_write-=1;
            }
        });
        
        for i in 0..number_of_blocks {
            let i_clone = i.clone();
            let file_path_clone = file.path.clone();
            let cipher_clone = cipher.clone();
            let thread_shared_map2 = Arc::clone(&shared_map);
            // Submit job for execution
            thread_manager.execute(move || {
                
                let at = (i_clone*560000) as u64;
                let mut file = OpenOptions::new()
                    .create(false)
                    .append(false)
                    .read(true)
                    .open(file_path_clone.clone()).unwrap();
                file.seek(SeekFrom::Start(at)).unwrap();

                let mut block: Box<[u8; 560000]> = Box::new([0; 560000]);
                let _count = file.read(&mut *block).unwrap();

                // Convert the original array into an array of GenericArrays
                let mut blocks_16: Box<[GenericArray<u8, U16>; 35000]> = Box::new(array![_ => GenericArray::from([0u8; 16]); 35000]);
                for i in 0..35000 {
                    let start_index = i * 16;
                    let end_index = start_index + 16;
                    let slice = &block[start_index..end_index];
                    let generic_array = GenericArray::clone_from_slice(slice);
                    blocks_16[i] = generic_array;
                }
                
                cipher_clone.clone().expect("REASON").encrypt_blocks(&mut *blocks_16);

                // Convert the array of GenericArrays into a single array of bytes
                let mut finished_array: Box<[u8; 560000]> = Box::new([0; 560000]);
                for i in 0..35000 {
                    let start_index = i * 16;
                    finished_array[start_index..start_index + 16].copy_from_slice(&blocks_16[i]);
                }
                
                thread_shared_map2.lock().unwrap().insert(i_clone as u64, finished_array);
            });
            while thread_manager.job_queue() > 10000000 {
                sleep(Duration::from_millis(10))
            }
        }
    }

    thread_manager.join();
    saver_thread_manager.join();
    println!("Finished Encrypt");
    
    true
}
fn get_header_len(input_file: PathBuf, encryption_key: Arc<String>) -> u64 {

    let key = string_to_key(encryption_key.as_str());
    let cipher = Aes256::new_from_slice(&key);

    let mut file = OpenOptions::new()
        .create(false)
        .append(false)
        .read(true)
        .open(input_file).unwrap();

    let mut block = GenericArray::from([0u8; 16]);
    
    file.read(&mut block).unwrap();
    
    cipher.clone().expect("REASON").decrypt_block(&mut block);

    // Convert GenericArray<u8, U16> to u64
    let mut result: u64 = 0;
    for (i, &byte) in block.iter().enumerate() {
        // Ensure we don't shift more than 64 bits
        if i < 8 {
            // Shift each byte by 8 * (7 - i) bits and bitwise OR it with the result
            result |= (byte as u64) << (8 * (7 - i));
        }
    }
    
    result
}
fn read_file_info(file_infos: &mut Vec<FileInfo>, data: &[u8]) {
    let mut cursor = Cursor::new(data);

    let mut header_len_bytes = [0; 8];
    cursor.read_exact(&mut header_len_bytes).expect("REASON");
    let header_len = u64::from_be_bytes(header_len_bytes);

    loop {
        if cursor.position() >= header_len{
            break;
        }
        let mut name_len_bytes = [0; 4];
        cursor.read_exact(&mut name_len_bytes).expect("REASON");
        let name_len = u32::from_be_bytes(name_len_bytes);

        let mut name_bytes = vec![0; name_len as usize];
        cursor.read_exact(&mut name_bytes).expect("REASON");

        let mut path_len_bytes = [0; 4];
        cursor.read_exact(&mut path_len_bytes).expect("REASON");

        let path_len = u32::from_be_bytes(path_len_bytes);
        let mut path_bytes = vec![0; path_len as usize];
        cursor.read_exact(&mut path_bytes).expect("REASON");

        let path_str = String::from_utf8(path_bytes)
            .map_err(|e| io::Error::new(ErrorKind::InvalidData, e)).expect("REASON");
        let path = PathBuf::from(path_str);

        let mut size_bytes = [0; 8];
        cursor.read_exact(&mut size_bytes).expect("REASON");
        let size: u64 = u64::from_be_bytes(size_bytes);

        let file_info = FileInfo {
            name: String::from_utf8(name_bytes)
                .map_err(|e| io::Error::new(ErrorKind::InvalidData, e)).expect("REASON"),
            path,
            size,
        };

        file_infos.push(file_info);
    }
}
fn collect_info_from_header(input_file: PathBuf, encryption_key: Arc<String>, file_infos: &mut Vec<FileInfo>, header_len: &mut u64){
    let mut temp_header_len = *header_len;

    temp_header_len = temp_header_len + 8;
    temp_header_len = (div_up(temp_header_len as usize, 16) as u64) * 16;
    *header_len = temp_header_len.clone();
    
    let key = string_to_key(encryption_key.as_str());
    let cipher = Aes256::new_from_slice(&key);

    let mut file = OpenOptions::new()
        .create(false)
        .append(false)
        .read(true)
        .open(input_file).unwrap();

    let mut header = vec![];
    
    header.resize(temp_header_len as usize, 0);

    file.read(&mut header).unwrap();

    // Splitting header into 16-byte parts
    let mut parts: Vec<GenericArray<u8, U16>> = header
        .chunks_exact(16)
        .map(|chunk| {
            let mut arr = GenericArray::from([0u8; 16]);
            arr.copy_from_slice(chunk);
            arr
        })
        .collect();
    // If there are remaining bytes, push them as a separate part
    if !header.is_empty() && header.len() % 16 != 0 {
        let remainder = &header[header.len() - (header.len() % 16)..];
        let mut arr = GenericArray::from([0u8; 16]);
        arr[..remainder.len()].copy_from_slice(remainder);
        parts.push(arr);
    }

    let mut decrypted_header: Vec<GenericArray<u8, U16>> = vec![];
    
    for part in parts.iter() {
        //println!("Part {}: {:?}, last len:{}", i, part, last_len);
        let mut temp = part.clone();
        cipher.clone().expect("REASON").decrypt_block(&mut temp);
        decrypted_header.push(temp);
    }
    
    drop(header);

    let mut merged_header: Vec<u8> = vec![];

    for array in decrypted_header {
        merged_header.extend_from_slice(&array[..]);
    }
    
    read_file_info(file_infos, &merged_header);
}
fn append_x_to_file16(filename: PathBuf, data: GenericArray<u8, U16>, x: usize) -> io::Result<()> {
    // Open the file in append mode, creating it if it doesn't exist.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    if x!=16 {
        let mut temp = data.to_vec();
        temp.truncate(x);
        file.write_all(&temp)?;
        return Ok(());
    }
    // Write the data to the file.
    file.write_all(&data)?;

    Ok(())
}
pub fn div_up(a: usize, b: usize) -> usize {
    let mut output;
    if a % b == 0{
        output = a/b;
    }
    else { 
        output=a/b;
        output+=1;
    }
    output
}