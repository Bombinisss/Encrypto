use std::fs::{self, File, OpenOptions};
use std::io::{Write, Read, stderr, SeekFrom, Seek};
use std::os::windows::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
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
    
    let encrypted_file_name = "files.encrypto";
    let encrypted_file_path = directory_path.join(encrypted_file_name);
    let packed_file_name = "files.bin";
    let packed_file_path = directory_path.join(packed_file_name);
    
    if mode { //encrypt
        let mut file_infos: Vec<FileInfo> = Vec::new();
        // Collect file information recursively
        collect_file_info(directory_path, &mut file_infos, encrypted_file_name).unwrap();
        if file_infos.len()==0 { 
            println!("No files to encrypt!");
            return Some(true); 
        }

        let header = get_raw_file_info(&file_infos);
        let file_infos_copy: Vec<FileInfo> = file_infos.clone();

        let start_time = Instant::now();
        encrypt_files(encrypted_file_path.clone(), encryption_key.clone(), file_infos, header);
        let end_time = Instant::now();
        let elapsed_time = end_time.duration_since(start_time);
        println!("Time taken: {:?}", elapsed_time);
        
        delete_files(file_infos_copy).unwrap();
    }
    else { //TODO: Rework decrypt logic later //decrypt
        //decrypt 8bytes
        
        //read header for header size
        
        //collect info
        
        //decrypt files

        let mut file = File::open(encrypted_file_path.clone()).unwrap();
        let mut file_infos: Vec<FileInfo> = Vec::new();
        let header_len = read_file_info(&mut file_infos, &mut file);

        drop(file);

        let mut file = File::open(encrypted_file_path.clone()).unwrap();
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

fn collect_file_info(path: &Path, file_infos: &mut Vec<FileInfo>, output_file_name: &str) -> Result<(), std::io::Error> {
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
                size: metadata.file_size() as usize,
                bytes: vec![],
                name_len: 0,
                path_len: 0,
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
    let mut header_with_size_bytes: Vec<u8> = Vec::from((header.len() as u64).to_be_bytes());
    header_with_size_bytes.extend_from_slice(header.as_slice());
    
    return header_with_size_bytes;
}

fn read_file_info(file_infos: &mut Vec<FileInfo>, input_file: &mut File) -> u64 {
    let mut header_len_bytes = [0; 8];
    if let Err(_) = input_file.read_exact(&mut header_len_bytes) {
        // If error occurs while reading, it's likely end of file
        return 0;
    }
    let header_len = u64::from_be_bytes(header_len_bytes);
    
    loop {
        let mut name_len_bytes = [0; 4];
        if let Err(_) = input_file.read_exact(&mut name_len_bytes) {
            // If error occurs while reading, it's likely end of file
            break;
        }
        let name_len = u32::from_be_bytes(name_len_bytes);

        let mut name_bytes = vec![0; name_len as usize];
        input_file.read_exact(&mut name_bytes).unwrap();

        let mut path_len_bytes = [0; 4];
        input_file.read_exact(&mut path_len_bytes).unwrap();
        let path_len = u32::from_be_bytes(path_len_bytes);

        let mut path_bytes = vec![0; path_len as usize];
        input_file.read_exact(&mut path_bytes).unwrap();

        let path_str = String::from_utf8(path_bytes).ok().ok_or(stderr());
        let path = path_str.unwrap().as_str().into();

        let mut size_bytes = [0; 8];
        input_file.read_exact(&mut size_bytes).unwrap();
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

    header_len
}

fn read_file_data_n_unpack(file_infos: &Vec<FileInfo>, input_file: &mut File) -> bool {
    let mut temp = [0 ; 1];
    let mut start_pos = 8;
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

fn encrypt_files(output_file: PathBuf, encryption_key: Arc<String>, file_infos: Vec<FileInfo>, header: Vec<u8>) -> Option<bool> {
    
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
    let mut last_len: usize = 16;
    if !header.is_empty() && header.len() % 16 != 0 {
        let remainder = &header[header.len() - (header.len() % 16)..];
        let mut arr = GenericArray::from([0u8; 16]);
        last_len = remainder.len();
        arr[..remainder.len()].copy_from_slice(remainder);
        parts.push(arr);
    }
    
    
    for (i, part) in parts.iter().enumerate() {
        //println!("Part {}: {:?}, last len:{}", i, part, last_len);
        let mut temp = part.clone();
        cipher.clone().expect("REASON").encrypt_block(&mut temp);
        
        if i == parts.len()-1 {
            append_x_to_file16(output_file.clone(), temp, last_len).unwrap();
            break;
        }
        append_x_to_file16(output_file.clone(), temp, 16).unwrap();
    }
    
    drop(parts);

    for file in file_infos {
        
        let data_buffer: HashMap<u64, [u8; 72000]> = HashMap::new();
        let shared_map: Arc<Mutex<HashMap<u64, [u8; 72000]>>> = Arc::new(Mutex::new(data_buffer));
        let number_of_blocks = div_up(file.size,72000);
        let output_file_copy = output_file.clone();

        let thread_shared_map = Arc::clone(&shared_map);
        saver_thread_manager.execute(move || { //Saver thread which waits for elements in order
            let mut blocks_to_write = number_of_blocks.clone();
            let temp_file_path = output_file_copy.clone();
            let mut counter: u64 = 0;
            let file_size_copy = file.size.clone();
            // Open the file in append mode, creating it if it doesn't exist.
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(temp_file_path.clone()).unwrap();
            
            while blocks_to_write!=0 {
                
                let block_copy = thread_shared_map.lock().unwrap().get(&counter).copied();
                
                if block_copy.is_none() { continue; }
                let data = block_copy.unwrap();
                
                if blocks_to_write==1 && file_size_copy%72000!=0 {
                    let x = file_size_copy%72000;
                    append_x_to_file_fast(&mut file, data, x).unwrap();
                    counter+=1;
                    blocks_to_write-=1;
                    continue;
                }
                append_x_to_file_fast(&mut file, data, 72000).unwrap();
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
                let block;
                block = read_72000_from_file(&mut file_path_clone.clone(), (i_clone*72000)as u64);

                // Convert the original array into an array of GenericArrays
                let mut blocks_16: [GenericArray<u8, U16>; 4500] = array![_ => GenericArray::from([0u8; 16]); 4500];
                for i in 0..4500 {
                    let start_index = i * 16;
                    let end_index = start_index + 16;
                    let slice = &block[start_index..end_index];
                    let generic_array = GenericArray::clone_from_slice(slice);
                    blocks_16[i] = generic_array;
                }
                
                cipher_clone.clone().expect("REASON").encrypt_blocks(&mut blocks_16);

                // Convert the array of GenericArrays into a single array of bytes
                let mut finished_array: [u8; 72000] = [0; 72000];
                for i in 0..4500 {
                    let start_index = i * 16;
                    finished_array[start_index..start_index + 16].copy_from_slice(&blocks_16[i]);
                }
                
                thread_shared_map2.lock().unwrap().insert(i_clone as u64, finished_array);
            });
            while thread_manager.job_queue() > 1000000 {
                sleep(Duration::from_millis(10))
            }
        }
    }

    thread_manager.join();
    saver_thread_manager.join();
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
            append_x_to_file16(temp_file_path, buffer, 16).unwrap();
        });
        thread_join_handle.join().expect("TODO: Thread panicked");
    }

    println!("finished decrypt");
    Some(true)
}

fn append_x_to_file_fast(file: &mut File, data: [u8; 72000], x: usize) -> std::io::Result<()> {

    if x!=72000 {
        let mut temp = data.to_vec();
        temp.truncate(x as usize);
        file.write_all(&temp)?;
        return Ok(());
    }
    // Write the data to the file.
    file.write_all(&data)?;

    Ok(())
}
fn append_x_to_file16(filename: PathBuf, data: GenericArray<u8, U16>, x: usize) -> std::io::Result<()> {
    // Open the file in append mode, creating it if it doesn't exist.
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    if x!=16 {
        let mut temp = data.to_vec();
        temp.truncate(x as usize);
        file.write_all(&temp)?;
        return Ok(());
    }
    // Write the data to the file.
    file.write_all(&data)?;

    Ok(())
}

fn read_72000_from_file(filename: &mut PathBuf, at: u64) -> [u8; 72000] {
    // Open the file in append mode, creating it if it doesn't exist.
    let mut file = OpenOptions::new()
        .create(false)
        .append(false)
        .read(true)
        .open(filename).unwrap();
    file.seek(SeekFrom::Start(at)).unwrap();

    let mut data: [u8; 72000] = [0; 72000];
    // Write the data to the file.
    let count = file.read(&mut data).unwrap();

    return data;
}

pub fn div_up(a: usize, b: usize) -> usize {
    let mut output;
    if a % 16 == 0{
        output = a/b;
    }
    else { 
        output=a/b;
        output+=1;
    }
    return output;
}