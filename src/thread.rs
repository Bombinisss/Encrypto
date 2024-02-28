use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key,// Or `Aes128Gcm`
};
use sha2::{Sha256, Digest};

pub fn encrypt_test(data: String, user_key: &str) -> bool {
    // The encryption key can be generated randomly:
    //let key = Aes256Gcm::generate_key(OsRng);

    let key = string_to_key(user_key);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message

    // Attempt encryption
    let ciphertext = match cipher.encrypt(&nonce, data.as_ref()) {
        Ok(ciphertext) => ciphertext,
        Err(_) => return false, // Return false if encryption fails
    };

    // Attempt decryption
    let plaintext = match cipher.decrypt(&nonce, ciphertext.as_ref()) {
        Ok(plaintext) => plaintext,
        Err(_) => return false, // Return false if decryption fails
    };

    //println!("{:?}", plaintext);

    let string2 = String::from_utf8(plaintext.clone()).unwrap_or_else(|_| String::from("Invalid UTF-8 bytes"));
    println!("{}", string2);
    true
}

// Function to convert a string into a key
fn string_to_key(s: &str) -> Key<aes_gcm::Aes256Gcm> {
    // Create SHA-256 hasher
    let mut hasher = Sha256::new();

    // Hash the input string
    hasher.update(s);

    // Get the resulting hash
    let result = hasher.finalize();

    // Convert the hash into a fixed-size array
    let mut key = [0u8; 32];
    key.copy_from_slice(&result[..]);

    Key::<aes_gcm::Aes256Gcm>::from(key)
}