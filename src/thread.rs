use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, // Or `Aes128Gcm`
};

pub fn encrypt_test(data: String) -> bool {
    // The encryption key can be generated randomly:
    let key = Aes256Gcm::generate_key(OsRng);
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

    println!("{:?}", plaintext);

    let string2 = String::from_utf8(plaintext.clone()).unwrap_or_else(|_| String::from("Invalid UTF-8 bytes"));
    println!("{}", string2);
    true
}
