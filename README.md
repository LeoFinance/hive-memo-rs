# Hive Memo


![Crates.io](https://img.shields.io/crates/v/hive_memo)
![License](https://img.shields.io/crates/l/hive_memo)




Hive Memo is a Rust crate designed for encrypting and decrypting memos using elliptic curve cryptography (ECC) and AES-256-CBC encryption, taking [@hiveo/dhive](https://github.com/openhive-network/dhive)'s memo encryption and decryption methods into account.




## Features


- **Key Management**
  - Parse and validate WIF (Wallet Import Format) private keys.
  - Handle public keys in Hive format (`STM` prefixed).
  - Derive public keys from private keys.


- **Encryption & Decryption**
  - Encrypt memos using AES-256-CBC with shared secrets derived from ECDH.
 
## Installation


Add `hive_memo` to your `Cargo.toml`:


```toml
[dependencies]
hive_memo = "0.1.0"
```
### OR
```
cargo add hive_memo
```


## Usage 


### Encryption
```rs
use hive_memo::keys::{wif_to_secret_key, public_key_from_string};
use hive_memo::encryption::encrypt_memo;
use std::error::Error;


fn main()  {
    // Sender's WIF private key
    let sender_private_wif = "5KV4qZ1obXQPwUQqitD5Tx86Writ4tbeDAo68WLXhcU3ZaHR1M7";
    // Receiver's public key in Hive format
    let receiver_public_key_str = "STM5PQVrcekY3psFdYxRDXtYRNNWsPjeHtTvfhUtKaiADPvRqSVYM";


    // Convert WIF to SecretKey
    let sender_private_key = wif_to_secret_key(sender_private_wif)?;
    // Convert Hive public key string to PublicKey
    let receiver_public_key = public_key_from_string(receiver_public_key_str)?;


    let memo = "#This is a secure memo";


    // Encrypt the memo
    let encrypted_memo = encrypt_memo(&sender_private_key, &receiver_public_key, memo)?;
    println!("Encrypted Memo: {}", encrypted_memo);
}


```


### Decryption 


```rs
use hive_memo::keys::wif_to_secret_key;
use hive_memo::encryption::decrypt_memo;
use std::error::Error;


fn main() {
    // Receiver's WIF private key
    let receiver_private_wif = "5KV4qZ1obXQPwUQqitD5Tx86Writ4tbeDAo68WLXhcU3ZaHR1M7";
    // Encrypted memo string
    let encrypted_memo = "#<Base58EncodedEncryptedMemo>";


    // Convert WIF to SecretKey
    let receiver_private_key = wif_to_secret_key(receiver_private_wif)?;


    // Decrypt the memo
    let decrypted_memo = decrypt_memo(&receiver_private_key, encrypted_memo)?;
    println!("Decrypted Memo: {}", decrypted_memo);
}
```


