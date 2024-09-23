use hive_memo::{serialization::{deserialize_encrypted_memo}, keys::{wif_to_secret_key, public_key_from_string}, encryption::{encrypt_memo, decrypt_memo}};
use hive_memo::HiveMemoError;

#[test]
fn test_serialize_deserialize_encrypted_memo() {
    let sender_private_wif = "5KV4qZ1obXQPwUQqitD5Tx86Writ4tbeDAo68WLXhcU3ZaHR1M7"; // Sender's WIF private key
    let receiver_public_key_str = "STM8NdWaHRo41w1VdmsErA7iX1hnzkc2Z87evTUTBsiSg2PeTzX37"; // Receiver's public key

    let sender_private_key = wif_to_secret_key(sender_private_wif).unwrap();
    let receiver_public_key = public_key_from_string(receiver_public_key_str).unwrap();

    let memo = "#Hi from InLeo!";

    let encrypted_memo = encrypt_memo(&sender_private_key, &receiver_public_key, memo).unwrap();
    println!("Encrypted Memo: {:#?}", encrypted_memo);

    let receiver_private_wif = "5KV4qZ1obXQPwUQqitD5Tx86Writ4tbeDAo68WLXhcU3ZaHR1M7";

    let receiver_private_key = wif_to_secret_key(receiver_private_wif).unwrap();

    // Decrypt the memo
    let decrypted_memo = decrypt_memo(&receiver_private_key, &encrypted_memo).unwrap();
    assert_eq!("Hi from InLeo!", decrypted_memo);
}

#[test]
fn test_deserialize_invalid_data() {
    let invalid_data = vec![0, 1, 2]; // Too short
    let deserialized = deserialize_encrypted_memo(&invalid_data);
    assert!(matches!(deserialized, Err(HiveMemoError::DeserializationError(_))));
}
