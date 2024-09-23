use hive_memo::keys::{wif_to_secret_key, public_key_from_string, public_key_to_hive_format};
use hive_memo::HiveMemoError;

#[test]
fn test_wif_to_secret_key_uncompressed() {
    let wif = "5KV4qZ1obXQPwUQqitD5Tx86Writ4tbeDAo68WLXhcU3ZaHR1M7";
    let secret_key = wif_to_secret_key(wif);
    assert!(secret_key.is_ok());
}

#[test]
fn test_public_key_from_string_valid() {
    let key_str = "STM8NdWaHRo41w1VdmsErA7iX1hnzkc2Z87evTUTBsiSg2PeTzX37";
    let public_key = public_key_from_string(key_str);
    assert!(public_key.is_ok());
}

#[test]
fn test_public_key_from_string_invalid_prefix() {
    let key_str = "ABC5PQVrcekY3psFdYxRDXtYRNNWsPjeHtTvfhUtKaiADPvRqSVYM";
    let public_key = public_key_from_string(key_str);
    assert!(matches!(public_key, Err(HiveMemoError::InvalidPublicKeyFormat(_))));
}

#[test]
fn test_public_key_to_hive_format() {
    let wif = "5KV4qZ1obXQPwUQqitD5Tx86Writ4tbeDAo68WLXhcU3ZaHR1M7";
    let secret_key = wif_to_secret_key(wif).unwrap();
    let public_key = secret_key.public_key();
    let hive_format = public_key_to_hive_format(&public_key);
    assert!(hive_format.starts_with("STM"));
}
