// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

#[test_only]
module sui::ecdsa_r1_tests {
    use sui::ecdsa_r1;
    
    #[test]
    fun test_ecrecover_pubkey() {
        // test case generated against https://docs.rs/secp256r1/latest/secp256r1/
        let hashed_msg = x"57caa176af1ac0433c5df30e8dabcd2ec1af1e92a26eced5f719b88458777cd6";

        let sig = x"84dc8043979a2d8f3238b086893adfa6bfe6b2b87b0b13453bcd48ce99bbb807104a492d26ee51608ae1eb8f5f8eb9386303611b42634fe18b1543fe4efbb0b000";
        let pubkey_bytes = x"020257e02f7cff75df5bbcbe9717f1ad946b14673f9b6c97fb98cdcdef47e05609";

        let pubkey = ecdsa_r1::ecrecover(&sig, &hashed_msg);
        assert!(pubkey == pubkey_bytes, 0);
    }

    #[test]
    fun test_ecrecover_pubkey_2() {
        // Test case from go-ethereum: https://github.com/ethereum/go-ethereum/blob/master/crypto/signature_test.go#L37
        let hashed_msg = x"ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008";
        let sig = x"90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc9301";
        let pubkey_bytes = x"02e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f15878109880a";

        let pubkey = ecdsa_r1::ecrecover(&sig, &hashed_msg);
        assert!(pubkey == pubkey_bytes, 0);
    }

    #[test]
    #[expected_failure(abort_code = ecdsa_r1::EFailToRecoverPubKey)]
    fun test_ecrecover_pubkey_fail_to_recover() {
        let hashed_msg = x"00";
        let sig = x"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        ecdsa_r1::ecrecover(&sig, &hashed_msg);
    }

    #[test]
    #[expected_failure(abort_code = ecdsa_r1::EInvalidSignature)]
    fun test_ecrecover_pubkey_invalid_sig() {
        let hashed_msg = x"ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008";
        // incorrect length sig
        let sig = x"90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e549984a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93";
        ecdsa_r1::ecrecover(&sig, &hashed_msg);
    }

    #[test]
    fun test_secp256r1_verify_fails_with_recoverable_sig() {
        let msg = x"48656c6c6f2c20776f726c6421";
        let pk = x"0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a";
        let sig = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d2700";
        let verify = ecdsa_r1::secp256r1_verify(&sig, &pk, &msg);
        assert!(verify == false, 0);
        
        let sig_1 = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d2701";
        let verify_1 = ecdsa_r1::secp256r1_verify(&sig_1, &pk, &msg);
        assert!(verify_1 == false, 0);
    }

    #[test]
    fun test_secp256r1_verify_success_with_nonrecoverable_sig() {
        let msg = x"48656c6c6f2c20776f726c6421";
        let pk = x"0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a";
        let sig = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d27";
        let verify = ecdsa_r1::secp256r1_verify(&sig, &pk, &msg);
        assert!(verify == true, 0)
    }

    #[test]
    fun test_secp256r1_verify_recoverable_sig_success() {
        let msg = x"48656c6c6f2c20776f726c6421";
        let pk = x"0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a";
        let sig = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d2700";
        let verify = ecdsa_r1::secp256r1_verify_recoverable(&sig, &pk, &msg);
        assert!(verify == true, 0);

        // wrong recovery id fails to verify
        let sig_1 = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d2701";
        let verify_1 = ecdsa_r1::secp256r1_verify_recoverable(&sig_1, &pk, &msg);
        assert!(verify_1 == false, 0);
    }

    #[test]
    fun test_secp256r1_verify_recoverable_sig_fails() {
        let msg = x"48656c6c6f2c20776f726c6421";
        let pk = x"0227322b3a891a0a280d6bc1fb2cbb23d28f54906fd6407f5f741f6def5762609a";
        let sig = x"63943a01af84b202f80f17b0f567d0ab2e8b8c8b0c971e4b253706d0f4be91204d69c018c5ca4bb8b8587772467e2e32cc71c067336709862145246a5e778d27";
        let verify = ecdsa_r1::secp256r1_verify_recoverable(&sig, &pk, &msg);
        assert!(verify == false, 0)
    }

    #[test]
    fun test_secp256r1_invalid_public_key_length() {
        let msg = x"57caa176af1ac0433c5df30e8dabcd2ec1af1e92a26eced5f719b88458777cd6";
        let pk = x"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let sig = x"9c7a72ff1e7db1646b9f9443cb1a3563aa3a6344e4e513efb96258c7676ac4895953629d409a832472b710a028285dfec4733a2c1bb0a2749e465a18292b8bd601";
        
        let verify = ecdsa_r1::secp256r1_verify(&sig, &pk, &msg);
        assert!(verify == false, 0)
    }
}
