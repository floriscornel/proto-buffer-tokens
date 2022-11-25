#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use ed25519_dalek::Keypair;
    use proto_buffer_tokens::{Token, TokenSigner, TokenVerifier};
    use rand_07::rngs::OsRng;
    use uuid::Uuid;

    #[test]
    fn encoding_and_decoding_is_consistent() {
        let keypair_base64 = "lqfKGQWmPPpuv/N96ac2sPXaVaEgDsz3qYk/g1en+HP+ELqND/uhgZsQgPA/H6TlCpiVRxTYeYHXQSbNkXXE5Q==";

        let uuid_str = "6e16fb2e-32fc-4f0a-9579-c17e0176c09d";
        let before_date_time_str = "2022-11-24T20:25:00+00:00";
        let after_date_time_str = "2022-11-24T21:25:00+00:00";

        let keypair = Keypair::from_bytes(
            &base64::decode(keypair_base64).expect("Could not decode base64 of public_key_base64"),
        )
        .expect("Could not create keypair from public_key_base64 bytes");

        let public_key = Keypair::from_bytes(
            &base64::decode(keypair_base64).expect("Could not decode base64 of public_key_base64"),
        )
        .expect("Could not create keypair from public_key_base64 bytes")
        .public;

        let user_id = Uuid::parse_str(uuid_str).expect("UUID could not be parsed");
        let not_before: DateTime<Utc> = DateTime::parse_from_rfc3339(before_date_time_str)
            .unwrap()
            .with_timezone(&Utc);
        let not_after = DateTime::parse_from_rfc3339(after_date_time_str)
            .unwrap()
            .with_timezone(&Utc);

        let token = Token {
            user_id,
            not_before,
            not_after,
        };

        let signer = TokenSigner::<ed25519_dalek::Keypair>::new(keypair);
        let verifier = TokenVerifier::<ed25519_dalek::PublicKey>::new(public_key);

        let signed_payload = signer.sign_token(&token);
        let decoded = verifier.get_verified_token(&signed_payload).unwrap();

        assert_eq!(token, decoded);

        let expected_b64_token = "CkAzIwRsTlop06GHU2go21V8TL0XvGW509+OaH/zb9CRxXNTQkK/ubGzPsm+mty70wltZdEI6kcHp/DFOy6XVYIMEh4JCk/8Mi77Fm4RncB2AX7BeZUYnKb/mwYgrML/mwY=";
        let encoded_b64_token = base64::encode(&signed_payload);
        assert_eq!(&encoded_b64_token, expected_b64_token);

        let decoded_base64 = base64::decode(expected_b64_token).unwrap();
        let parsed_token = verifier.get_verified_token(&decoded_base64).unwrap();
        assert_eq!(parsed_token.user_id, user_id);
        assert_eq!(parsed_token.not_before, not_before);
        assert_eq!(parsed_token.not_after, not_after);

        let expected_b91_token = "KABkpB0ooes6`q!O<4[%%rm]HCy,{UgnE5gnhnKy@_!6$M6>`*l;*+V;]{@6g/<!kMF~yC=u^_ugpf^WjZ0MwD6?sx5{Y?Gw@\"VIP(V[zG[2D~%6vWDP~~aJA";
        let encoded_b91_token = String::from_utf8(base91::slice_encode(&signed_payload)).unwrap();
        assert_eq!(&encoded_b91_token, expected_b91_token);

        let decoded_base64 = base91::slice_decode(expected_b91_token.as_bytes());
        let parsed_token = verifier.get_verified_token(&decoded_base64).unwrap();
        assert_eq!(parsed_token.user_id, user_id);
        assert_eq!(parsed_token.not_before, not_before);
        assert_eq!(parsed_token.not_after, not_after);
    }

    #[test]
    fn can_generate_key() {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        let keypair_bytes = keypair.to_bytes();
        let keypair_base64 = base64::encode(keypair_bytes);

        let new_keypair = Keypair::from_bytes(
            &base64::decode(keypair_base64).expect("Could not decode base64 of public_key_base64"),
        )
        .expect("Could not create keypair from public_key_base64 bytes");

        assert_eq!(new_keypair.to_bytes(), keypair_bytes);
    }
}
