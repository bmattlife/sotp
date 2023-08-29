pub mod otp {

    use std::time::SystemTime;

    use hmac::{Hmac, Mac};
    use sha1::Sha1;

    type HmacSha1 = Hmac<Sha1>;

    #[derive(Debug)]
    pub enum Algorithm {
        SHA1,
        SHA256,
        SHA512,
    }

    #[derive(Debug)]
    pub enum Secret {
        Raw(Vec<u8>),
        Encoded(String),
    }

    impl Secret {
        fn as_base32(&self) -> String {
            match self {
                Self::Raw(bytes) => {
                    base32::encode(base32::Alphabet::RFC4648 { padding: false }, bytes)
                }
                Self::Encoded(string) => string.clone(),
            }
        }
    }

    #[derive(Debug)]
    pub struct Totp {
        secret: Secret,
        issuer: String,
        account_name: String,
        algorithm: Algorithm,
        digits: Option<u32>,
        period: Option<u64>,
    }

    impl Totp {
        pub fn new(
            secret: Secret,
            issuer: String,
            account_name: String,
            algorithm: Algorithm,
        ) -> Self {
            Self {
                secret,
                issuer,
                account_name,
                algorithm,
                digits: None,
                period: None,
            }
        }

        fn get_timesteps(&self) -> Result<u64, std::time::SystemTimeError> {
            let period = self.period.unwrap_or(30);
            let unix_time_secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs();

            Ok(unix_time_secs / period)
        }

        pub fn get(&self) -> String {
            let mut mac = HmacSha1::new_from_slice(self.secret.as_bytes()).unwrap();
            mac.update(&self.get_timesteps().to_be_bytes());

            let result = mac.finalize().into_bytes();

            let offset = (result.last().unwrap() & 15) as usize;
            let bin_code =
                u32::from_be_bytes(result[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff;
            let totp = bin_code % 10_u32.pow(self.digits.unwrap_or(6));
            totp.to_string()
        }
    }
}
