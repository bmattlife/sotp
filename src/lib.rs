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
    pub struct Totp {
        secret: String,
        issuer: Option<String>,
        account_name: Option<String>,
        algorithm: Option<Algorithm>,
        digits: Option<u32>,
        period: Option<u64>,
    }

    impl Totp {
        pub fn new(secret: String) -> Self {
            Self {
                secret: secret,
                issuer: None,
                account_name: None,
                algorithm: None,
                digits: None,
                period: None,
            }
        }

        fn get_timesteps(&self) -> u64 {
            let period = self.period.unwrap_or(30);
            let unix_time_secs = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            unix_time_secs / period
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
