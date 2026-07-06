//! Library of KCP on Tokio

pub use self::{
    config::{KcpConfig, KcpNoDelayConfig, ListenerMode},
    listener::KcpListener,
    stream::KcpStream,
};

mod config;
mod crypt;
mod fec;
mod listener;
mod session;
mod skcp;
mod stream;
mod utils;

// 导出加密相关类型
pub use crypt::{BlockCrypt, NoneBlockCrypt};

#[cfg(feature = "aes")]
pub use crypt::{Aes128BlockCrypt, Aes192BlockCrypt, Aes256BlockCrypt};

#[cfg(feature = "aes-gcm")]
pub use crypt::AesGcmBlockCrypt;

#[cfg(feature = "tea")]
pub use crypt::TeaBlockCrypt;

#[cfg(feature = "xtea")]
pub use crypt::XteaBlockCrypt;

#[cfg(feature = "simple_xor")]
pub use crypt::SimpleXorBlockCrypt;

#[cfg(feature = "blowfish")]
pub use crypt::BlowfishBlockCrypt;

#[cfg(feature = "cast5")]
pub use crypt::Cast5BlockCrypt;

#[cfg(feature = "triple_des")]
pub use crypt::TripleDesBlockCrypt;

#[cfg(feature = "twofish")]
pub use crypt::TwofishBlockCrypt;

#[cfg(feature = "salsa20")]
pub use crypt::Salsa20BlockCrypt;

#[cfg(feature = "sm4")]
pub use crypt::Sm4BlockCrypt;
