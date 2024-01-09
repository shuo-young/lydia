use std::error::Error;
use std::str::FromStr;
use web3::{
    transports::{Http, WebSocket},
    types::{H160, U256},
    Web3,
};

pub(crate) enum Web3Transport {
    Http(Web3<Http>),
    WebSocket(Web3<WebSocket>),
}

impl Web3Transport {
    pub async fn new(url: &str) -> Result<Self, Box<dyn Error>> {
        if url.starts_with("https") {
            let http = Http::new(url)?;
            Ok(Web3Transport::Http(Web3::new(http)))
        } else {
            let ws = WebSocket::new(url).await?;
            Ok(Web3Transport::WebSocket(Web3::new(ws)))
        }
    }

    // Example method to get the code from the contract.
    // You can implement other methods as needed.
    pub async fn get_code(
        &self,
        address: web3::types::Address,
    ) -> web3::Result<web3::types::Bytes> {
        match self {
            Web3Transport::Http(web3) => web3.eth().code(address, None).await,
            Web3Transport::WebSocket(web3) => web3.eth().code(address, None).await,
        }
    }

    pub async fn get_storage(
        &self,
        storage_addr: H160,
        slot_index: &str,
        byte_low: &str,
        byte_high: &str,
    ) -> Result<String, Box<dyn Error>> {
        let slot_index =
            U256::from_str(slot_index).map_err(|e| format!("Failed to parse slot_index: {}", e))?;

        // Parse byte_low and byte_high from string to usize
        let byte_low =
            usize::from_str(byte_low).map_err(|e| format!("Failed to parse byte_low: {}", e))?;
        let byte_high =
            usize::from_str(byte_high).map_err(|e| format!("Failed to parse byte_high: {}", e))?;
        let storage_content = match self {
            Web3Transport::Http(web3) => web3.eth().storage(storage_addr, slot_index, None).await?,
            Web3Transport::WebSocket(web3) => {
                web3.eth().storage(storage_addr, slot_index, None).await?
            }
        };
        let storage_content_str = format!("{:?}", storage_content);

        let contract_addr = if byte_low == 0 {
            format!(
                "0x{}",
                &storage_content_str[(storage_content_str.len() - (byte_high + 1) * 2)..]
            )
        } else {
            format!(
                "0x{}",
                &storage_content_str[(storage_content_str.len() - (byte_high + 1) * 2)
                    ..(storage_content_str.len() - byte_low * 2)]
            )
        };
        Ok(contract_addr)
    }
}
