use anyhow::Result;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
};
use tokio_stream::StreamExt;
use tokio_util::codec::Framed;

use crate::codec::PacketCodec;

pub mod codec;

// SSH-protoversion-softwareversion SP comments CR LF
const VERSION: &str = "SSH-2.0-softpaw_0.1.0 \r\n";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut stream = BufReader::new(TcpStream::connect(("0.0.0.0", 2222)).await?);
    stream.write_all(VERSION.as_bytes()).await?;

    let mut server_version = String::new();
    stream.read_line(&mut server_version).await?;

    dbg!(server_version);

    let mut framed = Framed::new(stream, PacketCodec::new(35 * 1000, 0));

    while let Some(packet) = framed.try_next().await? {
        dbg!(packet);
    }

    Ok(())
}
