//! End-to-end test of the auto-IP control handshake over a real UDP socket
//! (no TUN device, so it runs unprivileged). Exercises the full wire path:
//! encrypt → obfs-free datagram → decrypt → `control::parse`, plus allocation
//! from a [`LeasePool`].

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use shadowvpn::control::{self, Control};
use shadowvpn::crypto::{decrypt_packet, encrypt_packet, evp_bytes_to_key, Cipher};
use shadowvpn::pool::LeasePool;
use tokio::net::UdpSocket;

#[tokio::test]
async fn request_assign_handshake_over_udp() {
    let cipher = Cipher::ChaCha20Poly1305;
    let key = evp_bytes_to_key(b"shared-psk", cipher.key_len());

    let server = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    let server_addr = server.local_addr().unwrap();
    let client = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
    client.connect(server_addr).await.unwrap();

    // Server: answer one REQUEST with an ASSIGN drawn from the pool.
    let server_key = key.clone();
    let srv = tokio::spawn(async move {
        let mut pool = LeasePool::new(
            Ipv4Addr::new(10, 9, 0, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            Duration::from_secs(120),
        );
        let mut buf = vec![0u8; 2048];
        let (n, peer) = server.recv_from(&mut buf).await.unwrap();
        let plaintext = decrypt_packet(cipher, &server_key, &buf[..n]).unwrap();
        assert_eq!(control::parse(&plaintext), Some(Control::Request));

        let ip = pool.allocate(Instant::now()).unwrap();
        let assign = Control::Assign {
            ip,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            peer_ip: Ipv4Addr::new(10, 9, 0, 1),
            mtu: 1400,
        };
        let datagram = encrypt_packet(cipher, &server_key, &assign.encode()).unwrap();
        server.send_to(&datagram, peer).await.unwrap();
        ip
    });

    // Client: send REQUEST, await ASSIGN.
    let request = encrypt_packet(cipher, &key, &Control::Request.encode()).unwrap();
    client.send(&request).await.unwrap();

    let mut buf = vec![0u8; 2048];
    let n = client.recv(&mut buf).await.unwrap();
    let plaintext = decrypt_packet(cipher, &key, &buf[..n]).unwrap();
    let assigned = match control::parse(&plaintext) {
        Some(Control::Assign {
            ip, peer_ip, mtu, ..
        }) => {
            assert_eq!(peer_ip, Ipv4Addr::new(10, 9, 0, 1));
            assert_eq!(mtu, 1400);
            ip
        }
        other => panic!("expected Assign, got {other:?}"),
    };

    let server_ip = srv.await.unwrap();
    assert_eq!(assigned, server_ip);
    assert_ne!(assigned, Ipv4Addr::new(10, 9, 0, 1)); // never the server's own IP
}
