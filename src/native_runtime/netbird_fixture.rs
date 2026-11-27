use super::*;
use std::net::SocketAddr;

#[derive(Deserialize)]
struct Fixture {
    directory: PathBuf,
    xray: PathBuf,
    uid: u32,
    gid: u32,
    servers: [SocketAddr; 2],
}

pub(super) fn record(slot: u8, server: SocketAddr) -> io::Result<Record> {
    let id = random_id()?;
    let host = Ipv4Addr::new(169, 254, 230, slot * 4 + 1);
    let index = (230 << 6) | u16::from(slot);
    let profile = json!({"protocol": "netbird"});
    Ok(Record {
        prepared: Prepared {
            id: format!("c{slot}"),
            generation: id.clone(),
            profile_digest: crate::routing::digest(&profile)?,
            address: Ipv4Addr::new(169, 254, 230, slot * 4 + 2).into(),
            data_port: 22100,
            probe_port: 22101,
            password: random_id()?,
            probe_password: random_id()?,
        },
        profile,
        namespace: format!("wgates-{id}"),
        interface: format!("wgn{}", &id[..10]),
        peer: format!("wgp{}", &id[..10]),
        host,
        host6: Ipv6Addr::new(0xfd72, 0x7767, 0x6174, index, 0, 0, 0, 1),
        peer6: Ipv6Addr::new(0xfd72, 0x7767, 0x6174, index, 0, 0, 0, 2),
        endpoints: ["tcp", "udp"]
            .into_iter()
            .map(|protocol| Endpoint {
                address: server.ip(),
                port: server.port(),
                protocol: protocol.into(),
            })
            .collect(),
        netbird_hosts: BTreeMap::new(),
        namespace_identity: None,
        namespace_file: None,
        firewall_digest: None,
        paused: false,
    })
}

#[test]
#[ignore = "run via tests/netbird_smoke.py on the disposable Linux stand"]
fn bridges() -> io::Result<()> {
    let mut input = io::stdin().lock();
    let Fixture {
        directory,
        xray,
        uid,
        gid,
        servers,
    } = serde_json::from_str(
        &io::BufRead::lines(&mut input)
            .next()
            .transpose()?
            .unwrap_or_default(),
    )?;
    if uid == 0 || gid == 0 {
        return Err(invalid("fixture bridge requires an unprivileged identity"));
    }
    secure_directory(&directory, 0o700, 0o077)?;
    let runtime = Runtime {
        root: directory.clone(),
        directory: directory.clone(),
        uid,
        gid,
        xray: executable(&xray)?,
        netbird: PathBuf::new(),
        openfortivpn: PathBuf::new(),
        instances: BTreeMap::new(),
        reaping: Vec::new(),
    };
    let mut instances = Vec::new();
    let result = (|| {
        let mut bridges = Vec::new();
        for (slot, server) in [1, 2].into_iter().zip(servers) {
            let record = record(slot, server)?;
            runtime.save(&record)?;
            let auth = Authentication::new(Credentials::default(), false)?;
            instances.push(Instance::new(record, auth));
            let instance = instances.last_mut().unwrap();
            runtime.create_network(&mut instance.record)?;
            secure_directory(
                &directory.join(&instance.record.prepared.generation),
                0o700,
                0o077,
            )?;
            runtime.proxy(instance, true)?;
            let prepared = &instance.record.prepared;
            bridges.push(json!({
                "namespace": instance.record.namespace,
                "address": prepared.address,
                "port": prepared.data_port,
                "id": prepared.bridge_id(false)
            }));
        }
        private_write(&directory.join("bridges.json"), &bridges)?;
        io::copy(&mut input, &mut io::sink())?;
        Ok(())
    })();
    let mut cleanup = Ok(());
    for mut instance in instances.into_iter().rev() {
        stop(&mut instance.proxy);
        if let Err(error) = runtime.cleanup(&mut instance.record, true) {
            cleanup = Err(error);
        }
    }
    result.and(cleanup)
}
