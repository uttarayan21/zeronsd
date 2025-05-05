use std::{
    collections::{BTreeMap, HashMap},
    net::IpAddr,
    path::PathBuf,
    str::FromStr,
    sync::Arc,
    time::Duration,
};

use crate::{
    addresses::Calculator,
    errors,
    hosts::{parse_hosts, HostsFile},
    traits::{ToHostname, ToPointerSOA, ToWildcard},
    utils::parse_member_name,
};
use error_stack::{Result, ResultExt};

use async_trait::async_trait;
use ipnetwork::IpNetwork;
use trust_dns_resolver::{
    config::NameServerConfigGroup,
    proto::rr::{dnssec::SupportedAlgorithms, rdata::SOA, RData, Record, RecordSet, RecordType},
    IntoName, Name,
};
use trust_dns_server::{
    authority::{AuthorityObject, Catalog},
    client::rr::{LowerName, RrKey},
    store::{
        forwarder::{ForwardAuthority, ForwardConfig},
        in_memory::InMemoryAuthority,
    },
};

use zerotier_api::central_api;

pub async fn find_members(mut zt: ZTAuthority) {
    let mut timer = tokio::time::interval(zt.update_interval);

    loop {
        match zt.configure_hosts().await {
            Ok(_) => {}
            Err(e) => tracing::error!("error refreshing hosts file: {}", e),
        }

        match zt.get_members().await {
            Ok((network, members)) => match zt.configure_members(network, members).await {
                Ok(_) => {}
                Err(e) => {
                    tracing::error!("error configuring authority: {}", e)
                }
            },
            Err(e) => {
                tracing::error!("error syncing members: {}", e)
            }
        }

        timer.tick().await;
    }
}

pub async fn init_catalog(zt: ZTAuthority) -> Result<Catalog, errors::Error> {
    let mut catalog = Catalog::default();

    let resolv =
        trust_dns_resolver::system_conf::read_system_conf().change_context(errors::Error)?;
    let mut nsconfig = NameServerConfigGroup::new();

    for server in resolv.0.name_servers() {
        nsconfig.push(server.clone());
    }

    let options = Some(resolv.1);
    let config = &ForwardConfig {
        name_servers: nsconfig.clone(),
        options,
    };

    let forwarder = ForwardAuthority::try_from_config(
        Name::root(),
        trust_dns_server::authority::ZoneType::Primary,
        config,
    )
    .expect("Could not initialize forwarder");

    catalog.upsert(Name::root().into(), Box::new(Arc::new(forwarder)));

    catalog.upsert(
        zt.forward_authority.domain_name.clone(),
        zt.forward_authority.box_clone(),
    );

    for (network, authority) in zt.reverse_authority_map {
        catalog.upsert(
            network.to_ptr_soa_name().change_context(errors::Error)?,
            authority.box_clone(),
        )
    }

    Ok(catalog)
}

#[derive(Clone)]
pub struct ZTAuthority {
    pub network_id: String,
    pub hosts_file: Option<PathBuf>,
    pub client: central_api::Client,
    pub reverse_authority_map: HashMap<IpNetwork, RecordAuthority>,
    pub forward_authority: RecordAuthority,
    pub wildcard: bool,
    pub update_interval: Duration,
    pub hosts: Option<Box<HostsFile>>,
}

impl ZTAuthority {
    pub async fn configure_hosts(&mut self) -> Result<(), errors::Error> {
        self.hosts = Some(Box::new(
            parse_hosts(
                self.hosts_file.clone(),
                self.forward_authority.domain_name.clone().into(),
            )
            .change_context(errors::Error)?,
        ));

        for (ip, hostnames) in self.hosts.clone().unwrap().iter() {
            for hostname in hostnames {
                self.forward_authority
                    .match_or_insert(hostname.clone(), &[*ip])
                    .await;
            }
        }

        Ok(())
    }

    pub async fn configure_members(
        &self,
        network: central_api::types::Network,
        members: Vec<central_api::types::Member>,
    ) -> Result<(), errors::Error> {
        let mut forward_records = vec![self.forward_authority.domain_name.clone()];
        let mut reverse_records = HashMap::new();

        self.reverse_authority_map
            .iter()
            .for_each(|(network, authority)| {
                reverse_records.insert(network, vec![authority.domain_name.clone()]);
            });

        if let Some(hosts) = self.hosts.clone() {
            self.forward_authority
                .prune_hosts(hosts.clone())
                .await
                .change_context(errors::Error)?;
            forward_records.append(&mut hosts.values().flatten().map(|v| v.into()).collect());
        }

        let (mut sixplane, mut rfc4193) = (None, None);

        let v6assign = network.config.clone().unwrap().v6_assign_mode;
        if let Some(v6assign) = v6assign {
            if v6assign._6plane.unwrap_or(false) {
                let s = network.clone().sixplane().change_context(errors::Error)?;
                sixplane = Some(s);
            }

            if v6assign.rfc4193.unwrap_or(false) {
                let s = network.clone().rfc4193().change_context(errors::Error)?;
                rfc4193 = Some(s);
                reverse_records
                    .get_mut(&s)
                    .unwrap()
                    .push(s.to_ptr_soa_name().change_context(errors::Error)?)
            }
        }

        for member in members {
            let record = ZTRecord::new(
                &member,
                sixplane,
                rfc4193,
                self.forward_authority.domain_name.clone().into(),
                self.wildcard,
            )
            .change_context(errors::Error)?;

            self.forward_authority
                .insert_member(&mut forward_records, record.clone())
                .await
                .change_context(errors::Error)?;

            if let Some(ips) = member.clone().config.and_then(|c| {
                c.ip_assignments.map(|v| {
                    v.iter()
                        .filter_map(|ip| IpAddr::from_str(ip).ok())
                        .collect::<Vec<IpAddr>>()
                })
            }) {
                for (network, authority) in self.reverse_authority_map.clone() {
                    for ip in ips.clone() {
                        if network.contains(ip) {
                            authority
                                .insert_member_ptr(
                                    reverse_records.get_mut(&network).unwrap(),
                                    record.clone(),
                                )
                                .await
                                .change_context(errors::Error)?;
                        }
                    }
                }
            }

            if let Some(ptr) = rfc4193 {
                if let Some(authority) = self.reverse_authority_map.get(&ptr) {
                    if let Some(records) = reverse_records.get_mut(&ptr) {
                        let ptr = member
                            .rfc4193()
                            .change_context(errors::Error)?
                            .ip()
                            .into_name()
                            .change_context(errors::Error)?;
                        authority
                            .configure_ptr(ptr.clone(), record.ptr_name.clone())
                            .await
                            .change_context(errors::Error)?;
                        records.push(ptr.into());
                    }
                }
            }
        }

        self.forward_authority
            .prune_records(forward_records.clone())
            .await
            .change_context(errors::Error)?;

        for (network, authority) in self.reverse_authority_map.clone() {
            authority
                .prune_records(reverse_records.get(&network).unwrap().clone())
                .await
                .change_context(errors::Error)?;
        }

        Ok(())
    }

    pub async fn get_members(
        &self,
    ) -> Result<(central_api::types::Network, Vec<central_api::types::Member>), errors::Error> {
        let client = self.client.clone();
        let network_id = self.network_id.clone();

        let members = client
            .get_network_member_list(&network_id)
            .await
            .change_context(errors::Error)?;
        let network = client
            .get_network_by_id(&network_id)
            .await
            .change_context(errors::Error)?;

        Ok((network.to_owned(), members.to_owned()))
    }
}

#[derive(Clone)]
pub struct RecordAuthority {
    domain_name: LowerName,
    authority: Arc<InMemoryAuthority>,
}

impl RecordAuthority {
    pub async fn new(
        domain_name: LowerName,
        member_name: LowerName,
    ) -> Result<Self, errors::Error> {
        Ok(Self {
            authority: Arc::new(
                Self::configure_authority(domain_name.clone().into(), member_name.into())
                    .await
                    .change_context(errors::Error)?,
            ),
            domain_name,
        })
    }

    async fn configure_authority(
        domain_name: Name,
        member_name: Name,
    ) -> Result<InMemoryAuthority, errors::Error> {
        let mut map = BTreeMap::new();
        let mut soa = Record::with(domain_name.clone(), RecordType::SOA, 30);

        soa.set_data(Some(RData::SOA(SOA::new(
            domain_name.clone(),
            Name::from_str("administrator")
                .change_context(errors::Error)?
                .append_domain(&domain_name)
                .change_context(errors::Error)?,
            1,
            30,
            0,
            -1,
            0,
        ))));

        let mut soa_rs = RecordSet::new(&domain_name, RecordType::SOA, 1);
        soa_rs.insert(soa, 1);
        map.insert(
            RrKey::new(domain_name.clone().into(), RecordType::SOA),
            soa_rs,
        );

        let mut ns = Record::with(domain_name.clone(), RecordType::NS, 30);
        ns.set_data(Some(RData::NS(member_name)));
        let mut ns_rs = RecordSet::new(&domain_name, RecordType::NS, 1);
        ns_rs.insert(ns, 1);

        map.insert(
            RrKey::new(domain_name.clone().into(), RecordType::NS),
            ns_rs,
        );

        let authority = InMemoryAuthority::new(
            domain_name,
            map,
            trust_dns_server::authority::ZoneType::Primary,
            false,
        )
        .expect("Could not initialize authority");

        Ok(authority)
    }

    async fn replace_ip_record(&self, fqdn: Name, rdatas: Vec<RData>) {
        let serial = self.authority.serial().await;
        for rdata in rdatas {
            let mut address = Record::with(fqdn.clone(), rdata.to_record_type(), 60);
            address.set_data(Some(rdata.clone()));
            tracing::info!("Adding new record {}: ({})", fqdn.clone(), rdata);
            self.authority.upsert(address, serial).await;
        }
    }

    async fn prune_hosts(&self, hosts: Box<HostsFile>) -> Result<(), errors::Error> {
        let serial = self.authority.serial().await;
        let mut rr = self.authority.records_mut().await;

        let mut hosts_map = HashMap::new();

        for (ip, hosts) in hosts.into_iter() {
            for host in hosts {
                if !hosts_map.contains_key(&host) {
                    hosts_map.insert(host.clone(), vec![]);
                }

                hosts_map.get_mut(&host).unwrap().push(ip);
            }
        }

        for (host, ips) in hosts_map.into_iter() {
            for (rrkey, rset) in rr.clone() {
                let key = &rrkey.name().into_name().expect("could not parse name");
                let records = rset.records(false, SupportedAlgorithms::all());

                let rt = rset.record_type();
                let rdatas: Vec<RData> = ips
                    .clone()
                    .into_iter()
                    .filter_map(|i| match i {
                        IpAddr::V4(ip) => {
                            if rt == RecordType::A {
                                Some(RData::A(ip))
                            } else {
                                None
                            }
                        }
                        IpAddr::V6(ip) => {
                            if rt == RecordType::AAAA {
                                Some(RData::AAAA(ip))
                            } else {
                                None
                            }
                        }
                    })
                    .collect();

                if key.eq(&host)
                    && (records.is_empty()
                        || !records
                            .map(|r| r.data().unwrap())
                            .all(|rd| rdatas.contains(rd)))
                {
                    let mut new_rset = RecordSet::new(key, rt, serial);
                    for rdata in rdatas.clone() {
                        new_rset.add_rdata(rdata);
                    }

                    tracing::warn!("Replacing host record for {} with {:#?}", key, ips);
                    rr.remove(&rrkey);
                    rr.insert(rrkey.clone(), Arc::new(new_rset));
                }
            }
        }

        Ok(())
    }

    async fn prune_records(&self, written: Vec<LowerName>) -> Result<(), errors::Error> {
        let mut rrkey_list = Vec::new();

        let mut rr = self.authority.records_mut().await;

        for (rrkey, rs) in rr.clone() {
            let key = &rrkey
                .name()
                .into_name()
                .change_context(errors::Error)?
                .into();
            if !written.contains(key) && rs.record_type() != RecordType::SOA {
                rrkey_list.push(rrkey);
            }
        }

        for rrkey in rrkey_list {
            tracing::warn!("Removing expired record {}", rrkey.name());
            rr.remove(&rrkey);
        }

        Ok(())
    }

    pub async fn match_or_insert(&self, name: Name, ips: &[IpAddr]) {
        let rdatas: Vec<RData> = ips
            .iter()
            .map(|&ip| match ip {
                IpAddr::V4(ip) => RData::A(ip),
                IpAddr::V6(ip) => RData::AAAA(ip),
            })
            .collect();

        for rt in [RecordType::A, RecordType::AAAA] {
            let type_records = self.authority.records().await.clone();
            let name_records = type_records.get(&RrKey::new(name.clone().into(), rt));

            let type_ips: Vec<IpAddr> = ips
                .iter()
                .copied()
                .filter(|ip| {
                    matches!(
                        (ip, rt),
                        (IpAddr::V4(_), RecordType::A) | (IpAddr::V6(_), RecordType::AAAA)
                    )
                })
                .collect();

            match name_records {
                Some(name_records) => {
                    if name_records.is_empty()
                        || !name_records
                            .records_without_rrsigs()
                            .all(|r| rdatas.clone().contains(r.data().unwrap()))
                            && !type_ips.is_empty()
                    {
                        self.replace_ip_record(name.clone(), rdatas.clone()).await;
                    }
                }
                None => {
                    if !type_ips.is_empty() {
                        self.replace_ip_record(name.clone(), rdatas.clone()).await;
                    }
                }
            }
        }
    }

    async fn insert_member(
        &self,
        records: &mut Vec<LowerName>,
        record: ZTRecord,
    ) -> Result<(), errors::Error> {
        self.match_or_insert(record.fqdn.clone(), &record.ips).await;
        records.push(record.fqdn.clone().into());

        if record.wildcard {
            self.match_or_insert(record.fqdn.clone().to_wildcard(), &record.ips)
                .await;
            records.push(record.fqdn.clone().to_wildcard().into());
        }

        if let Some(name) = &record.custom_name {
            self.match_or_insert(name.clone(), &record.ips).await;
            records.push(name.clone().into());

            if record.wildcard {
                self.match_or_insert(record.get_custom_wildcard().unwrap(), &record.ips)
                    .await;
                records.push(record.get_custom_wildcard().unwrap().into());
            }
        }

        Ok(())
    }

    // insert_member_ptr is a lot like insert_authority, but for PTRs.
    async fn insert_member_ptr(
        &self,
        records: &mut Vec<LowerName>,
        record: ZTRecord,
    ) -> Result<(), errors::Error> {
        for ip in record.ips.clone() {
            let ip = ip.into_name().change_context(errors::Error)?;
            self.configure_ptr(ip.clone(), record.ptr_name.clone())
                .await
                .change_context(errors::Error)?;
            records.push(ip.into());
        }

        Ok(())
    }

    async fn configure_ptr(&self, ptr: Name, fqdn: Name) -> Result<(), errors::Error> {
        let records = self.authority.records().await.clone();

        match records.get(&RrKey::new(ptr.clone().into(), RecordType::PTR)) {
            Some(records) => {
                if !records
                    .records_without_rrsigs()
                    .any(|rec| rec.data().unwrap().eq(&RData::PTR(fqdn.clone())))
                {
                    self.set_ptr_record(ptr.clone(), fqdn.clone()).await;
                }
            }
            None => self.set_ptr_record(ptr.clone(), fqdn.clone()).await,
        }

        Ok(())
    }

    async fn set_ptr_record(&self, ptr: Name, fqdn: Name) {
        tracing::info!("Adding/Replacing record {}: ({})", ptr, fqdn);

        let mut records = self.authority.records_mut().await;
        records.remove(&RrKey::new(
            ptr.clone()
                .into_name()
                .expect("Could not coerce IP address into DNS name")
                .into(),
            RecordType::PTR,
        ));
        drop(records);

        let serial = self.authority.serial().await;
        let mut address = Record::with(ptr.clone(), RecordType::PTR, 60);
        address.set_data(Some(RData::PTR(fqdn.clone())));

        self.authority.upsert(address, serial).await;
    }
}

#[async_trait]
impl AuthorityObject for RecordAuthority {
    fn box_clone(&self) -> Box<dyn AuthorityObject> {
        Box::new(self.authority.clone())
    }

    fn zone_type(&self) -> trust_dns_server::authority::ZoneType {
        trust_dns_server::authority::ZoneType::Primary
    }

    fn is_axfr_allowed(&self) -> bool {
        false
    }

    async fn update(
        &self,
        update: &trust_dns_server::authority::MessageRequest,
    ) -> trust_dns_server::authority::UpdateResult<bool> {
        self.authority.update(update).await
    }

    fn origin(&self) -> &trust_dns_server::client::rr::LowerName {
        &self.domain_name
    }

    async fn lookup(
        &self,
        name: &trust_dns_server::client::rr::LowerName,
        rtype: RecordType,
        lookup_options: trust_dns_server::authority::LookupOptions,
    ) -> core::result::Result<
        Box<dyn trust_dns_server::authority::LookupObject>,
        trust_dns_server::authority::LookupError,
    > {
        self.authority.lookup(name, rtype, lookup_options).await
    }

    async fn search(
        &self,
        request_info: trust_dns_server::server::RequestInfo<'_>,
        lookup_options: trust_dns_server::authority::LookupOptions,
    ) -> core::result::Result<
        Box<dyn trust_dns_server::authority::LookupObject>,
        trust_dns_server::authority::LookupError,
    > {
        self.authority.search(request_info, lookup_options).await
    }

    async fn get_nsec_records(
        &self,
        name: &trust_dns_server::client::rr::LowerName,
        lookup_options: trust_dns_server::authority::LookupOptions,
    ) -> core::result::Result<
        Box<dyn trust_dns_server::authority::LookupObject>,
        trust_dns_server::authority::LookupError,
    > {
        self.authority.get_nsec_records(name, lookup_options).await
    }
}

#[derive(Debug, Clone)]
struct ZTRecord {
    fqdn: Name,
    custom_name: Option<Name>,
    ptr_name: Name,
    ips: Vec<IpAddr>,
    wildcard: bool,
}

impl ZTRecord {
    pub fn new(
        member: &central_api::types::Member,
        sixplane: Option<IpNetwork>,
        rfc4193: Option<IpNetwork>,
        domain_name: Name,
        wildcard: bool,
    ) -> Result<Self, errors::Error> {
        let member_name = format!(
            "zt-{}",
            member
                .clone()
                .node_id
                .expect("Node ID for member does not exist")
        );

        let fqdn = member_name
            .to_fqdn(domain_name.clone())
            .change_context(errors::Error)?;

        // this is default the zt-<member id> but can switch to a named name if
        // tweaked in central. see below.
        let mut custom_name = None;
        let mut ptr_name = fqdn.clone();

        if let Some(name) = parse_member_name(member.name.clone(), domain_name) {
            custom_name = Some(name.clone());
            ptr_name = name;
        }

        let mut ips = member
            .clone()
            .config
            .expect("Member config does not exist")
            .ip_assignments
            .map_or(Vec::new(), |v| {
                v.iter()
                    .map(|s| IpAddr::from_str(s).expect("Could not parse IP address"))
                    .collect()
            });

        if sixplane.is_some() {
            ips.push(
                member
                    .clone()
                    .sixplane()
                    .change_context(errors::Error)?
                    .ip(),
            );
        }

        if rfc4193.is_some() {
            ips.push(member.clone().rfc4193().change_context(errors::Error)?.ip());
        }

        Ok(Self {
            wildcard,
            fqdn,
            custom_name,
            ptr_name,
            ips,
        })
    }

    pub fn get_custom_wildcard(&self) -> Option<Name> {
        self.custom_name.as_ref().map(ToWildcard::to_wildcard)
    }
}
