use anyhow::Context;
use serde::Deserialize;
use std::{collections::HashMap, fs, path::Path};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct ZoneStore {
    records: HashMap<String, Vec<Record>>,
}

#[derive(Debug, Deserialize)]
struct ZoneFile {
    origin: String,
    ttl: u32,
    records: Vec<ZoneRecord>,
}

#[derive(Debug, Deserialize)]
struct ZoneRecord {
    name: String,
    #[serde(rename = "type")]
    typ: String,
    value: String,
}

impl ZoneStore {
    pub fn load_dir(dir: &str) -> anyhow::Result<Self> {
        let mut records = HashMap::new();
        let path = Path::new(dir);
        if !path.exists() {
            return Ok(Self { records });
        }

        for entry in fs::read_dir(path).with_context(|| format!("read_dir {dir}"))? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|x| x.to_str()) != Some("toml") {
                continue;
            }
            let s = fs::read_to_string(&p)?;
            let z: ZoneFile = toml::from_str(&s).with_context(|| format!("parse zone file {:?}", p))?;
            Self::ingest_zone(&mut records, z)?;
        }

        Ok(Self { records })
    }

    fn ingest_zone(dst: &mut HashMap<String, Vec<Record>>, z: ZoneFile) -> anyhow::Result<()> {
        let origin = Name::from_ascii(&z.origin).with_context(|| format!("origin inválido: {}", z.origin))?;

        for rr in z.records {
            let fqdn = Name::from_ascii(&rr.name)
                .or_else(|_| Name::from_ascii(format!("{}.{}", rr.name.trim_end_matches('.'), origin).as_str()))
                .with_context(|| format!("nombre inválido: {}", rr.name))?;

            let rtype = parse_rrtype(&rr.typ)?;
            let rdata = parse_rdata(rtype, &rr.value, &origin)?;

            let rec = Record::from_rdata(name, ttl, rdata);

            let key = fqdn.to_ascii().trim_end_matches('.').to_ascii_lowercase();
            dst.entry(key).or_default().push(rec);
        }
        Ok(())
    }

    pub fn lookup(&self, qname: &Name, qtype: RecordType) -> Option<Vec<Record>> {
        let key = qname.to_ascii().trim_end_matches('.').to_ascii_lowercase();
        let recs = self.records.get(&key)?;
        let out: Vec<Record> = recs.iter().filter(|r| r.record_type() == qtype || qtype == RecordType::ANY).cloned().collect();
        if out.is_empty() { None } else { Some(out) }
    }
}

fn parse_rrtype(s: &str) -> anyhow::Result<RecordType> {
    Ok(match s.to_ascii_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "CNAME" => RecordType::CNAME,
        "TXT" => RecordType::TXT,
        other => anyhow::bail!("tipo no soportado en zona local: {other}"),
    })
}

fn parse_rdata(rt: RecordType, v: &str, origin: &Name) -> anyhow::Result<RData> {
    Ok(match rt {
        RecordType::A => RData::A(rdata::A(v.parse::<Ipv4Addr>()?)),
        RecordType::AAAA => RData::AAAA(rdata::AAAA(v.parse::<Ipv6Addr>()?)),
        RecordType::CNAME => {
            let name = Name::from_ascii(v)
                .or_else(|_| Name::from_ascii(format!("{}.{}", v.trim_end_matches('.'), origin).as_str()))?;
            RData::CNAME(rdata::CNAME(name))
        }
        RecordType::TXT => RData::TXT(rdata::TXT::new(vec![v.to_string()])),
        _ => anyhow::bail!("RDATA no soportado para {rt:?}"),
    })
}
