use anyhow::Context;
use serde::Deserialize;
use std::{collections::HashMap, fs, path::Path};
use hickory_proto::rr::{Name, RData, Record, RecordType, rdata};
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone)]
pub struct ZoneStore {
    // qname_lc -> list of records (absolute names)
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
        let mut records: HashMap<String, Vec<Record>> = HashMap::new();
        let path = Path::new(dir);
        if !path.exists() {
            // si no existe, lo creamos vacío; el ejemplo viene en el zip.
            return Ok(Self { records });
        }

        for entry in fs::read_dir(path).with_context(|| format!("read_dir {dir}"))? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|x| x.to_str()) != Some("toml") {
                continue;
            }
            let s = fs::read_to_string(&p)?;
            let z: ZoneFile = toml::from_str(&s)
                .with_context(|| format!("parse zone file {:?}", p))?;
            Self::ingest_zone(&mut records, z)?;
        }

        Ok(Self { records })
    }

    fn ingest_zone(dst: &mut HashMap<String, Vec<Record>>, z: ZoneFile) -> anyhow::Result<()> {
        let origin = Name::from_ascii(&z.origin)
            .with_context(|| format!("origin inválido: {}", z.origin))?;

        for rr in z.records {
            let fqdn = Name::from_ascii(&rr.name)
                .or_else(|_| Name::from_ascii(format!("{}.{}", rr.name.trim_end_matches('.'), origin).as_str()))
                .with_context(|| format!("nombre inválido: {}", rr.name))?;

            let rtype = parse_rrtype(&rr.typ)?;
            let rdata = parse_rdata(rtype, &rr.value, &origin)?;

            let mut rec = Record::new();
            rec.set_name(fqdn.clone());
            rec.set_ttl(z.ttl);
            rec.set_record_type(rtype);
            rec.set_data(Some(rdata));

            let key = fqdn.to_ascii().trim_end_matches('.').to_ascii_lowercase();
            dst.entry(key).or_default().push(rec);
        }
        Ok(())
    }

    pub fn lookup(&self, qname: &Name, qtype: RecordType) -> Option<Vec<Record>> {
        let key = qname.to_ascii().trim_end_matches('.').to_ascii_lowercase();
        let recs = self.records.get(&key)?;
        let mut out = Vec::new();
        for r in recs {
            if r.record_type() == qtype || qtype == RecordType::ANY {
                out.push(r.clone());
            }
        }
        if out.is_empty() { None } else { Some(out) }
    }
}

fn parse_rrtype(s: &str) -> anyhow::Result<RecordType> {
    Ok(match s.to_ascii_uppercase().as_str() {
        "A" => RecordType::A,
        "AAAA" => RecordType::AAAA,
        "CNAME" => RecordType::CNAME,
        "TXT" => RecordType::TXT,
        "MX" => RecordType::MX,
        "NS" => RecordType::NS,
        other => anyhow::bail!("tipo no soportado en zona local: {other}"),
    })
}

fn parse_rdata(rt: RecordType, v: &str, origin: &Name) -> anyhow::Result<RData> {
    Ok(match rt {
        RecordType::A => {
            let ip: Ipv4Addr = v.parse()?;
            RData::A(rdata::A(ip))
        }
        RecordType::AAAA => {
            let ip: Ipv6Addr = v.parse()?;
            RData::AAAA(rdata::AAAA(ip))
        }
        RecordType::CNAME => {
            let name = Name::from_ascii(v)
                .or_else(|_| Name::from_ascii(format!("{}.{}", v.trim_end_matches('.'), origin).as_str()))?;
            RData::CNAME(rdata::CNAME(name))
        }
        RecordType::TXT => {
            RData::TXT(rdata::TXT::new(vec![v.to_string()]))
        }
        RecordType::MX => {
            // "pref host"
            let parts: Vec<&str> = v.split_whitespace().collect();
            if parts.len() != 2 {
                anyhow::bail!("MX value debe ser: '<pref> <host>'");
            }
            let pref: u16 = parts[0].parse()?;
            let ex = Name::from_ascii(parts[1])
                .or_else(|_| Name::from_ascii(format!("{}.{}", parts[1].trim_end_matches('.'), origin).as_str()))?;
            RData::MX(rdata::MX::new(pref, ex))
        }
        RecordType::NS => {
            let ns = Name::from_ascii(v)
                .or_else(|_| Name::from_ascii(format!("{}.{}", v.trim_end_matches('.'), origin).as_str()))?;
            RData::NS(rdata::NS(ns))
        }
        _ => anyhow::bail!("RDATA no soportado para {rt:?}"),
    })
}
