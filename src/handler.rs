use crate::{
    cache::{CacheKey, DnsCaches},
    config::AppConfig,
    filters::Filters,
    recursor_engine::RecursorEngine,
    zones::ZoneStore,
};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};

use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use hickory_proto::ProtoErrorKind;
use hickory_resolver::ResolveErrorKind;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct DnsHandler {
    pub cfg: AppConfig,
    zones: Arc<ZoneStore>,
    filters: Arc<Filters>,
    caches: Arc<DnsCaches>,
    forwarder: Option<hickory_resolver::TokioAsyncResolver>,
    recursor: Option<Arc<RecursorEngine>>,
}

impl DnsHandler {
    pub fn new(
        cfg: AppConfig,
        zones: ZoneStore,
        filters: Filters,
        caches: DnsCaches,
        forwarder: Option<hickory_resolver::TokioAsyncResolver>,
        recursor: Option<RecursorEngine>,
    ) -> Self {
        Self {
            cfg,
            zones: Arc::new(zones),
            filters: Arc::new(filters),
            caches: Arc::new(caches),
            forwarder,
            recursor: recursor.map(Arc::new),
        }
    }

    pub async fn serve(self, udp: SocketAddr, tcp: SocketAddr) -> anyhow::Result<()> {
        use hickory_server::ServerFuture;
        use tokio::net::{TcpListener, UdpSocket};

        let udp_socket = UdpSocket::bind(udp).await?;
        let tcp_listener = TcpListener::bind(tcp).await?;

        let mut server = ServerFuture::new(self);
        server.register_socket(udp_socket);
        server.register_listener(tcp_listener, Duration::from_secs(10));

        server.block_until_done().await?;
        Ok(())
    }

    fn cache_key(query_name: &Name, query_type: RecordType, do_bit: bool) -> CacheKey {
        CacheKey {
            qname_lc: query_name
                .to_ascii()
                .trim_end_matches('.')
                .to_ascii_lowercase(),
            qtype: query_type.into(),
            do_bit,
        }
    }

    fn encode_message(msg: &Message) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(512);
        let mut enc = BinEncoder::new(&mut buf);
        msg.emit(&mut enc)?;
        Ok(buf)
    }

    fn min_ttl_from_records(records: &[Record]) -> Option<Duration> {
        records
            .iter()
            .map(|r| r.ttl() as u64)
            .min()
            .map(Duration::from_secs)
    }

    fn refused(req: &Request) -> Message {
        let mut m = Message::new();
        m.set_id(req.id());
        m.set_message_type(MessageType::Response);
        m.set_op_code(OpCode::Query);
        m.set_response_code(ResponseCode::Refused);
        m
    }

    fn servfail(req: &Request) -> Message {
        let mut m = Message::new();
        m.set_id(req.id());
        m.set_message_type(MessageType::Response);
        m.set_op_code(OpCode::Query);
        m.set_response_code(ResponseCode::ServFail);
        m
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        req: &Request,
        mut response: R,
    ) -> ResponseInfo {
        // Hickory server 0.25.x: Request expone queries()/edns()/header()
        let do_bit = req.edns().map(|e| e.dnssec_ok()).unwrap_or(false);

        let query = match req.queries().first() {
            Some(q) => q.clone(),
            None => {
                let m = Self::servfail(req);
                return match response.send_response(m).await {
                    Ok(info) => info,
                    Err(_) => ResponseInfo::from(*req.header()),
                };
            }
        };

        let qname = query.name().clone(); // (en Hickory suele ser LowerName)
        let qtype = query.query_type();

        // 0) filtro por dominio
        if !self.filters.domain_allowed(&qname.to_ascii()) {
            let m = Self::refused(req);
            return match response.send_response(m).await {
                Ok(info) => info,
                Err(_) => ResponseInfo::from(*req.header()),
            };
        }

        // 1) zona local
        if let Some(recs) = self.zones.lookup(&qname, qtype) {
            let mut m = Message::new();
            m.set_id(req.id());
            m.set_message_type(MessageType::Response);
            m.set_op_code(OpCode::Query);
            m.set_response_code(ResponseCode::NoError);
            m.add_query(query.clone());
            for r in recs {
                m.add_answer(r);
            }

            return match response.send_response(m).await {
                Ok(info) => info,
                Err(_) => ResponseInfo::from(*req.header()),
            };
        }

        // 2) cache positivo
        let key = Self::cache_key(&qname, qtype, do_bit);
        if let Some(bytes) = self.caches.answers.get(&key).await {
            if let Ok(mut cached) = Message::from_bytes(&bytes) {
                cached.set_id(req.id());
                cached.set_message_type(MessageType::Response);
                return match response.send_response(cached).await {
                    Ok(info) => info,
                    Err(_) => ResponseInfo::from(*req.header()),
                };
            }
        }

        // 3) cache negativo
        if let Some(bytes) = self.caches.negative.get(&key).await {
            if let Ok(mut cached) = Message::from_bytes(&bytes) {
                cached.set_id(req.id());
                cached.set_message_type(MessageType::Response);
                return match response.send_response(cached).await {
                    Ok(info) => info,
                    Err(_) => ResponseInfo::from(*req.header()),
                };
            }
        }

        // 4) resolver (forwarder o recursor)
        let (records, rcode): (Vec<Record>, ResponseCode) = if let Some(fwd) = &self.forwarder {
            match fwd.lookup(qname.clone(), qtype).await {
                Ok(lookup) => {
                    // En 0.25.x, iter() suele dar RData; records() devuelve Record.
                    let recs = lookup.records().iter().cloned().collect::<Vec<Record>>();
                    (recs, ResponseCode::NoError)
                }
                Err(e) => match e.kind() {
                    ResolveErrorKind::Proto(pe) => match pe.kind() {
                        ProtoErrorKind::NoRecordsFound { response_code, .. } => {
                            (vec![], *response_code)
                        }
                        _ => (vec![], ResponseCode::ServFail),
                    },
                    _ => (vec![], ResponseCode::ServFail),
                },
            }
        } else if let Some(rec) = &self.recursor {
            // ✅ FIX: RecursorEngine::resolve espera Name, pero query.name() suele ser LowerName.
            let qname_name: hickory_proto::rr::Name = qname.clone().into();

            match rec.resolve(qname_name, qtype, do_bit).await {
                Ok(lookup) => (
                    lookup.iter().cloned().collect::<Vec<Record>>(),
                    ResponseCode::NoError,
                ),
                Err(_) => (vec![], ResponseCode::ServFail),
            }
        } else {
            (vec![], ResponseCode::ServFail)
        };

        // Armar respuesta
        let mut resp = Message::new();
        resp.set_id(req.id());
        resp.set_message_type(MessageType::Response);
        resp.set_op_code(OpCode::Query);
        resp.set_response_code(rcode);
        resp.add_query(query.clone());
        for r in &records {
            resp.add_answer(r.clone());
        }

        // cache TTL
        let is_negative = records.is_empty()
            && (rcode == ResponseCode::NXDomain || rcode == ResponseCode::NoError);

        let ttl = if !records.is_empty() {
            Self::min_ttl_from_records(&records).unwrap_or(self.caches.min_ttl)
        } else {
            self.caches.negative_ttl
        };
        let ttl = self.caches.clamp_ttl(ttl);

        if let Ok(bytes) = Self::encode_message(&resp) {
            if is_negative {
                self.caches.negative.insert(key.clone(), bytes).await;
                let neg = self.caches.negative.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(ttl).await;
                    neg.invalidate(&key).await;
                });
            } else if rcode == ResponseCode::NoError {
                self.caches.answers.insert(key.clone(), bytes).await;
                let ans = self.caches.answers.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(ttl).await;
                    ans.invalidate(&key).await;
                });
            }
        }

        // send_response devuelve Result<ResponseInfo, io::Error> -> lo aplanamos
        match response.send_response(resp).await {
            Ok(info) => info,
            Err(_) => ResponseInfo::from(*req.header()),
        }
    }
}

