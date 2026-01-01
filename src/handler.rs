use crate::{
    cache::{CacheKey, DnsCaches},
    config::AppConfig,
    filters::Filters,
    recursor_engine::RecursorEngine,
    zones::ZoneStore,
};

use hickory_proto::op::{MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};

use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use hickory_proto::ProtoErrorKind;
use tokio::time::sleep;
use hickory_resolver::{ResolveErrorKind, TokioResolver};

use std::iter;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct DnsHandler {
    pub cfg: AppConfig,
    zones: Arc<ZoneStore>,
    filters: Arc<Filters>,
    caches: Arc<DnsCaches>,
    forwarder: Option<TokioResolver>,
    recursor: Option<Arc<RecursorEngine>>,
}

impl DnsHandler {
    pub fn new(
        cfg: AppConfig,
        zones: ZoneStore,
        filters: Filters,
        caches: DnsCaches,
        forwarder: Option<TokioResolver>,
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

    // Opción B: esto hoy no se usa, pero lo queremos conservar (para cache TTL, debug, etc.)
    #[allow(dead_code)]
    fn encode_message(msg: &hickory_proto::op::Message) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(512);
        let mut enc = BinEncoder::new(&mut buf);
        msg.emit(&mut enc)?;
        Ok(buf)
    }

    // Opción B: idem
    #[allow(dead_code)]
    fn min_ttl_from_records(records: &[Record]) -> Option<Duration> {
        records
            .iter()
            .map(|r| r.ttl() as u64)
            .min()
            .map(Duration::from_secs)
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        req: &Request,
        mut response: R,
    ) -> ResponseInfo {
        // DO bit desde flags (hickory 0.25.x)
        let do_bit = req.edns().map(|e| e.flags().dnssec_ok).unwrap_or(false);

        let query = match req.queries().first() {
            Some(q) => q.clone(),
            None => {
                let msg = MessageResponseBuilder::from_message_request(req)
                    .error_msg(req.header(), ResponseCode::ServFail);
                return response
                    .send_response(msg)
                    .await
                    .unwrap_or_else(|_| ResponseInfo::from(*req.header()));
            }
        };

        let qname = query.name().clone();
        let qtype = query.query_type();

        // 0) filtro
        if !self.filters.domain_allowed(&qname.to_ascii()) {
            let msg = MessageResponseBuilder::from_message_request(req)
                .error_msg(req.header(), ResponseCode::Refused);
            return response
                .send_response(msg)
                .await
                .unwrap_or_else(|_| ResponseInfo::from(*req.header()));
        }

        // 1) zona local
        if let Some(recs) = self.zones.lookup(&qname, qtype) {
            let mut header = *req.header();
            header.set_message_type(MessageType::Response);
    header.set_recursion_available(true);
    header.set_authentic_data(false);
            header.set_op_code(OpCode::Query);
            header.set_response_code(ResponseCode::NoError);

            let msg = MessageResponseBuilder::from_message_request(req)
                .build(header, recs.iter(), iter::empty(), iter::empty(), iter::empty());

            return response
                .send_response(msg)
                .await
                .unwrap_or_else(|_| ResponseInfo::from(*req.header()));
        }

        // 2 y 3) cache (sin or_else con await)
        let key = Self::cache_key(&qname, qtype, do_bit);

        let cached_bytes = if let Some(bytes) = self.caches.answers.get(&key).await {
            Some(bytes)
        } else if let Some(bytes) = self.caches.negative.get(&key).await {
            Some(bytes)
        } else {
            None
        };

        if let Some(bytes) = cached_bytes {
            if let Ok(cached) = hickory_proto::op::Message::from_bytes(&bytes) {
                let mut header = *req.header();
                header.set_message_type(MessageType::Response);
    header.set_recursion_available(true);
    header.set_authentic_data(false);
                header.set_op_code(OpCode::Query);
                header.set_response_code(cached.response_code());

                let msg = MessageResponseBuilder::from_message_request(req).build(
                    header,
                    cached.answers().iter(),
                    iter::empty(),
                    iter::empty(),
                    iter::empty(),
                );

                return response
                    .send_response(msg)
                    .await
                    .unwrap_or_else(|_| ResponseInfo::from(*req.header()));
            }
        }

        // 4) resolver
        let (records, rcode) = if let Some(fwd) = &self.forwarder {
            match fwd.lookup(qname.clone(), qtype).await {
                Ok(lookup) => (
                    lookup.records().iter().cloned().collect::<Vec<Record>>(),
                    ResponseCode::NoError,
                ),
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
            let name: Name = qname.clone().into();

            // Reintento corto para evitar SERVFAIL transitorio por timeouts/red.
            let mut last_err = None;
            let mut result = None;

            for attempt in 0..3 {
                match rec.resolve(name.clone(), qtype, do_bit).await {
                    Ok(lookup) => {
                        result = Some((
                            lookup.records().iter().cloned().collect::<Vec<Record>>(),
                            ResponseCode::NoError,
                        ));
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        if attempt < 2 {
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }

            match result {
                Some(ok) => ok,
                None => {
                    let _ = last_err; // por ahora no lo logueamos
                    (vec![], ResponseCode::ServFail)
                }
            }
        } else {
            (vec![], ResponseCode::ServFail)
        };

        // construir respuesta final
        let mut header = *req.header();
        header.set_message_type(MessageType::Response);
    header.set_recursion_available(true);
    header.set_authentic_data(false);
        header.set_op_code(OpCode::Query);
        header.set_response_code(rcode);

        let msg = MessageResponseBuilder::from_message_request(req)
            .build(header, records.iter(), iter::empty(), iter::empty(), iter::empty());

// --- write-through cache (positivo y negativo) ---
// Guardamos un hickory_proto::op::Message serializado (no MessageResponse),
// porque el cache-hit reconstruye la respuesta a partir de ese Message.
if let Ok(bytes) = {
    let mut m = hickory_proto::op::Message::new();
    m.set_id(req.id());
    m.set_message_type(MessageType::Response);
    m.set_op_code(OpCode::Query);
    m.set_response_code(rcode);
    m.set_recursion_desired(req.recursion_desired());
    m.set_recursion_available(true);
    m.set_authentic_data(false);

    for r in &records {
        m.add_answer(r.clone());
    }
    // Nota: para estos tests no necesitamos Authority/Additional en cache.
    Self::encode_message(&m)
} {
    if rcode == ResponseCode::NoError && !records.is_empty() {
        self.caches.answers.insert(key.clone(), bytes.clone()).await;
    } else if rcode == ResponseCode::NXDomain {
        // Cache negativo con política "2 hits":
        // 1er NXDOMAIN: marcamos probe. 2do NXDOMAIN: recién cacheamos.
        if self.caches.negative.get(&key).await.is_none() {
            if self.caches.negative_probe.get(&key).await.is_some() {
                self.caches.negative.insert(key.clone(), bytes.clone()).await;
            } else {
                self.caches.negative_probe.insert(key.clone(), 1).await;
            }
        }
    }
}

        response
            .send_response(msg)
            .await
            .unwrap_or_else(|_| ResponseInfo::from(*req.header()))
    }
}
