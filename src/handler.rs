use crate::{
    cache::{CacheKey, CacheState, CachedEntry, DnsCaches},
    config::AppConfig,
    filters::Filters,
    recursor_engine::RecursorEngine,
    zones::ZoneStore,
};

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};

use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};

use hickory_proto::ProtoErrorKind;
use hickory_resolver::{ResolveErrorKind, TokioResolver};

use tokio::spawn;
use tokio::time::sleep;

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

    fn set_common_flags(req: &Request, header: &mut hickory_proto::op::Header, rcode: ResponseCode) {
        header.set_message_type(MessageType::Response);
        header.set_op_code(OpCode::Query);
        header.set_response_code(rcode);

        // RD lo define el cliente; lo preservamos
        header.set_recursion_desired(req.recursion_desired());

        // RA: el servidor anuncia capacidad de recursión
        header.set_recursion_available(true);

        // AD: no afirmamos DNSSEC (no validamos)
        header.set_authentic_data(false);

        // AA: no somos autoritativos
        header.set_authoritative(false);
    }

    // Opción B: conservar por compat/debug (serialización)
    #[allow(dead_code)]
    fn encode_message(msg: &Message) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(512);
        let mut enc = BinEncoder::new(&mut buf);
        msg.emit(&mut enc)?;
        Ok(buf)
    }

    #[allow(dead_code)]
    fn min_ttl_from_records(records: &[Record]) -> Option<Duration> {
        records
            .iter()
            .map(|r| r.ttl() as u64)
            .min()
            .map(Duration::from_secs)
    }

    fn build_msg_from_records(records: &[Record], rcode: ResponseCode, req_id: u16, rd: bool) -> anyhow::Result<Vec<u8>> {
        let mut m = Message::new();
        m.set_id(req_id);
        m.set_message_type(MessageType::Response);
        m.set_op_code(OpCode::Query);
        m.set_response_code(rcode);
        m.set_recursion_desired(rd);
        m.set_recursion_available(true);
        m.set_authentic_data(false);

        for r in records {
            m.add_answer(r.clone());
        }

        let mut buf = Vec::with_capacity(512);
        let mut enc = BinEncoder::new(&mut buf);
        m.emit(&mut enc)?;
        Ok(buf)
    }

    async fn send_cached_bytes<R: ResponseHandler>(req: &Request, mut response: R, bytes: &[u8]) -> Option<ResponseInfo> {
        let cached = Message::from_bytes(bytes).ok()?;
        let mut header = *req.header();
        Self::set_common_flags(req, &mut header, cached.response_code());

        let msg = MessageResponseBuilder::from_message_request(req).build(
            header,
            cached.answers().iter(),
            iter::empty(),
            iter::empty(),
            iter::empty(),
        );

        Some(
            response
                .send_response(msg)
                .await
                .unwrap_or_else(|_| ResponseInfo::from(*req.header())),
        )
    }

    async fn refresh_answer_cache(
        caches: Arc<DnsCaches>,
        forwarder: Option<TokioResolver>,
        recursor: Option<Arc<RecursorEngine>>,
        key: CacheKey,
        qname: Name,
        qtype: RecordType,
        do_bit: bool,
    ) -> anyhow::Result<()> {
        let (records, rcode) = if let Some(fwd) = forwarder {
            match fwd.lookup(qname, qtype).await {
                Ok(lookup) => (
                    lookup.records().iter().cloned().collect::<Vec<Record>>(),
                    ResponseCode::NoError,
                ),
                Err(e) => match e.kind() {
                    ResolveErrorKind::Proto(pe) => match pe.kind() {
                        ProtoErrorKind::NoRecordsFound { response_code, .. } => (vec![], *response_code),
                        _ => (vec![], ResponseCode::ServFail),
                    },
                    _ => (vec![], ResponseCode::ServFail),
                },
            }
        } else if let Some(rec) = recursor {
            let mut last_err = None;
            let mut result = None;

            for attempt in 0..3 {
                match rec.resolve(qname.clone(), qtype, do_bit).await {
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
                    let _ = last_err;
                    (vec![], ResponseCode::ServFail)
                }
            }
        } else {
            (vec![], ResponseCode::ServFail)
        };

        // Conservador: refrescamos sólo positivos con answers.
        if rcode == ResponseCode::NoError && !records.is_empty() {
            // bytes sin authority/additional (suficiente para estos tests / dig básico)
            let bytes = {
                let ttl_secs = records.iter().map(|r| r.ttl() as u64).min().unwrap_or(30);
                let ttl = caches.clamp_ttl(Duration::from_secs(ttl_secs));
                let msg_bytes = {
                    let mut m = Message::new();
                    m.set_message_type(MessageType::Response);
                    m.set_op_code(OpCode::Query);
                    m.set_response_code(rcode);
                    m.set_recursion_available(true);
                    m.set_authentic_data(false);
                    for r in &records {
                        m.add_answer(r.clone());
                    }
                    let mut buf = Vec::with_capacity(512);
                    let mut enc = BinEncoder::new(&mut buf);
                    m.emit(&mut enc)?;
                    buf
                };
                let entry = CachedEntry::new(msg_bytes, ttl, caches.stale_window());
                caches.answers.insert(key, entry).await;
            };
            let _ = bytes;
        }

        Ok(())
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(&self, req: &Request, mut response: R) -> ResponseInfo {
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
            Self::set_common_flags(req, &mut header, ResponseCode::NoError);

            let msg = MessageResponseBuilder::from_message_request(req)
                .build(header, recs.iter(), iter::empty(), iter::empty(), iter::empty());

            return response
                .send_response(msg)
                .await
                .unwrap_or_else(|_| ResponseInfo::from(*req.header()));
        }

        // 2) cache (answers) con Prefetch / Stale-While-Revalidate
        let key = Self::cache_key(&qname, qtype, do_bit);

        if let Some(entry) = self.caches.answers.get(&key).await {
            match self.caches.classify(&entry) {
                CacheState::Fresh => {
                    if let Some(info) = Self::send_cached_bytes(req, response, &entry.bytes).await {
                        return info;
                    }
                    // Si falla el decode, caemos a resolver normal.
                }

                CacheState::NearExpiry | CacheState::Stale => {
                    let info = Self::send_cached_bytes(req, response, &entry.bytes).await;

                    // Revalidación en background (prefetch / SWR)
                    let caches = self.caches.clone();
                    let forwarder = self.forwarder.clone();
                    let recursor = self.recursor.clone();
                    let key2 = key.clone();
                    let qname2 = qname.clone();

                    spawn(async move {
                        let _ = DnsHandler::refresh_answer_cache(
                            caches,
                            forwarder,
                            recursor,
                            key2,
                            qname2,
                            qtype,
                            do_bit,
                        )
                        .await;
                    });

                    if let Some(info) = info {
                        return info;
                    }
                    // Si falla decode, caemos a resolver normal.
                }

                CacheState::Dead => {
                    // caer a resolución normal
                }
            }
        }

        // 3) cache negativo existente (bytes)
        if let Some(bytes) = self.caches.negative.get(&key).await {
            if let Some(info) = Self::send_cached_bytes(req, response, &bytes).await {
                return info;
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
                        ProtoErrorKind::NoRecordsFound { response_code, .. } => (vec![], *response_code),
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
                    let _ = last_err;
                    (vec![], ResponseCode::ServFail)
                }
            }
        } else {
            (vec![], ResponseCode::ServFail)
        };

        // construir respuesta final
        let mut header = *req.header();
        Self::set_common_flags(req, &mut header, rcode);

        let msg = MessageResponseBuilder::from_message_request(req)
            .build(header, records.iter(), iter::empty(), iter::empty(), iter::empty());

        // --- write-through cache (positivo y negativo) ---
        // Guardamos un hickory_proto::op::Message serializado (no MessageResponse),
        // porque el cache-hit reconstruye la respuesta a partir de ese Message.
        if let Ok(bytes) = Self::build_msg_from_records(&records, rcode, req.id(), req.recursion_desired()) {
            if rcode == ResponseCode::NoError && !records.is_empty() {
                let ttl_secs = records.iter().map(|r| r.ttl() as u64).min().unwrap_or(30);
                let ttl = self.caches.clamp_ttl(Duration::from_secs(ttl_secs));
                let entry = CachedEntry::new(bytes.clone(), ttl, self.caches.stale_window());
                self.caches.answers.insert(key.clone(), entry).await;
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
