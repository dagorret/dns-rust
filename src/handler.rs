use crate::{cache::{CacheKey, DnsCaches}, config::AppConfig, filters::Filters, recursor_engine::RecursorEngine, zones::ZoneStore};
use anyhow::Context;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone)]
pub struct DnsHandler {
    pub cfg: AppConfig,
    zones: Arc<ZoneStore>,
    filters: Arc<Filters>,
    caches: Arc<DnsCaches>,
    recursor: Arc<RecursorEngine>,
}

impl DnsHandler {
    pub fn new(cfg: AppConfig, zones: ZoneStore, filters: Filters, caches: DnsCaches, recursor: RecursorEngine) -> Self {
        Self {
            cfg,
            zones: Arc::new(zones),
            filters: Arc::new(filters),
            caches: Arc::new(caches),
            recursor: Arc::new(recursor),
        }
    }

    pub async fn serve(self, udp: SocketAddr, tcp: SocketAddr) -> anyhow::Result<()> {
        use hickory_server::ServerFuture;
        use tokio::net::{UdpSocket, TcpListener};
        use std::time::Duration;

        let udp_socket = UdpSocket::bind(udp).await
            .with_context(|| format!("no pude bind UDP {udp}"))?;
        let tcp_listener = TcpListener::bind(tcp).await
            .with_context(|| format!("no pude bind TCP {tcp}"))?;

        let mut server = ServerFuture::new(self);
        server.register_socket(udp_socket);
        server.register_listener(tcp_listener, Duration::from_secs(10));
        server.block_until_done().await?;
        Ok(())
    }

    fn cache_key(query_name: &Name, query_type: RecordType, do_bit: bool) -> CacheKey {
        CacheKey {
            qname_lc: query_name.to_ascii().trim_end_matches('.').to_ascii_lowercase(),
            qtype: query_type.into(),
            do_bit,
        }
    }

    fn build_servfail(req: &Request) -> Message {
        let mut m = Message::new();
        m.set_id(req.id());
        m.set_message_type(MessageType::Response);
        m.set_op_code(OpCode::Query);
        m.set_response_code(ResponseCode::ServFail);
        m
    }

    fn build_refused(req: &Request) -> Message {
        let mut m = Message::new();
        m.set_id(req.id());
        m.set_message_type(MessageType::Response);
        m.set_op_code(OpCode::Query);
        m.set_response_code(ResponseCode::Refused);
        m
    }

    fn build_nxdomain(req: &Request) -> Message {
        let mut m = Message::new();
        m.set_id(req.id());
        m.set_message_type(MessageType::Response);
        m.set_op_code(OpCode::Query);
        m.set_response_code(ResponseCode::NXDomain);
        m
    }

    fn encode_message(msg: &Message) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(512);
        let mut enc = BinEncoder::new(&mut buf);
        msg.emit(&mut enc)?;
        Ok(buf)
    }

    fn decode_message(bytes: &[u8]) -> anyhow::Result<Message> {
        Ok(Message::from_bytes(bytes)?)
    }

    fn min_ttl_from_records(records: &[Record]) -> Option<Duration> {
        records.iter().map(|r| r.ttl() as u64).min().map(Duration::from_secs)
    }

    fn is_nodata(resp: &Message) -> bool {
        resp.response_code() == ResponseCode::NoError && resp.answers().is_empty()
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsHandler {
    async fn handle_request<R: ResponseHandler>(&self, req: &Request, mut response: R) -> ResponseInfo {
        let message = req.message();
        let do_bit = message.edns().map(|e| e.dnssec_ok()).unwrap_or(false);

        let query = match message.queries().first() {
            Some(q) => q.clone(),
            None => {
                let m = Self::build_servfail(req);
                return response.send_response(m).await;
            }
        };

        let qname = query.name().clone();
        let qtype = query.query_type();

        // 0) filtros por dominio
        if !self.filters.domain_allowed(&qname.to_ascii()) {
            let m = Self::build_refused(req);
            return response.send_response(m).await;
        }

        // 1) zona local
        if let Some(recs) = self.zones.lookup(&qname, qtype) {
            let mut m = Message::new();
            m.set_id(req.id());
            m.set_message_type(MessageType::Response);
            m.set_op_code(OpCode::Query);
            m.set_response_code(ResponseCode::NoError);
            m.add_query(query);
            for r in recs {
                m.add_answer(r);
            }
            return response.send_response(m).await;
        }

        // 2) cache frontal (positivo)
        let key = Self::cache_key(&qname, qtype, do_bit);
        if let Some(bytes) = self.caches.answers.get(&key).await {
            if let Ok(mut cached) = Self::decode_message(&bytes) {
                cached.set_id(req.id());
                cached.set_message_type(MessageType::Response);
                return response.send_response(cached).await;
            }
        }

        // 3) cache frontal (negativo)
        if let Some(bytes) = self.caches.negative.get(&key).await {
            if let Ok(mut cached) = Self::decode_message(&bytes) {
                cached.set_id(req.id());
                cached.set_message_type(MessageType::Response);
                return response.send_response(cached).await;
            }
        }

        // 4) recursor (iterativo)
        let lookup = match self.recursor.resolve(qname.clone(), qtype, do_bit).await {
            Ok(x) => x,
            Err(e) => {
                tracing::warn!("resolve error {} {:?}: {e:#}", qname, qtype);
                let m = Self::build_servfail(req);
                return response.send_response(m).await;
            }
        };

        // Construimos respuesta basada en el Lookup
        let mut resp_msg = Message::new();
        resp_msg.set_id(req.id());
        resp_msg.set_message_type(MessageType::Response);
        resp_msg.set_op_code(OpCode::Query);
        resp_msg.set_response_code(ResponseCode::NoError);
        resp_msg.add_query(query);

        let records: Vec<Record> = lookup.iter().cloned().collect();
        for r in &records {
            resp_msg.add_answer(r.clone());
        }

        // Si no hay answers, diferenciamos NXDOMAIN/NODATA:
        // Hickory recursor suele devolver error en NXDOMAIN; si llega acá con vacío, lo tratamos como NODATA.
        // (Para NXDOMAIN explícito, el engine devolvería error; acá construimos NOERROR vacío.)
        let is_negative = records.is_empty();

        // TTL para cache frontal
        let ttl = if !is_negative {
            Self::min_ttl_from_records(&records).unwrap_or(self.caches.min_ttl)
        } else {
            self.caches.negative_ttl
        };
        let ttl = self.caches.clamp_ttl(ttl);

        // Guardar en cache frontal
        match Self::encode_message(&resp_msg) {
            Ok(bytes) => {
                if !is_negative {
                    self.caches.answers.insert(key, bytes).await;
                    // moka expira por su propio "time to idle"? no: usamos invalidación manual por TTL:
                    // estrategia: programamos una invalidación best-effort.
                    let answers = self.caches.answers.clone();
                    let key2 = Self::cache_key(&qname, qtype, do_bit);
                    tokio::spawn(async move {
                        tokio::time::sleep(ttl).await;
                        answers.invalidate(&key2).await;
                    });
                } else {
                    self.caches.negative.insert(key, bytes).await;
                    let neg = self.caches.negative.clone();
                    let key2 = Self::cache_key(&qname, qtype, do_bit);
                    tokio::spawn(async move {
                        tokio::time::sleep(ttl).await;
                        neg.invalidate(&key2).await;
                    });
                }
            }
            Err(e) => {
                tracing::debug!("no pude serializar para cache: {e:#}");
            }
        }

        response.send_response(resp_msg).await
    }
}
