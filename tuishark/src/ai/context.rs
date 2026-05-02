use serde_json::{json, Value};

use crate::dissect::model::{Layer, LinkMeta, PacketDetail, PacketSummary};
use crate::trace::model::{ContainerInfo, ProcessInfo};

use super::model::ChatMessage;

const SYSTEM_PROMPT: &str = "\
You are a network packet analysis tutor embedded in TuiShark.\n\
Explain only from the supplied packet context.\n\
Be accurate, concise, and educational.\n\
Prefer protocol facts over speculation.\n\
If information is missing or ambiguous, say what cannot be determined.\n\
Do not invent payload contents that are not present in the supplied fields or bytes.\n\
Connect general networking knowledge to the concrete selected packet.\n\
Structure the answer for a terminal UI.";

const WHOLE_PACKET_PROMPT: &str = "\
Explain this packet at a high level for someone learning networking.\n\
\n\
Answer these questions:\n\
1. What protocol stack and packet type does this represent?\n\
2. What are the source and destination endpoints?\n\
3. What important flags, codes, ports, lengths, or header fields stand out?\n\
4. What does this packet likely mean in the flow?\n\
5. Are there any warnings, anomalies, retransmissions, resets, fragmentation, \
truncation, private/public address notes, or security-relevant observations?";

const FIELD_PROMPT: &str = "\
Explain the selected packet field for someone learning networking.\n\
\n\
Cover:\n\
1. What this field means generally.\n\
2. How to interpret this packet's value.\n\
3. How this field relates to the current packet and connection.\n\
4. Whether the value is normal, suspicious, or context-dependent.";

pub fn build_packet_context(
    summary: &PacketSummary,
    raw: Option<&[u8]>,
    detail: Option<&PacketDetail>,
    max_raw_bytes: usize,
    trace_info: Option<&ProcessInfo>,
    container_info: Option<&ContainerInfo>,
    link_type_name: &str,
) -> Value {
    let mut ctx = json!({
        "index": summary.index,
        "timestamp": summary.timestamp,
        "link_type": link_type_name,
        "source": summary.source,
        "destination": summary.destination,
        "protocol": summary.protocol.to_string(),
        "length": summary.length,
        "original_length": summary.original_length,
        "info": summary.info,
    });

    if let Some(port) = summary.src_port {
        ctx["src_port"] = json!(port);
    }
    if let Some(port) = summary.dst_port {
        ctx["dst_port"] = json!(port);
    }

    if let Some(ref meta) = summary.link_meta {
        match meta {
            LinkMeta::Pflog(pf) => {
                ctx["link_meta"] = json!({
                    "type": "pflog",
                    "action": pf.action.to_string(),
                    "direction": pf.direction.to_string(),
                    "interface": pf.ifname,
                    "rule_number": pf.rule_number,
                });
            }
            LinkMeta::Enc(enc) => {
                ctx["link_meta"] = json!({
                    "type": "enc",
                    "spi": format!("0x{:08x}", enc.spi),
                    "flags": crate::dissect::model::enc_flags_str(enc.flags),
                    "address_family": enc.address_family,
                });
            }
        }
    }

    if let Some(raw_bytes) = raw {
        let cap = raw_bytes.len().min(max_raw_bytes);
        let hex: String = raw_bytes[..cap]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        ctx["raw_hex"] = json!(hex);
        if cap < raw_bytes.len() {
            ctx["raw_hex_truncated"] = json!(true);
        }
    }

    if let Some(detail) = detail {
        let layers: Vec<Value> = detail
            .layers
            .iter()
            .map(|layer| serialize_layer(layer))
            .collect();
        ctx["layers"] = json!(layers);
    }

    if let Some(info) = trace_info {
        ctx["trace"] = json!({
            "process": info.comm_str(),
            "pid": info.pid,
            "uid": info.uid,
        });
    }

    if let Some(ci) = container_info {
        ctx["container"] = json!({
            "netns": ci.netns_inum,
            "device": ci.dev_name_str(),
            "tcp_state": ci.tcp_state_str(),
        });
    }

    ctx
}

fn serialize_layer(layer: &Layer) -> Value {
    let fields: Vec<Value> = layer
        .fields
        .iter()
        .map(|f| {
            json!({
                "name": f.name,
                "value": f.value,
            })
        })
        .collect();
    json!({
        "name": layer.name,
        "fields": fields,
    })
}

pub fn build_field_context(
    detail: &PacketDetail,
    layer_index: usize,
    field_index: Option<usize>,
) -> Value {
    let Some(layer) = detail.layers.get(layer_index) else {
        return json!({});
    };

    let mut ctx = json!({
        "selected_layer": layer.name,
    });

    if let Some(fi) = field_index {
        if let Some(field) = layer.fields.get(fi) {
            ctx["selected_field"] = json!({
                "name": field.name,
                "value": field.value,
            });
        }
    }

    ctx
}

pub fn build_whole_packet_messages(context_json: &str) -> Vec<ChatMessage> {
    vec![
        ChatMessage {
            role: "system".into(),
            content: SYSTEM_PROMPT.into(),
        },
        ChatMessage {
            role: "user".into(),
            content: format!(
                "{WHOLE_PACKET_PROMPT}\n\nPacket context:\n{context_json}"
            ),
        },
    ]
}

pub fn build_field_messages(
    field_context_json: &str,
    packet_context_json: &str,
) -> Vec<ChatMessage> {
    vec![
        ChatMessage {
            role: "system".into(),
            content: SYSTEM_PROMPT.into(),
        },
        ChatMessage {
            role: "user".into(),
            content: format!(
                "{FIELD_PROMPT}\n\nSelected field context:\n{field_context_json}\n\n\
                 Full packet context:\n{packet_context_json}"
            ),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::model::{LayerField, Protocol};

    fn test_summary() -> PacketSummary {
        PacketSummary {
            index: 42,
            timestamp: 1714650000.123456,
            source: "192.168.1.100".into(),
            destination: "93.184.216.34".into(),
            protocol: Protocol::Tcp,
            length: 74,
            original_length: 74,
            info: "54321 → 443 [SYN] Seq=0 Win=65535".into(),
            src_port: Some(54321),
            dst_port: Some(443),
            link_meta: None,
        }
    }

    fn test_detail() -> PacketDetail {
        PacketDetail {
            layers: vec![
                Layer {
                    name: "Ethernet II".into(),
                    fields: vec![
                        LayerField {
                            name: "Source".into(),
                            value: "aa:bb:cc:dd:ee:ff".into(),
                            byte_range: Some((6, 12)),
                        },
                    ],
                },
                Layer {
                    name: "TCP".into(),
                    fields: vec![
                        LayerField {
                            name: "Flags".into(),
                            value: "SYN".into(),
                            byte_range: None,
                        },
                        LayerField {
                            name: "Seq".into(),
                            value: "0".into(),
                            byte_range: None,
                        },
                    ],
                },
            ],
        }
    }

    #[test]
    fn packet_context_basic_fields() {
        let summary = test_summary();
        let ctx = build_packet_context(&summary, None, None, 512, None, None, "Ethernet");
        assert_eq!(ctx["index"], 42);
        assert_eq!(ctx["source"], "192.168.1.100");
        assert_eq!(ctx["protocol"], "TCP");
        assert_eq!(ctx["src_port"], 54321);
        assert_eq!(ctx["dst_port"], 443);
        assert_eq!(ctx["link_type"], "Ethernet");
    }

    #[test]
    fn packet_context_with_layers() {
        let summary = test_summary();
        let detail = test_detail();
        let ctx = build_packet_context(&summary, None, Some(&detail), 512, None, None, "Ethernet");
        let layers = ctx["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0]["name"], "Ethernet II");
        assert_eq!(layers[1]["fields"][0]["name"], "Flags");
        assert_eq!(layers[1]["fields"][0]["value"], "SYN");
    }

    #[test]
    fn raw_bytes_capped() {
        let summary = test_summary();
        let raw = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let ctx = build_packet_context(&summary, Some(&raw), None, 3, None, None, "Ethernet");
        assert_eq!(ctx["raw_hex"], "aabbcc");
        assert_eq!(ctx["raw_hex_truncated"], true);
    }

    #[test]
    fn raw_bytes_not_truncated_when_within_limit() {
        let summary = test_summary();
        let raw = vec![0x01, 0x02];
        let ctx = build_packet_context(&summary, Some(&raw), None, 512, None, None, "Ethernet");
        assert_eq!(ctx["raw_hex"], "0102");
        assert!(ctx.get("raw_hex_truncated").is_none());
    }

    #[test]
    fn field_context_with_field() {
        let detail = test_detail();
        let ctx = build_field_context(&detail, 1, Some(0));
        assert_eq!(ctx["selected_layer"], "TCP");
        assert_eq!(ctx["selected_field"]["name"], "Flags");
        assert_eq!(ctx["selected_field"]["value"], "SYN");
    }

    #[test]
    fn field_context_layer_only() {
        let detail = test_detail();
        let ctx = build_field_context(&detail, 0, None);
        assert_eq!(ctx["selected_layer"], "Ethernet II");
        assert!(ctx.get("selected_field").is_none());
    }

    #[test]
    fn whole_packet_messages_structure() {
        let msgs = build_whole_packet_messages("{}");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert!(msgs[0].content.contains("network packet analysis tutor"));
        assert_eq!(msgs[1].role, "user");
        assert!(msgs[1].content.contains("protocol stack"));
    }

    #[test]
    fn field_messages_structure() {
        let msgs = build_field_messages("{\"selected_layer\":\"TCP\"}", "{}");
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[1].role, "user");
        assert!(msgs[1].content.contains("selected_layer"));
    }

    #[test]
    fn packet_context_no_ports() {
        let mut summary = test_summary();
        summary.src_port = None;
        summary.dst_port = None;
        summary.protocol = Protocol::Icmp;
        let ctx = build_packet_context(&summary, None, None, 512, None, None, "Ethernet");
        assert!(ctx.get("src_port").is_none());
        assert!(ctx.get("dst_port").is_none());
    }

    #[test]
    fn packet_context_with_trace_info() {
        let summary = test_summary();
        let mut info = ProcessInfo {
            pid: 1234,
            uid: 1000,
            comm: [0u8; 16],
        };
        info.comm[..4].copy_from_slice(b"curl");
        let ctx = build_packet_context(&summary, None, None, 512, Some(&info), None, "Ethernet");
        assert_eq!(ctx["trace"]["process"], "curl");
        assert_eq!(ctx["trace"]["pid"], 1234);
        assert_eq!(ctx["trace"]["uid"], 1000);
    }
}
