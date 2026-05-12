use serde_json::{json, Value};

use crate::config::ai::AiPromptConfig;
use crate::dissect::model::{Layer, LinkMeta, PacketDetail, PacketSummary};
use crate::trace::model::{ContainerInfo, ProcessInfo};

use super::model::ChatMessage;

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
                    "reason": crate::dissect::model::pflog_reason_str(pf.reason),
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

pub fn build_whole_packet_messages(context_json: &str, prompts: &AiPromptConfig) -> Vec<ChatMessage> {
    vec![
        ChatMessage {
            role: "system".into(),
            content: prompts.system.clone(),
        },
        ChatMessage {
            role: "user".into(),
            content: prompts.render_whole_packet(context_json),
        },
    ]
}

pub fn build_field_messages(
    field_context_json: &str,
    packet_context_json: &str,
    prompts: &AiPromptConfig,
) -> Vec<ChatMessage> {
    vec![
        ChatMessage {
            role: "system".into(),
            content: prompts.system.clone(),
        },
        ChatMessage {
            role: "user".into(),
            content: prompts.render_field(field_context_json, packet_context_json),
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
            eth_src: None,
            eth_dst: None,
            vlan_id: None,
            tcp_flags: 0,
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
        let prompts = AiPromptConfig::default();
        let msgs = build_whole_packet_messages("{}", &prompts);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert!(msgs[0].content.contains("network packet analysis tutor"));
        assert_eq!(msgs[1].role, "user");
        assert!(msgs[1].content.contains("protocol stack"));
    }

    #[test]
    fn field_messages_structure() {
        let prompts = AiPromptConfig::default();
        let msgs = build_field_messages("{\"selected_layer\":\"TCP\"}", "{}", &prompts);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[1].role, "user");
        assert!(msgs[1].content.contains("selected_layer"));
    }

    #[test]
    fn custom_prompts_override_defaults() {
        let prompts = AiPromptConfig {
            system: "Custom system".into(),
            whole_packet: "Custom whole {packet_context_json}".into(),
            field: "Custom field {selected_field_context_json} {packet_context_json}".into(),
        };
        let msgs = build_whole_packet_messages("{\"test\":1}", &prompts);
        assert_eq!(msgs[0].content, "Custom system");
        assert!(msgs[1].content.contains("{\"test\":1}"));

        let msgs = build_field_messages("{\"field\":1}", "{\"pkt\":1}", &prompts);
        assert!(msgs[1].content.contains("{\"field\":1}"));
        assert!(msgs[1].content.contains("{\"pkt\":1}"));
    }

    #[test]
    fn prompts_without_placeholders_append_context() {
        let prompts = AiPromptConfig {
            system: "sys".into(),
            whole_packet: "Explain this packet.".into(),
            field: "Explain this field.".into(),
        };
        let msgs = build_whole_packet_messages("{\"test\":1}", &prompts);
        assert!(msgs[1].content.contains("Packet context:"));
        assert!(msgs[1].content.contains("{\"test\":1}"));

        let msgs = build_field_messages("{\"f\":1}", "{\"p\":1}", &prompts);
        assert!(msgs[1].content.contains("Selected field context:"));
        assert!(msgs[1].content.contains("Full packet context:"));
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
