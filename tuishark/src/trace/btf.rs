#[cfg(feature = "trace")]
use std::fs;

#[cfg(feature = "trace")]
const BTF_MAGIC: u16 = 0xEB9F;
#[cfg(feature = "trace")]
const BTF_KIND_STRUCT: u32 = 4;

#[cfg(feature = "trace")]
#[derive(Debug, Clone)]
pub struct SkbOffsets {
    pub transport_header: usize,
    pub network_header: usize,
    pub head: usize,
    pub dev: usize,
    pub sk: usize,
}

#[cfg(feature = "trace")]
#[derive(Debug, Clone)]
pub struct NetdevOffsets {
    pub ifindex: usize,
    pub nd_net: usize,
    pub name: usize,
}

#[cfg(feature = "trace")]
#[derive(Debug, Clone)]
pub struct NetOffsets {
    pub ns_common: usize,
}

#[cfg(feature = "trace")]
#[derive(Debug, Clone)]
pub struct NsCommonOffsets {
    pub inum: usize,
}

#[cfg(feature = "trace")]
impl SkbOffsets {
    pub fn defaults() -> Self {
        Self {
            transport_header: 182,
            network_header: 184,
            head: 200,
            dev: 16,
            sk: 24,
        }
    }
}

#[cfg(feature = "trace")]
impl NetdevOffsets {
    pub fn defaults() -> Self {
        Self { ifindex: 224, nd_net: 264, name: 288 }
    }
}

#[cfg(feature = "trace")]
impl NetOffsets {
    pub fn defaults() -> Self {
        Self { ns_common: 152 }
    }
}

#[cfg(feature = "trace")]
impl NsCommonOffsets {
    pub fn defaults() -> Self {
        Self { inum: 24 }
    }
}

#[cfg(feature = "trace")]
pub struct ResolvedOffsets {
    pub skb: SkbOffsets,
    pub netdev: NetdevOffsets,
    pub net_ns_inum: usize,
}

#[cfg(feature = "trace")]
impl ResolvedOffsets {
    pub fn defaults() -> Self {
        Self {
            skb: SkbOffsets::defaults(),
            netdev: NetdevOffsets::defaults(),
            net_ns_inum: 152 + 24,
        }
    }
}

#[cfg(feature = "trace")]
pub fn resolve_from_btf() -> Result<ResolvedOffsets, String> {
    let data = fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("cannot read /sys/kernel/btf/vmlinux: {e}"))?;

    let btf = BtfParser::parse(&data)?;

    let skb_members = btf.struct_members("sk_buff")?;
    let skb = SkbOffsets {
        transport_header: find_offset(&skb_members, "transport_header")?,
        network_header: find_offset(&skb_members, "network_header")?,
        head: find_offset(&skb_members, "head")?,
        dev: find_offset(&skb_members, "dev")?,
        sk: find_offset(&skb_members, "sk")?,
    };

    let netdev_members = btf.struct_members("net_device")?;
    let netdev = NetdevOffsets {
        ifindex: find_offset(&netdev_members, "ifindex")?,
        nd_net: find_offset(&netdev_members, "nd_net")?,
        name: find_offset(&netdev_members, "name")?,
    };

    let net_members = btf.struct_members("net")?;
    let ns_off = find_offset(&net_members, "ns")?;
    let nscommon_members = btf.struct_members("ns_common")?;
    let inum_off = find_offset(&nscommon_members, "inum")?;

    Ok(ResolvedOffsets {
        skb,
        netdev,
        net_ns_inum: ns_off + inum_off,
    })
}

#[cfg(feature = "trace")]
fn find_offset(members: &[(String, usize)], name: &str) -> Result<usize, String> {
    members
        .iter()
        .find(|(n, _)| n == name)
        .map(|(_, off)| *off)
        .ok_or_else(|| format!("field '{name}' not found in BTF struct"))
}

#[cfg(feature = "trace")]
struct BtfParser {
    strings: Vec<u8>,
    types: Vec<BtfRawType>,
}

#[cfg(feature = "trace")]
struct BtfRawType {
    name_off: u32,
    kind: u32,
    size_type: u32,
    members: Vec<BtfRawMember>,
}

#[cfg(feature = "trace")]
struct BtfRawMember {
    name_off: u32,
    type_id: u32,
    bit_offset: u32,
}

#[cfg(feature = "trace")]
impl BtfParser {
    fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 24 {
            return Err("BTF data too short".into());
        }

        let magic = u16::from_le_bytes([data[0], data[1]]);
        if magic != BTF_MAGIC {
            return Err(format!("bad BTF magic: 0x{magic:04x}"));
        }

        let hdr_len = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let type_off = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let type_len = u32::from_le_bytes([data[12], data[13], data[14], data[15]]) as usize;
        let str_off = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
        let str_len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;

        let type_start = hdr_len + type_off;
        let str_start = hdr_len + str_off;

        if str_start + str_len > data.len() || type_start + type_len > data.len() {
            return Err("BTF section out of bounds".into());
        }

        let strings = data[str_start..str_start + str_len].to_vec();

        let mut types = Vec::new();
        let mut pos = type_start;
        let type_end = type_start + type_len;

        while pos + 12 <= type_end {
            let name_off = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            let info = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let size_type = u32::from_le_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
            pos += 12;

            let kind = (info >> 24) & 0x1f;
            let vlen = (info & 0xffff) as usize;

            let mut members = Vec::new();

            if kind == BTF_KIND_STRUCT || kind == 5 {
                for _ in 0..vlen {
                    if pos + 12 > type_end {
                        break;
                    }
                    let m_name = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
                    let m_type = u32::from_le_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
                    let m_offset = u32::from_le_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]]);
                    pos += 12;
                    members.push(BtfRawMember { name_off: m_name, type_id: m_type, bit_offset: m_offset });
                }
            } else {
                let extra = match kind {
                    1 => 4,           // INT
                    3 => 12,          // ARRAY: 3 u32s
                    6 => vlen * 8,    // ENUM
                    13 => vlen * 8,   // FUNC_PROTO
                    14 => 4,          // VAR
                    15 => vlen * 12,  // DATASEC
                    17 => 4,          // DECL_TAG
                    19 => vlen * 12,  // ENUM64
                    _ => 0,
                };
                pos += extra;
            }

            types.push(BtfRawType { name_off, kind, size_type, members });
        }

        Ok(Self { strings, types })
    }

    fn get_string(&self, off: u32) -> &str {
        let start = off as usize;
        if start >= self.strings.len() {
            return "";
        }
        let end = self.strings[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|p| start + p)
            .unwrap_or(self.strings.len());
        std::str::from_utf8(&self.strings[start..end]).unwrap_or("")
    }

    fn struct_members(&self, name: &str) -> Result<Vec<(String, usize)>, String> {
        for (idx, ty) in self.types.iter().enumerate() {
            if (ty.kind == BTF_KIND_STRUCT || ty.kind == 5) && self.get_string(ty.name_off) == name {
                let mut result = Vec::new();
                self.collect_members(idx, 0, &mut result);
                return Ok(result);
            }
        }
        Err(format!("struct '{name}' not found in kernel BTF"))
    }

    fn collect_members(&self, type_idx: usize, base_bit_offset: u32, result: &mut Vec<(String, usize)>) {
        let ty = &self.types[type_idx];
        for m in &ty.members {
            let field_name = self.get_string(m.name_off);
            let abs_bit_offset = base_bit_offset + m.bit_offset;

            if field_name.is_empty() {
                // Anonymous struct/union — recurse into it
                // type_id is 1-based, types vec is 0-based
                if m.type_id > 0 && (m.type_id as usize - 1) < self.types.len() {
                    self.collect_members(m.type_id as usize - 1, abs_bit_offset, result);
                }
            } else {
                result.push((field_name.to_string(), (abs_bit_offset / 8) as usize));
            }
        }
    }
}

#[cfg(test)]
#[cfg(feature = "trace")]
mod tests {
    use super::*;

    #[test]
    fn resolve_defaults() {
        let d = ResolvedOffsets::defaults();
        assert_eq!(d.skb.transport_header, 182);
        assert_eq!(d.skb.network_header, 184);
        assert_eq!(d.skb.head, 200);
        assert_eq!(d.netdev.ifindex, 224);
        assert_eq!(d.net_ns_inum, 176);
    }

    #[test]
    fn resolve_from_kernel_btf() {
        if std::fs::metadata("/sys/kernel/btf/vmlinux").is_err() {
            eprintln!("Skipping BTF test — /sys/kernel/btf/vmlinux not available");
            return;
        }
        let offsets = resolve_from_btf().expect("BTF resolution failed");
        assert!(offsets.skb.transport_header > 0);
        assert!(offsets.skb.network_header > 0);
        assert!(offsets.skb.head > 0);
        assert!(offsets.netdev.ifindex > 0);
        assert!(offsets.net_ns_inum > 0);
    }
}
