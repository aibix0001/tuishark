# Small Open-Weights Models for Packet/Protocol Explanation in tuishark

## TL;DR
- As of May 2026 there is **no open-weights small generative LLM specifically fine-tuned to explain packets in natural language**. Every dedicated "network/packet" model that has actually released weights (ET-BERT, netFound, rdpahalavan/bert-network-packet-flow, NetBERT) is an encoder/classifier — useful only as a feature/label source, not as the "explain this packet" engine.
- The realistic best path is a **general small instruct model (Qwen3-4B-Instruct-2507, Gemma-3-4B-IT, or Phi-4-mini-Instruct, ~3.8–4B params, all Apache-2.0 / MIT / permissive) driven by structured `tshark -T json -V` input plus a RAG index over RFCs and Wireshark dissector docs**. This pattern is exactly what current research papers (RTSP-RAG, BACnet-RAG, eX-NIDS) already use successfully.
- Treat the dedicated networking models as optional augmenters: use **`snlucsb/netFound-small` (53.4M params, MIT, Hugging Face)** or **`rdpahalavan/bert-network-packet-flow-header-payload` (DistilBERT, Apache-2.0)** as a fast classifier whose label gets concatenated into the explainer prompt — but the natural-language explanation itself must come from a general LLM.

## Key Findings

### 1. Dedicated "network LLMs" — verified status
| Model | Architecture / Size | Weights public? | License | Generative? | Useful for tuishark? |
|---|---|---|---|---|---|
| **ET-BERT** (Lin et al., WWW 2022) | BERT-style encoder, ~110M | Code + pretrained ckpt on `linwhitehat/ET-BERT` GitHub | MIT (repo) | No — classifier head | No (label-only) |
| **netFound v2** (UCSB SNL, Mar 2026) | Hierarchical Transformer encoder; small 53.4M / base ~200M / large 643M | Yes — `snlucsb/netFound-{small,base,large}` on HF (download counts last month: 31 / 9 / 5) | MIT (source repo) | No — MLM-pretrained encoder for classification/regression | Only as classifier feature |
| **netFound v1** (`snlucsb/netFound-640M-base`) | Same architecture, 643M | Yes (57 downloads/month), now deprecated by v2 | MIT | No | Only as classifier feature |
| **Lens** (Wang/Li et al., arXiv 2402.03646, v5 retitled "Knowledge-Guided" Jan 2026) | T5-base (~250M), encoder-decoder | **Not released** — paper only through 5 revisions | N/A | Yes (in paper: classification + header-field generation) | Cannot use — no weights |
| **TrafficLLM** (Cui et al., arXiv 2504.04222) | P-tuning v2 PEFT prefix adapters on ChatGLM2-6B (default) or Llama2-7B/Mistral/Gemma | Adapters on **Google Drive only** (not HF Hub); no SPDX LICENSE file in repo | Unspecified at repo level → use with caution; base model under ChatGLM/Llama license | Yes, but trained for short class labels and structured packet generation — not free-form explanation | Marginal — would need re-finetuning on explanation pairs |
| **NetLLM** (Wu et al., SIGCOMM 2024, `duowuyms/NetLLM`) | DD-LRNA LoRA on Llama2-7B + multimodal encoder + networking head | Code MIT-licensed; **no adapter weights published** (no GitHub Releases, no HF) | MIT (code) | Generative LLM, but heads are task-specific (viewport prediction, ABR, job scheduling) | Not relevant — tasks are not packet parsing |
| **NetGPT** (Chen et al., IEEE Network 2024) | Concept paper / cloud-edge architecture using GPT-2 + LLaMA LoRA | Conceptual / no public packet-explanation checkpoint | — | Generative for personalized content, not for packet semantics | Not relevant |
| **PAC-GPT** (Kholgh & Kostakos 2023) | Fine-tune of OpenAI GPT-3 Babbage for synthetic packet generation | Closed (OpenAI fine-tune); only the CLI tool is open | Closed weights | Generative for *creating* packets, not explaining them | Cannot use |
| **PacketCLIP** (Masukawa et al., arXiv 2503.03747) | CLIP-style joint embedding + GNN | No weights on HF; paper code only | — | No — embedding/classifier | No |
| **LLMcap** (B-YOND, Tulczyjew et al., 2024) | MLM on PCAP key-value dictionaries | Internal / paper only | — | Encoder-style failure detector | No |
| **Net-GPT** (UAV MITM paper, IEEE 2024) | LLM fine-tuned for spoofing UAV/GCS packets | Code+weights not publicly released | — | Generative for adversarial mimicry | Not relevant |
| **NetBERT** (`antoinelouis/netbert`) | BERT-base, 110M, pretrained on Cisco networking *text* (not PCAPs) | Yes on HF | Apache-2.0 | No — MLM/classification | Useful only as RAG retrieval encoder over networking docs |
| **ServeNet** (Yang et al., 2018) | BERT + LSTM web-service classifier | Older, off-topic (web service descriptions) | — | No | No |
| **"PacketBERT"** | Term used loosely; closest match is `rdpahalavan/bert-network-packet-flow-header-payload` (DistilBERT) | Yes on HF | Apache-2.0 | No — 24-class intrusion classifier | Auxiliary classifier only |
| **PacketLLM** | Not a packet model; this is an R/CRAN package for OpenAI chat in RStudio. Name collision. | — | — | — | Irrelevant |

**Bottom line:** Of the named candidates the user asked about, only netFound (HF), ET-BERT (GitHub), NetBERT (HF), and rdpahalavan-DistilBERT (HF) have actual downloadable weights, and **all four are encoder/classifier models**. The two generative-LLM-based projects with public artifacts (TrafficLLM adapters on Google Drive, NetLLM code without weights) target classification labels or non-explanation tasks (viewport prediction / ABR / cluster job scheduling), not free-form packet narration.

### 2. Why general small models are the right primary engine
- Modern packet "explanation" requires:
  1. parsing structured fields (which `tshark -T json -V` already does perfectly via Wireshark dissectors),
  2. mapping fields to RFC semantics,
  3. producing fluent natural language.
  Strengths 1 and 2 are not what byte-level traffic encoders learn — they learn class boundaries over byte distributions. Strength 3 is exactly what general instruct models do.
- Recent peer-reviewed papers that *successfully* generate protocol explanations all use the same recipe: a general LLM + structured input + RAG over RFCs. Examples:
  - "Decoding BACnet Packets" (arXiv 2407.15428) — RAG-augmented LLM summarizing BACnet packet captures.
  - "Retrieval Augmented Generation Based LLM Evaluation For Protocol State Machine Inference With Chain-of-Thought Reasoning" (arXiv 2502.15727 / Springer ICICT 2025, doi:10.1007/978-981-96-6441-2_27) — Gemma-2-9B and Llama-3-8B with RFC 2326 vector store; the abstract states verbatim "Our experiments demonstrate significant improvements of up to 18.19%, 14.81%, and 23.45% in BLEU, ROUGE, and WER, respectively, over baseline models."
  - **eX-NIDS** (arXiv 2507.16241, Houssel/Layeghy/Singh/Portmann, University of Queensland) — for malicious-flow explanation using Llama 3 and GPT-4: "The use of augmented prompts enhances performance by over 20% compared to the Basic-Prompt Explainer." Note this is NIDS flow explanation, not general packet narration, but the architectural lesson transfers.
  - "An LLM-Powered AI Agent Framework for Holistic IoT Traffic Interpretation" (arXiv 2510.13925) — Zeek + RAG + LLM.

### 3. Recommended general small models (all permissive, all run on a DGX Spark trivially)
| Model | Size | License | Notes for tuishark |
|---|---|---|---|
| **Qwen3-4B-Instruct-2507** | 4B (32k ctx) | Apache-2.0 | Per Artificial Analysis (artificialanalysis.ai/models/qwen3-4b-2507-instruct-reasoning), the reasoning variant scores 18 on the Intelligence Index v4.0 vs. 8 median for similar-size open-weight models; non-reasoning instruct scores 12. Strong tool/JSON use; good instruction following. |
| **Gemma-3-4B-IT** | 4B (128k ctx) | Gemma terms (permissive, commercial OK) | Long context — useful for full-flow explanation; multimodal optional |
| **Phi-4-mini-Instruct** | ~3.8B (128k ctx) | MIT | Strong reasoning per param; o200k_base tiktoken vocab; good for structured input |
| **Qwen3-8B** / **Qwen2.5-7B-Instruct** | 7–8B | Apache-2.0 | Drop-in upgrade if 4B quality insufficient; vLLM/SGLang first-class |
| **Llama-3.1-8B-Instruct** | 8B | Llama 3.1 community license (commercial-permitted with conditions) | Mature ecosystem; GGUF/AWQ widely available |
| **Mistral-7B-Instruct-v0.3** | 7B | Apache-2.0 | Smaller VRAM footprint, fully permissive |

For a TUI tool aimed at single-packet snippets, **Qwen3-4B-Instruct-2507 or Gemma-3-4B-IT** is the sweet spot: ~3 GB VRAM at Q4_K_M, 50–150 tok/s on a single GPU, fully Apache-2.0 / commercially clean.

## Details

### Encoder/classifier models — when (and how) to use them
- `snlucsb/netFound-small` (53.4M, MIT, Hierarchical Transformer over PCAP bursts with multi-modal embedding and protocol-aware tokenization) and `rdpahalavan/bert-network-packet-flow-header-payload` (DistilBERT, Apache-2.0, 24-class CIC-IDS-style classifier covering Analysis/Backdoor/Bot/DDoS/DoS variants/Exploits/FTP Patator/Generic/Heartbleed/Infiltration/Normal/Port Scan/Reconnaissance/SSH Patator/Shellcode/Web Attacks/Worms) are cheap (<200 ms CPU) and can run alongside tshark.
- They produce a **label or embedding**, not a sentence. Their output is most useful as a *prefix to the explainer prompt*, e.g. `auxiliary_classifier_label: "DNS query, likely benign (p=0.97)"`. This anchors the LLM and reduces hallucination.
- ET-BERT pretrain checkpoint exists in the `linwhitehat/ET-BERT` repo but is geared to encrypted-traffic fingerprinting; it adds little over netFound for the explanation use case.
- NetBERT (`antoinelouis/netbert`, Apache-2.0) was pretrained by Antoine Louis (Université de Liège, master's thesis 2020, hdl.handle.net/2268.2/9060) on Cisco product documentation — the GitHub repo (`ant-louis/netbert`) states the corpus was "collected by scraping all the text content from cisco.com. It resulted in about 30GB of uncleaned text, collected from 442,028 web pages" (the commonly cited ~23 GB figure refers to the cleaned corpus). On Louis's custom benchmarks NetBERT delivered "networking text classification (0.9% F1 improvement) and networking information retrieval (12.3% improvement on a custom retrieval score)" over base BERT. It is genuinely useful as the **embedding model for a RAG index over RFCs / vendor docs / Wireshark wiki**.

### TrafficLLM details (the closest candidate, but not a fit)
- Adapters are P-tuning v2 PEFT layers on top of ChatGLM2-6B, trained to output short class labels (e.g. malware family) or to *generate* synthetic packet header sequences. They are not trained on (packet, free-form explanation) pairs.
- Distribution channel is **Google Drive** (`drive.google.com/drive/folders/1YjEhdordqZRpnw_oKczwUztcT52T0oQ0`), not Hugging Face; the README has no SPDX license; ChatGLM2 itself has its own model license requiring a separate agreement for commercial use. This is a hard pass for a clean commercial OSS project.

### Lens, NetLLM, PAC-GPT — not viable
- **Lens** (T5-based, both classification and header-field generation) is the most architecturally interesting but **no weights have ever been released** through 5 arXiv revisions (Feb 2024 → Jan 2026). The latest version retitled "Knowledge-Guided Foundation Model for Network Traffic" still ships paper-only, with no `[Code]` tag on lead author Qineng Wang's homepage.
- **NetLLM** code is MIT, but only training scripts for VP/ABR/CJS exist; the top-level README does not link to released LoRA adapters and there are no GitHub Releases.
- **PAC-GPT** is a closed OpenAI fine-tune of Babbage; weights are not retrievable.

### Practical integration architecture for tuishark
```
[ user selects packet in TUI ]
        │
        ▼
[ tshark -T json -V on that packet ]   ──► structured fields, dissector names
        │
        ▼
┌─────────────────────────────────────────────────────────────┐
│  Prompt builder                                             │
│    - system: "You are a Wireshark protocol expert..."       │
│    - few-shot examples (TCP SYN, DNS query, TLS ClientHello)│
│    - tshark JSON of selected packet (truncated to ~2 KB)    │
│    - optional: rdpahalavan/netFound-small classifier label  │
│    - RAG: top-3 chunks from RFC index + Wireshark docs      │
└─────────────────────────────────────────────────────────────┘
        │
        ▼
[ Qwen3-4B / Gemma-3-4B / Phi-4-mini via llama.cpp or vLLM ]
        │
        ▼
[ streamed natural-language explanation rendered in TUI pane ]
```
- **Inference backend on the DGX Spark:** llama.cpp + GGUF for the lowest-overhead per-packet path (the request rate from a TUI is essentially one-at-a-time); vLLM/SGLang only buys throughput you don't need here, but is fine if you already run them.
- **RAG index:** the IETF RFC series exceeded 9,950 documents by April 2026 (per the IETF `rfc-index-latest.txt`, last updated 28 Apr 2026); restrict to active networking RFCs — IP, TCP, UDP, DNS, TLS, HTTP, QUIC, ICMP, ARP, BGP, OSPF, DHCP, etc., a working set of ~200–400 RFCs. Add the Wireshark display-filter reference and the dissector source comments. Use `BAAI/bge-small-en-v1.5` (or `antoinelouis/netbert` for domain-specific embeddings); FAISS or sqlite-vss for the store.
- **Caching:** key the cache on `(protocol_stack, dissector_field_hash)` rather than on raw bytes — the same SYN to a different IP should hit cache.
- **Token budget:** 1k system + few-shot, 2k packet JSON, 1k RAG, ~512 generated → fits comfortably in any 4B model's 32k window.

## Recommendations

1. **Build the v0 explainer on Qwen3-4B-Instruct-2507 (Apache-2.0) via llama.cpp.** Feed `tshark -T json -V` output plus a curated 6-shot prompt of canonical packet types. Ship this first — you can have it working in a day.
2. **Add a small RAG layer over RFCs + Wireshark dissector docs.** Use `BAAI/bge-small-en-v1.5` or `antoinelouis/netbert` for embeddings; FAISS index. This is where you get the biggest accuracy lift (cf. the +20% gain in eX-NIDS and the up-to-18.19% BLEU / 14.81% ROUGE / 23.45% WER gains in the protocol-FSM RAG paper).
3. **Optionally bolt on `snlucsb/netFound-small` (53M, MIT) as a side classifier.** Its raw-PCAP input pipeline matches your data; surface its top-k label in the prompt as a hint. Skip ET-BERT and TrafficLLM unless you find a specific gap.
4. **If 4B quality is insufficient for niche protocols (e.g., 5G NAS, BGP-LS, IS-IS):** upgrade to Qwen3-8B or Gemma-3-12B, both still fit in <16 GB at Q4. Avoid TrafficLLM/NetLLM — they offer nothing for natural-language explanation.
5. **If you eventually want a custom fine-tune**, the right corpus is **(packet, expert-written explanation) pairs**, not raw PCAP. Generate it semi-synthetically: take a sample PCAP set, run tshark `-V`, and use a stronger teacher (GPT-5, Claude Opus, Gemini 3 Pro) to produce reference explanations grounded in RFCs; then SFT a Qwen3-4B with LoRA. This is the same recipe TrafficLLM uses but with an explanation target instead of a label target.

### Trigger thresholds to revisit this recommendation
- A new release of **Lens** with public weights → reconsider (encoder-decoder T5 is the only architecture in this space designed for both understanding and generation of packet content).
- A community release of a **netFound-Instruct** or **TrafficLLM-Explain** variant with explanation-pair fine-tuning → switch.
- If your homelab evaluation shows Qwen3-4B confabulates field semantics for >5% of test packets → upgrade to 8B or add stronger RAG, don't pivot to a packet-encoder model.

## Caveats

- **Hallucination on rare fields is real.** Even strong general models will invent option semantics for obscure protocols (LISP, BFD, GTP-U variants). The RFC-RAG step is what mitigates this; do not skip it.
- **TrafficLLM has no SPDX license file** in its GitHub repo as of this writing; the underlying ChatGLM2-6B has a custom non-Apache license. If you experiment with it, treat it as research-only.
- **Lens has been "almost released" since Feb 2024**; do not plan around it.
- **netFound v2 model cards** (small/base/large) on Hugging Face show low download counts (5–31/month) and were freshly published on March 9, 2026; the per-card license tag should be re-checked at integration time. The source GitHub repo is MIT.
- **NetBERT was trained on Cisco product documentation** (Antoine Louis's master's thesis at Cisco, 2020). It does not understand byte-level packets at all — it's good only as a domain text embedder for RAG.
- **rdpahalavan/bert-network-packet-flow-header-payload** is trained on CIC-IDS-2017-style features and is biased toward intrusion classes; its labels are noisy on benign protocols and should be displayed as a hint, not as ground truth.
- **PacketLLM on CRAN** is unrelated — it is an RStudio gadget for the OpenAI API, not a packet model.
- **Inference cost is not the bottleneck** on a DGX Spark; the engineering work is in the prompt, the RAG corpus curation, and the tshark→prompt adapter. Budget time accordingly.