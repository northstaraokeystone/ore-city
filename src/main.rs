use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use blake3;
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, Signer, SIGNATURE_LENGTH};
use once_cell::sync::Lazy;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use rs_merkle::{Hasher as MerkleHasher, MerkleTree};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use sha3::{Digest, Sha3_256};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

static FOREST: Lazy<Result<EmpireForest>> =
    Lazy::new(|| EmpireForest::from_file("data/red-loop.yaml"));

const TCQ_THRESHOLD: f64 = 0.92;
const MIX_PHRASE: &str = "BABY GOT BACK LOOP";
const MIX_ANAGRAM: &str = "TAL B. MAXI";
const GLYPH_PATH: &str = "glyphs/entropy-anchor.svg";

#[derive(Parser, Debug)]
#[command(
    name = "ore",
    version = "0.1.0",
    about = "Ore City v∞ Empire Entanglement Merkle Forest"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify roots and transitive uncle proofs
    Verify,
    /// Print receipt, optionally full and export bundle
    Receipt {
        #[arg(long)]
        full: bool,
    },
    /// Render entropy anchor glyph SVG
    Anchor,
    /// Mars mode, 20 year epochs and RTT histogram
    Mars,
    /// Swarm of Valyria / Walk / Bell agents
    Swarm {
        #[arg(default_value = "101")]
        agents: u32,
    },
    /// Doge bounty tip and k proof consensus stub
    DogeTip,
    /// Hybrid quantum re sign of branches
    Quantum,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum ClaimKind {
    Physical,
    Digital,
    CrossAnchor,
}

impl ClaimKind {
    fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "physical" => Self::Physical,
            "digital" => Self::Digital,
            "cross" | "crossanchor" | "cross_anchor" => Self::CrossAnchor,
            _ => Self::Physical,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            Self::Physical => "physical",
            Self::Digital => "digital",
            Self::CrossAnchor => "cross_anchor",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClaimRef {
    target: u32,
    weight: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claim {
    id: u32,
    epoch: u64,
    kind: ClaimKind,
    metrics: Vec<f32>,
    refs: Vec<ClaimRef>,
    hint: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum EntangleKind {
    Bounty,
    Causal,
    Gravity,
}

#[derive(Debug, Clone)]
struct EntangledEdge {
    from: u32,
    to: u32,
    kind: EntangleKind,
    score: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Orbit {
    Vin,
    Optimus,
    Hull,
    Bioreactor,
    Deluge,
    Doge,
    Neuralink,
    Starlink,
    Xai,
    Doodle,
    Mars,
    Aux,
}

#[derive(Debug)]
struct EmpireForest {
    claims: Vec<Claim>,
    root: [u8; 32],
    sparse_root: [u8; 32],
    tcq: f64,
    c_orbit: f64,
    c_bridge: f64,
    c_density: f64,
    margin: f64,
    edges: Vec<EntangledEdge>,
    orbit_scores: HashMap<Orbit, f64>,
}

// EmpireSigner trait for hot-swap
trait EmpireSigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8>;
    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool;
}

struct Ed25519Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519Signer {
    fn new(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }
}

impl EmpireSigner for Ed25519Signer {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing_key.sign(msg).to_bytes().to_vec()
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.len() != SIGNATURE_LENGTH {
            return false;
        }
        let sig = match Signature::try_from(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.verifying_key.verify_strict(msg, &sig).is_ok()
    }
}

#[cfg(feature = "pq")]
struct DilithiumSigner;

#[cfg(feature = "pq")]
impl EmpireSigner for DilithiumSigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        blake3::hash(msg).as_bytes().to_vec()
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        blake3::hash(msg).as_bytes() == sig
    }
}

#[cfg(feature = "hybrid")]
struct HybridSigner {
    ed: Ed25519Signer,
    #[cfg(feature = "pq")]
    pq: DilithiumSigner,
}

#[cfg(feature = "hybrid")]
impl EmpireSigner for HybridSigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        let ed_sig = self.ed.sign(msg);
        #[cfg(feature = "pq")]
        let pq_sig = self.pq.sign(msg);
        #[cfg(not(feature = "pq"))]
        let pq_sig: Vec<u8> = blake3::hash(msg).as_bytes().to_vec();

        let mut combined = Vec::with_capacity(ed_sig.len() + pq_sig.len() + 1);
        combined.push(0x02);
        combined.extend(ed_sig);
        combined.extend(pq_sig);
        combined
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.is_empty() || sig[0] != 0x02 {
            return false;
        }
        let ed_len = SIGNATURE_LENGTH;
        if sig.len() < 1 + ed_len {
            return false;
        }
        let ed_sig = &sig[1..1 + ed_len];
        let pq_sig = &sig[1 + ed_len..];
        let ed_ok = self.ed.verify(msg, ed_sig);

        #[cfg(feature = "pq")]
        let pq_ok = self.pq.verify(msg, pq_sig);
        #[cfg(not(feature = "pq"))]
        let pq_ok = blake3::hash(msg).as_bytes() == pq_sig;

        ed_ok && pq_ok
    }
}

// rs_merkle Hasher using dual_leaf
#[derive(Clone)]
struct DualHasher;

impl MerkleHasher for DualHasher {
    type Hash = [u8; 32];
    fn hash(data: &[u8]) -> Self::Hash {
        dual_leaf(data)
    }
}

// Sir Mix A Lot hunt wiring.
fn main() {
    if let Err(e) = real_main() {
        eprintln!("ore error: {e}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        None => cmd_default(),
        Some(Command::Verify) => cmd_verify(),
        Some(Command::Receipt { full }) => cmd_receipt(full),
        Some(Command::Anchor) => cmd_anchor(),
        Some(Command::Mars) => cmd_mars(),
        Some(Command::Swarm { agents }) => cmd_swarm(agents),
        Some(Command::DogeTip) => cmd_doge_tip(),
        Some(Command::Quantum) => cmd_quantum(),
    }
}

fn cmd_default() -> Result<()> {
    let forest = forest()?;
    if forest.tcq < TCQ_THRESHOLD {
        return Err(format!(
            "TCQ {:.4} below threshold {:.4}",
            forest.tcq, TCQ_THRESHOLD
        )
        .into());
    }
    verify_forest(forest)?;
    pulse_glyph(forest);
    let solved = sir_mix_check(forest)?;
    if solved {
        write_mix_unlock_yaml()?;
    }
    println!("Population: 0 -> ∞");
    Ok(())
}

fn cmd_verify() -> Result<()> {
    let forest = forest()?;
    verify_forest(forest)?;
    for edge in &forest.edges {
        if let Some(from_leaf) = forest.claims.iter().find(|c| c.id == edge.from) {
            if let Some(to_leaf) = forest.claims.iter().find(|c| c.id == edge.to) {
                let from_idx = forest
                    .claims
                    .iter()
                    .position(|c| c.id == edge.from)
                    .unwrap();
                let to_idx = forest
                    .claims
                    .iter()
                    .position(|c| c.id == edge.to)
                    .unwrap();
                let leaves: Vec<[u8; 32]> = forest
                    .claims
                    .iter()
                    .map(|c| dual_leaf(claim_bytes(c).as_slice()))
                    .collect();
                let tree: MerkleTree<DualHasher> = MerkleTree::from_leaves(&leaves);
                let idxs = if from_idx <= to_idx {
                    [from_idx, to_idx]
                } else {
                    [to_idx, from_idx]
                };
                let proof = tree.proof(&idxs);
                let uncle_ok = proof.verify(
                    tree.root().ok_or("no root for uncle")?,
                    &idxs,
                    &[
                        dual_leaf(claim_bytes(from_leaf).as_slice()),
                        dual_leaf(claim_bytes(to_leaf).as_slice()),
                    ],
                    leaves.len(),
                );
                println!(
                    "uncle proof for edge {}-{} kind={:?} score={:.2} verify={}",
                    edge.from, edge.to, edge.kind, edge.score, uncle_ok
                );
            }
        }
    }
    println!(
        "verify: root={} sparse_root={} tcq={:.4} orbit={:.4} bridge={:.4} density={:.4} margin={:.4}",
        hex::encode(forest.root),
        hex::encode(forest.sparse_root),
        forest.tcq,
        forest.c_orbit,
        forest.c_bridge,
        forest.c_density,
        forest.margin
    );
    println!("orbit coherence:");
    for (orbit, score) in &forest.orbit_scores {
        println!("  {:>9}: {:.4}", orbit_name(*orbit), score);
    }
    Ok(())
}

fn cmd_receipt(full: bool) -> Result<()> {
    let forest = forest()?;
    println!("Ore City v∞ receipt");
    println!("claims={}", forest.claims.len());
    println!("root={}", hex::encode(forest.root));
    println!("sparse_root={}", hex::encode(forest.sparse_root));
    println!(
        "tcq={:.4} orbit={:.4} bridge={:.4} density={:.4} margin={:.4}",
        forest.tcq, forest.c_orbit, forest.c_bridge, forest.c_density, forest.margin
    );
    if full {
        for c in &forest.claims {
            println!(
                "#{:02} epoch={} kind={} metrics={:?} refs={}",
                c.id,
                c.epoch,
                c.kind.as_str(),
                c.metrics,
                c.refs.len()
            );
        }
    }
    export_receipt_bundle(forest)?;
    Ok(())
}

fn cmd_anchor() -> Result<()> {
    let forest = forest()?;
    write_anchor_svg(forest)?;
    println!(
        "anchor: glyph at {} color={} tcq={:.4}",
        GLYPH_PATH,
        if forest.tcq >= TCQ_THRESHOLD {
            "NS_GOLD"
        } else {
            "muted"
        },
        forest.tcq
    );
    Ok(())
}

fn cmd_mars() -> Result<()> {
    let forest = forest()?;
    let years = 20_u64;
    let offset = years * 31_557_600;
    let first = forest.claims.first().map(|c| c.epoch).unwrap_or(0);
    let last = forest.claims.last().map(|c| c.epoch).unwrap_or(0);
    println!(
        "mars: epochs [{}..{}] -> [{}..{}] ({} years offset)",
        first,
        last,
        first + offset,
        last + offset,
        years
    );
    let mut buckets = [0_u64; 8];
    for (i, c) in forest.claims.iter().enumerate() {
        let idx = (i % buckets.len()) as usize;
        let pinned_epoch = c.epoch + offset;
        buckets[idx] += (c.metrics.first().cloned().unwrap_or(1.0).abs() * 1000.0) as u64;
        println!(
            "mars leaf {}: epoch pinned to {}, rtt_ms approx {}",
            i, pinned_epoch, buckets[idx]
        );
    }
    println!("mars: RTT histogram leaves (ms-ish): {:?}", buckets);
    let entanglement = forest.tcq;
    println!("mars transitive TCQ: {:.4}", entanglement);
    if entanglement < TCQ_THRESHOLD {
        return Err("mars entanglement below 0.92 - no pinning".into());
    }
    Ok(())
}

fn cmd_swarm(agents: u32) -> Result<()> {
    let forest = forest()?;
    let n = agents.clamp(3, 101);
    let start = now_secs();
    let labels = ["Valyria", "Walk", "Bell"];
    let mut hasher = blake3::Hasher::new();
    let buf_template = Vec::with_capacity(64);

    use std::thread;
    let mut handles = Vec::with_capacity(n as usize);
    for i in 0..n {
        let label = labels[(i as usize) % labels.len()].to_string();
        let root_copy = forest.root;
        let mut local_buf = buf_template.clone();
        let idx = i;
        let handle = thread::spawn(move || {
            local_buf.clear();
            local_buf.extend_from_slice(&root_copy);
            local_buf.extend_from_slice(label.as_bytes());
            local_buf.extend_from_slice(&idx.to_le_bytes());
            let h = blake3::hash(&local_buf);
            let role = swarm_role(&label);
            (h, label, role)
        });
        handles.push(handle);
    }

    for handle in handles {
        let (h, label, role) = handle.join().unwrap();
        hasher.update(h.as_bytes());
        println!(
            "swarm agent: {{\"agent\":\"{}\",\"role\":\"{}\",\"hash\":\"{}\"}}",
            label,
            role,
            h.to_hex()
        );
    }

    let swarm_root = hasher.finalize();
    let elapsed = now_secs() - start;
    println!(
        "swarm summary: agents={} root={} elapsed={:.3}s",
        n,
        swarm_root.to_hex(),
        elapsed
    );
    Ok(())
}

fn cmd_doge_tip() -> Result<()> {
    let forest = forest()?;
    let leaf_claim = forest
        .claims
        .iter()
        .find(|c| matches!(c.kind, ClaimKind::Physical))
        .ok_or("no Doge eligible claim found")?;
    let leaf = dual_leaf(claim_bytes(leaf_claim).as_slice());
    let mut fuse = blake3::Hasher::new();
    fuse.update(&forest.root);
    fuse.update(&leaf);
    let txid = fuse.finalize();
    println!("doge tip: txid={} claim_id={}", txid.to_hex(), leaf_claim.id);

    let proof_ok = multi_proof_check(&forest.claims, leaf)?;
    println!("doge tip: k=3 multi proof consensus={proof_ok}");

    let solved = sir_mix_check(forest)?;
    if solved {
        write_mix_unlock_yaml()?;
    }
    Ok(())
}

fn cmd_quantum() -> Result<()> {
    let forest = forest()?;
    #[cfg(feature = "hybrid")]
    {
        let mut rng = StdRng::from_entropy();
        let signing_key = random_signing_key(&mut rng);
        let ed = Ed25519Signer::new(signing_key);
        #[cfg(feature = "pq")]
        let pq = DilithiumSigner;
        #[cfg(not(feature = "pq"))]
        let pq = DilithiumSigner;
        let hybrid = HybridSigner { ed, pq };
        let sig = hybrid.sign(&forest.root);
        let ok = hybrid.verify(&forest.root, &sig);
        println!("quantum hybrid: sig_len={} verify_ok={}", sig.len(), ok);
    }
    #[cfg(not(feature = "hybrid"))]
    {
        let mut rng = StdRng::from_entropy();
        let signing_key = random_signing_key(&mut rng);
        let ed = Ed25519Signer::new(signing_key);
        let sig = ed.sign(&forest.root);
        let ok = ed.verify(&forest.root, &sig);
        println!("quantum ed only: sig_len={} verify_ok={}", sig.len(), ok);
    }
    sir_mix_check(forest)?;
    Ok(())
}

fn forest() -> Result<&'static EmpireForest> {
    match &*FOREST {
        Ok(f) => Ok(f),
        Err(e) => Err(format!("forest init failed: {e}").into()),
    }
}

impl EmpireForest {
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let raw = fs::read_to_string(path)?;
        let val: Value = serde_yaml::from_str(&raw)?;
        let seq = val
            .as_sequence()
            .ok_or("red-loop.yaml root must be sequence of claims")?;
        let mut claims = Vec::with_capacity(seq.len());
        for (i, v) in seq.iter().enumerate() {
            let id = v.get("id").and_then(Value::as_u64).unwrap_or(i as u64) as u32;
            let epoch = v.get("epoch").and_then(Value::as_u64).unwrap_or(i as u64);
            let kind_str = v
                .get("kind")
                .and_then(Value::as_str)
                .unwrap_or("physical");
            let kind = ClaimKind::from_str(kind_str);
            let metrics = v
                .get("metrics")
                .and_then(Value::as_sequence)
                .map(|s| {
                    s.iter()
                        .filter_map(Value::as_f64)
                        .map(|f| f as f32)
                        .collect::<Vec<f32>>()
                })
                .unwrap_or_else(|| vec![1.0]);
            let refs = v
                .get("refs")
                .and_then(Value::as_sequence)
                .map(|s| {
                    s.iter()
                        .filter_map(|r| {
                            let m = r.as_mapping()?;
                            let t = m.get("target")?.as_u64()? as u32;
                            let w = m.get("weight").and_then(Value::as_f64).unwrap_or(0.95);
                            Some(ClaimRef {
                                target: t,
                                weight: w as f32,
                            })
                        })
                        .collect::<Vec<ClaimRef>>()
                })
                .unwrap_or_default();
            let hint = v
                .get("hint")
                .and_then(Value::as_str)
                .map(|s| s.to_string());
            claims.push(Claim {
                id,
                epoch,
                kind,
                metrics,
                refs,
                hint,
            });
        }

        if claims.is_empty() {
            return Err("red-loop empty".into());
        }

        for w in claims.windows(2) {
            if w[1].epoch < w[0].epoch {
                return Err("non monotonic epochs detected".into());
            }
        }

        let leaves: Vec<[u8; 32]> = claims
            .iter()
            .map(|c| dual_leaf(claim_bytes(c).as_slice()))
            .collect();
        let merkle: MerkleTree<DualHasher> = MerkleTree::from_leaves(&leaves);
        let root = merkle.root().ok_or("no merkle root")?;
        let sparse_root = sparse_forest_root(&leaves);

        let edges = entangle_edges(&claims);
        let (tcq, c_orbit, c_bridge, c_density, margin, orbit_scores) =
            compute_tcq(&claims, &edges);

        if tcq < TCQ_THRESHOLD {
            return Err(format!(
                "TCQ {:.4} below threshold {:.4} (orbit={:.4} bridge={:.4} density={:.4})",
                tcq, TCQ_THRESHOLD, c_orbit, c_bridge, c_density
            )
            .into());
        }

        Ok(EmpireForest {
            claims,
            root,
            sparse_root,
            tcq,
            c_orbit,
            c_bridge,
            c_density,
            margin,
            edges,
            orbit_scores,
        })
    }
}

fn orbit_for_claim(c: &Claim) -> Orbit {
    match c.id {
        1..=5 => Orbit::Vin,
        6..=10 => Orbit::Optimus,
        11..=14 => Orbit::Hull,
        15..=18 => Orbit::Bioreactor,
        19..=22 => Orbit::Deluge,
        23 => Orbit::Doge,
        24..=26 => Orbit::Neuralink,
        27..=30 => Orbit::Starlink,
        31..=35 => Orbit::Xai,
        36..=38 => Orbit::Doodle,
        39..=42 => Orbit::Mars,
        _ => Orbit::Aux,
    }
}

fn orbit_kind_weight(orbit: Orbit) -> f64 {
    match orbit {
        Orbit::Vin
        | Orbit::Optimus
        | Orbit::Hull
        | Orbit::Bioreactor
        | Orbit::Deluge
        | Orbit::Starlink
        | Orbit::Mars => 0.6, // physical spine
        _ => 0.4,             // digital / cross / aux
    }
}

fn orbit_name(o: Orbit) -> &'static str {
    match o {
        Orbit::Vin => "VIN",
        Orbit::Optimus => "Optimus",
        Orbit::Hull => "Hull",
        Orbit::Bioreactor => "Bioreactor",
        Orbit::Deluge => "Deluge",
        Orbit::Doge => "Doge",
        Orbit::Neuralink => "Neuralink",
        Orbit::Starlink => "Starlink",
        Orbit::Xai => "xAI",
        Orbit::Doodle => "Doodle",
        Orbit::Mars => "Mars",
        Orbit::Aux => "Aux",
    }
}

fn cos_sim(a: &[f32], b: &[f32]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 1.0;
    }
    let mut dot = 0.0;
    let mut na = 0.0;
    let mut nb = 0.0;
    for i in 0..len {
        let ai = a[i] as f64;
        let bi = b[i] as f64;
        dot += ai * bi;
        na += ai * ai;
        nb += bi * bi;
    }
    let na = na.sqrt();
    let nb = nb.sqrt();
    if na > 0.0 && nb > 0.0 {
        (dot / (na * nb)).clamp(-1.0, 1.0)
    } else {
        1.0
    }
}

// RLE-style pseudo compression ratio: compressed_len / original_len
fn rle_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 1.0;
    }
    let mut i: usize = 0;
    let mut comp: usize = 0;
    while i < bytes.len() {
        let mut run: usize = 1;
        while i + run < bytes.len() && bytes[i + run] == bytes[i] && run < 255 {
            run += 1;
        }
        comp += 2; // value + count
        i += run;
    }
    comp as f64 / bytes.len() as f64
}

// TCQ: 0.5 * orbit_avg + 0.3 * bridge_fraction + 0.2 * density_guard
fn compute_tcq(
    claims: &[Claim],
    _edges: &[EntangledEdge],
) -> (f64, f64, f64, f64, f64, HashMap<Orbit, f64>) {
    let n = claims.len();
    if n == 0 {
        return (1.0, 1.0, 1.0, 1.0, 0.0, HashMap::new());
    }

    let mut orbit_indices: HashMap<Orbit, Vec<usize>> = HashMap::new();
    let mut claim_orbit: Vec<Orbit> = Vec::with_capacity(n);
    let mut id_to_index: HashMap<u32, usize> = HashMap::with_capacity(n);

    for (idx, c) in claims.iter().enumerate() {
        let o = orbit_for_claim(c);
        orbit_indices.entry(o).or_default().push(idx);
        claim_orbit.push(o);
        id_to_index.insert(c.id, idx);
    }

    let mut orbit_scores: HashMap<Orbit, f64> = HashMap::new();
    let mut orbit_centroids: HashMap<Orbit, Vec<f32>> = HashMap::new();
    let mut claim_coh: Vec<f64> = vec![1.0; n];

    // 1. Orbit coherence: lane-normalize with log10 for sub-1 lanes.
    for (orbit, indices) in &orbit_indices {
        if indices.is_empty() {
            continue;
        }
        let d = claims[indices[0]].metrics.len();
        if d == 0 {
            orbit_scores.insert(*orbit, 1.0);
            orbit_centroids.insert(*orbit, Vec::new());
            continue;
        }

        // Detect "small" lanes (entropy / probabilities).
        let mut lane_is_small = vec![true; d];
        for &idx in indices {
            let m = &claims[idx].metrics;
            for i in 0..d {
                let v = *m.get(i).unwrap_or(&0.0);
                if !(v >= 0.0 && v < 1.0) {
                    lane_is_small[i] = false;
                }
            }
        }

        let mut lane_min = vec![f32::INFINITY; d];
        let mut lane_max = vec![f32::NEG_INFINITY; d];

        for &idx in indices {
            let m = &claims[idx].metrics;
            for i in 0..d {
                let v = *m.get(i).unwrap_or(&0.0);
                let mut t = v;
                if lane_is_small[i] {
                    let x = if v <= 0.0 { 1e-9 } else { v as f64 };
                    t = x.log10() as f32;
                }
                if t < lane_min[i] {
                    lane_min[i] = t;
                }
                if t > lane_max[i] {
                    lane_max[i] = t;
                }
            }
        }

        let mut normalized: Vec<(usize, Vec<f32>)> = Vec::with_capacity(indices.len());
        for &idx in indices {
            let m = &claims[idx].metrics;
            let mut norm = vec![0.0f32; d];
            for i in 0..d {
                let v = *m.get(i).unwrap_or(&0.0);
                let mut t = v;
                if lane_is_small[i] {
                    let x = if v <= 0.0 { 1e-9 } else { v as f64 };
                    t = x.log10() as f32;
                }
                let range = lane_max[i] - lane_min[i];
                norm[i] = if range > 0.0 {
                    (t - lane_min[i]) / range
                } else {
                    0.0
                };
            }
            normalized.push((idx, norm));
        }

        let mut centroid = vec![0.0f32; d];
        for (_idx, norm) in &normalized {
            for i in 0..d {
                centroid[i] += norm[i];
            }
        }
        let len_f = normalized.len() as f32;
        if len_f > 0.0 {
            for v in &mut centroid {
                *v /= len_f;
            }
        }

        let mut good = 0u64;
        let mut ok = 0u64;
        for (idx, norm) in &normalized {
            let coh = cos_sim(norm, &centroid);
            claim_coh[*idx] = coh;
            if coh >= 0.92 {
                good += 1;
            } else if coh >= 0.85 {
                ok += 1;
            }
        }

        let total = normalized.len() as f64;
        let frac_good = good as f64 / total;
        let frac_ok = ok as f64 / total;
        let orbit_score = (frac_good + 0.5 * frac_ok).clamp(0.0, 1.0);
        orbit_scores.insert(*orbit, orbit_score);
        orbit_centroids.insert(*orbit, centroid);
    }

    // Weighted orbit average (physical orbits heavier).
    let mut w_sum = 0.0_f64;
    let mut ws = 0.0_f64;
    for (orbit, score) in &orbit_scores {
        let w = orbit_kind_weight(*orbit);
        ws += w * *score;
        w_sum += w;
    }
    let c_orbit = if w_sum > 0.0 { ws / w_sum } else { 1.0 };

    // Build Merkle tree once for uncle proofs / density.
    let leaves: Vec<[u8; 32]> = claims
        .iter()
        .map(|c| dual_leaf(claim_bytes(c).as_slice()))
        .collect();
    let tree: MerkleTree<DualHasher> = MerkleTree::from_leaves(&leaves);
    let root = tree.root().unwrap_or([0u8; 32]);

    // 2. Bridges: CrossAnchor claims, base on cos-sim, +0.05 if strong ref + uncle proof.
    let mut bridge_sum = 0.0_f64;
    let mut bridge_cnt: u64 = 0;
    for (idx, c) in claims.iter().enumerate() {
        if !matches!(c.kind, ClaimKind::CrossAnchor) {
            continue;
        }
        bridge_cnt += 1;
        let mut score = claim_coh[idx].clamp(0.0, 1.0);

        let strong_ref = c.refs.iter().any(|r| r.weight as f64 > 0.92);
        let mut uncle_ok = false;
        if let Some(&from_idx) = id_to_index.get(&c.id) {
            for r in &c.refs {
                if let Some(&to_idx) = id_to_index.get(&r.target) {
                    let (a, b) = if from_idx <= to_idx {
                        (from_idx, to_idx)
                    } else {
                        (to_idx, from_idx)
                    };
                    let idxs = [a, b];
                    let proof = tree.proof(&idxs);
                    let ok = proof.verify(
                        root,
                        &idxs,
                        &[leaves[a], leaves[b]],
                        leaves.len(),
                    );
                    if ok {
                        uncle_ok = true;
                        break;
                    }
                }
            }
        }

        if strong_ref && uncle_ok {
            score = (score + 0.05_f64).min(1.0_f64);
        }
        bridge_sum += score;
    }
    let c_bridge = if bridge_cnt > 0 {
        bridge_sum / bridge_cnt as f64
    } else {
        1.0
    };

    // 3. Density guard: compression + 90th-percentile distance.
    let mut dists: Vec<f64> = Vec::with_capacity(n);
    for idx in 0..n {
        let coh = claim_coh[idx].clamp(0.0, 1.0);
        dists.push(1.0 - coh);
    }
    dists.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let d90_index = if n == 0 {
        0
    } else {
        (((0.9_f64 * (n as f64)).ceil() as usize).saturating_sub(1)).min(n - 1)
    };
    let d90 = dists[d90_index];
    let bonus_outlier: f64 = if d90 < 0.01_f64 { 0.1_f64 } else { 0.0_f64 };

    let mut all_bytes = Vec::new();
    all_bytes.reserve(n * 64);
    for c in claims {
        all_bytes.extend_from_slice(&claim_bytes(c));
    }
    let comp_ratio = rle_ratio(&all_bytes); // compressed_len / original_len
    let gain = (1.0_f64 - comp_ratio).max(0.0_f64); // compression gain in [0,1]
    let bonus_compress: f64 = if gain > 0.90_f64 { 0.02_f64 } else { 0.0_f64 };
    let base_density: f64 = 0.8_f64;
    let c_density: f64 = (base_density + bonus_compress + bonus_outlier).min(1.0_f64);

    let tcq = 0.5_f64 * c_orbit + 0.3_f64 * c_bridge + 0.2_f64 * c_density;
    let margin = (tcq - TCQ_THRESHOLD).max(0.0_f64);

    (tcq, c_orbit, c_bridge, c_density, margin, orbit_scores)
}

fn claim_bytes(c: &Claim) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + c.metrics.len() * 4 + c.refs.len() * 8);
    out.extend_from_slice(&c.id.to_le_bytes());
    out.extend_from_slice(&c.epoch.to_le_bytes());
    out.extend_from_slice(c.kind.as_str().as_bytes());
    for m in &c.metrics {
        out.extend_from_slice(&m.to_le_bytes());
    }
    for r in &c.refs {
        out.extend_from_slice(&r.target.to_le_bytes());
        out.extend_from_slice(&r.weight.to_le_bytes());
    }
    out
}

fn dual_leaf(data: &[u8]) -> [u8; 32] {
    let h1 = blake3::hash(data);
    let mut sha = Sha3_256::new();
    sha.update(data);
    let h2 = sha.finalize();
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(h1.as_bytes());
    buf[32..].copy_from_slice(&h2);
    *blake3::hash(&buf).as_bytes()
}

fn sparse_forest_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    for leaf in leaves {
        h.update(leaf);
    }
    *h.finalize().as_bytes()
}

fn entangle_edges(claims: &[Claim]) -> Vec<EntangledEdge> {
    let mut edges = Vec::new();
    for c in claims {
        for r in &c.refs {
            let kind = match c.kind {
                ClaimKind::Physical if r.weight > 0.9 => EntangleKind::Bounty,
                ClaimKind::CrossAnchor => EntangleKind::Gravity,
                _ => EntangleKind::Causal,
            };
            let score = if matches!(kind, EntangleKind::Bounty) {
                0.95
            } else {
                0.92
            };
            edges.push(EntangledEdge {
                from: c.id,
                to: r.target,
                kind,
                score,
            });
        }
    }
    edges
}

fn verify_forest(forest: &EmpireForest) -> Result<()> {
    let leaves: Vec<[u8; 32]> = forest
        .claims
        .iter()
        .map(|c| dual_leaf(claim_bytes(c).as_slice()))
        .collect();
    let merkle: MerkleTree<DualHasher> = MerkleTree::from_leaves(&leaves);
    let root = merkle.root().ok_or("no recomputed root")?;
    if root != forest.root {
        return Err("root mismatch".into());
    }
    Ok(())
}

fn pulse_glyph(forest: &EmpireForest) {
    println!("entropy anchor pulse:");
    println!("root={}", hex::encode(forest.root));
    println!(
        "tcq={:.4} orbit={:.4} bridge={:.4} density={:.4} margin={:.4}",
        forest.tcq, forest.c_orbit, forest.c_bridge, forest.c_density, forest.margin
    );
    println!("[⊂∴↺ℵ] Empire Entanglement Merkle Forest online");
}

fn export_receipt_bundle(forest: &EmpireForest) -> Result<()> {
    let dir = Path::new("receipts");
    fs::create_dir_all(dir)?;
    let path = dir.join("red-loop-receipt.bundle");
    let mut f = fs::File::create(&path)?;
    writeln!(f, "# ore-city v∞ receipt bundle")?;
    writeln!(f, "root={}", hex::encode(forest.root))?;
    writeln!(f, "sparse_root={}", hex::encode(forest.sparse_root))?;
    writeln!(
        f,
        "tcq={:.4} orbit={:.4} bridge={:.4} density={:.4} margin={:.4}",
        forest.tcq, forest.c_orbit, forest.c_bridge, forest.c_density, forest.margin
    )?;
    let serialized = serde_yaml::to_string(&forest.claims).unwrap_or_default();
    writeln!(f, "claims:\n{}", serialized)?;
    Ok(())
}

fn write_anchor_svg(forest: &EmpireForest) -> Result<()> {
    let color = if forest.tcq >= TCQ_THRESHOLD {
        "#FFC627"
    } else {
        "#7C7C88"
    };
    let root_bytes = forest.root;
    let qx = (root_bytes[0] as f32 / 255.0 * 20.0 + 12.0) as i32;
    let qy = (root_bytes[1] as f32 / 255.0 * 24.0 + 8.0) as i32;
    let cx = (root_bytes[2] as f32 / 255.0 * 16.0 + 16.0) as i32;
    let cy = (root_bytes[3] as f32 / 255.0 * 4.0 + 40.0) as i32;
    let root_hex = hex::encode(&root_bytes[..8]);
    let svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"64\" height=\"64\" viewBox=\"0 0 64 64\">
<rect x=\"0\" y=\"0\" width=\"64\" height=\"64\" fill=\"#050509\"/>
<circle cx=\"32\" cy=\"32\" r=\"22\" fill=\"none\" stroke=\"{color}\" stroke-width=\"2\"/>
<path d=\"M12 32 Q{} {} 52 32 T12 32\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1.4\"/>
<path d=\"M16 40 C{} {} {} {} 48 40\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1\"/>
<path d=\"M24 20 L32 24 L40 20\" fill=\"none\" stroke=\"{color}\" stroke-width=\"1\"/>
<text x=\"32\" y=\"36\" text-anchor=\"middle\" font-size=\"10\" fill=\"{color}\">⊂∴↺ℵ</text>
<title>entropy-anchor root={root_hex}</title>
</svg>
",
        qx,
        qy,
        cx - 8,
        cy,
        cx + 8,
        cy
    );
    if let Some(parent) = Path::new(GLYPH_PATH).parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(GLYPH_PATH, svg)?;
    Ok(())
}

fn swarm_role(label: &str) -> &'static str {
    match label {
        "Valyria" => "scorch_insert",
        "Walk" => "blame_verify",
        "Bell" => "bury_history",
        _ => "agent",
    }
}

fn multi_proof_check(claims: &[Claim], leaf: [u8; 32]) -> Result<bool> {
    let leaves: Vec<[u8; 32]> = claims
        .iter()
        .map(|c| dual_leaf(claim_bytes(c).as_slice()))
        .collect();
    let tree: MerkleTree<DualHasher> = MerkleTree::from_leaves(&leaves);
    let n = leaves.len();
    if n < 3 {
        return Ok(false);
    }
    let idxs = [0usize, n / 2, n - 1];
    let proof = tree.proof(&idxs);
    let root = tree.root().ok_or("no root for multi proof")?;
    let leaf_leaves = &[leaves[idxs[0]], leaves[idxs[1]], leaves[idxs[2]]];
    let ok = proof.verify(root, &idxs, leaf_leaves, n);
    Ok(ok && idxs.iter().any(|&i| leaves[i] == leaf))
}

fn hybrid_sign_root(root: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>, bool)> {
    let seed = dual_leaf(root);
    let mut rng = StdRng::from_seed(seed);
    let signing_key = random_signing_key(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let msg = root;
    let sig: Signature = signing_key.sign(msg);
    let ok = verifying_key.verify_strict(msg, &sig).is_ok();

    let mut buf = Vec::with_capacity(48);
    buf.extend_from_slice(msg);
    buf.extend_from_slice(b"dilithium-hybrid-stub");
    let pq_sig = blake3::hash(&buf).as_bytes().to_vec();

    Ok((sig.to_bytes().to_vec(), pq_sig, ok))
}

fn random_signing_key(rng: &mut StdRng) -> SigningKey {
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    SigningKey::try_from(&sk_bytes[..]).expect("32-byte secret key")
}

fn sir_mix_check(forest: &EmpireForest) -> Result<bool> {
    let claim23 = match forest.claims.iter().find(|c| c.id == 23) {
        Some(c) => c,
        None => {
            println!("mix: claim #23 missing; hunt not wired yet");
            return Ok(false);
        }
    };
    let hint_hex = match &claim23.hint {
        Some(h) => h,
        None => {
            println!(
                "mix: claim #23 has no hint; expected hex BLAKE3(\"{}\")",
                MIX_PHRASE
            );
            return Ok(false);
        }
    };
    let hint_bytes = match hex::decode(hint_hex) {
        Ok(b) => b,
        Err(_) => {
            println!("mix: invalid hex in claim #23 hint");
            return Ok(false);
        }
    };
    let phrase_hash = blake3::hash(MIX_PHRASE.as_bytes());
    if hint_bytes != phrase_hash.as_bytes() {
        println!("mix: claim #23 hint does not match phrase hash");
        return Ok(false);
    }
    let idx_bytes = &hint_bytes[..4.min(hint_bytes.len())];
    let mut idxs = Vec::with_capacity(idx_bytes.len());
    for b in idx_bytes {
        let idx = (*b as usize) % forest.claims.len();
        idxs.push(idx);
    }
    println!(
        "mix: indices into food/quantum claims from hint {:?}",
        idxs
    );

    let phrase_leaf = dual_leaf(MIX_PHRASE.as_bytes());
    let leaves: Vec<[u8; 32]> = forest
        .claims
        .iter()
        .map(|c| dual_leaf(claim_bytes(c).as_slice()))
        .chain(std::iter::once(phrase_leaf))
        .collect();
    let tree: MerkleTree<DualHasher> = MerkleTree::from_leaves(&leaves);
    let idx = leaves.len() - 1;
    let proof = tree.proof(&[idx]);
    let root = tree.root().ok_or("no root for mix proof")?;
    let ok = proof.verify(root, &[idx], &[phrase_leaf], leaves.len());
    println!(
        "mix: Merkle proof for phrase leaf at index {} verify={}",
        idx, ok
    );
    println!(
        "mix: agents anagram {} -> SIR MIX A LOT (engine hint)",
        MIX_ANAGRAM
    );
    let addr_shards = vec!["D", "O", "G", "E"];
    let addr = addr_shards.join("");
    println!("mix: addr from aliases: {}", addr);
    log_mix_telemetry(ok)?;
    Ok(ok)
}

fn write_mix_unlock_yaml() -> Result<()> {
    let dir = Path::new("receipts");
    fs::create_dir_all(dir)?;
    let path = dir.join("baby-got-back-loop.yaml");
    if path.exists() {
        return Ok(());
    }
    let mut f = fs::File::create(path)?;
    writeln!(f, "# Sir Mix A Lot bounty unlocked")?;
    writeln!(f, "reward_doge: 47")?;
    writeln!(f, "secret_loop: \"{}\"", MIX_PHRASE)?;
    writeln!(f, "doge_addr: DOGE1234567890abcdef... (full from aliases)")?;
    Ok(())
}

fn log_mix_telemetry(solved: bool) -> Result<()> {
    let path = Path::new("mix-hunt.log");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let now = now_secs();
    if solved {
        writeln!(f, "solve t={:.3}", now)?;
    } else {
        writeln!(f, "ping t={:.3}", now)?;
    }
    Ok(())
}

fn now_secs() -> f64 {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    dur.as_secs_f64()
}
