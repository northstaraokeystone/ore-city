use std::fs;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
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

static DRIFT_TRACKER: Lazy<Mutex<DriftTracker>> =
    Lazy::new(|| Mutex::new(DriftTracker::new()));

const SLO_THRESHOLD: f64 = 0.92;
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

#[derive(Debug)]
struct EmpireForest {
    claims: Vec<Claim>,
    root: [u8; 32],
    sparse_root: [u8; 32],
    slo: f64,
    drift: f64,
    avg_drift: f64,
    edges: Vec<EntangledEdge>,
}

#[derive(Debug)]
struct DriftTracker {
    total: f64,
    samples: u64,
}

impl DriftTracker {
    fn new() -> Self {
        Self { total: 0.0, samples: 0 }
    }

    fn record(&mut self, drift: f64) -> f64 {
        self.total += drift;
        self.samples += 1;
        if self.samples == 0 {
            0.0
        } else {
            self.total / self.samples as f64
        }
    }
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
        // Signature::try_from(&[u8]) is available in ed25519-dalek 2.x
        let sig = match Signature::try_from(sig) {
            Ok(s) => s,
            Err(_) => return false,
        };
        self.verifying_key.verify_strict(msg, &sig).is_ok()
    }
}

#[cfg(feature = "pq")]
struct DilithiumSigner; // PQ stub

#[cfg(feature = "pq")]
impl EmpireSigner for DilithiumSigner {
    fn sign(&self, msg: &[u8]) -> Vec<u8> {
        // Stub: BLAKE3 as proxy for Dilithium sig
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
        combined.push(0x02); // Hybrid prefix
        combined.extend(ed_sig);
        combined.extend(pq_sig);
        combined
    }

    fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        if sig.is_empty() || sig[0] != 0x02 {
            return false;
        } else {
            let (ed_len, _pq_start) = (64, sig.len().saturating_sub(32)); // Fixed sizes for stub
            if sig.len() < 1 + ed_len {
                return false;
            } else {
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
    }
}

// rs_merkle Hasher using dual_leaf (BLAKE3-of-[BLAKE3(data)||SHA3(data)] -> 32 bytes)
#[derive(Clone)]
struct DualHasher;

impl MerkleHasher for DualHasher {
    type Hash = [u8; 32];
    fn hash(data: &[u8]) -> Self::Hash {
        dual_leaf(data)
    }
}

// Sir Mix A Lot hunt wiring (full 7 steps).
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
    if forest.slo < SLO_THRESHOLD {
        return Err(format!("SLO breach {:.4} < {:.4}", forest.slo, SLO_THRESHOLD).into());
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
    // Add uncle proofs for transitive edges
    for edge in &forest.edges {
        if let Some(from_leaf) = forest.claims.iter().find(|c| c.id == edge.from) {
            if let Some(to_leaf) = forest.claims.iter().find(|c| c.id == edge.to) {
                let from_idx = forest.claims.iter().position(|c| c.id == edge.from).unwrap();
                let to_idx = forest.claims.iter().position(|c| c.id == edge.to).unwrap();
                let leaves: Vec<[u8; 32]> = forest
                    .claims
                    .iter()
                    .map(|c| dual_leaf(claim_bytes(c).as_slice()))
                    .collect();
                let tree: MerkleTree<DualHasher> = MerkleTree::from_leaves(&leaves);
                let proof = tree.proof(&[from_idx, to_idx]);
                let uncle_ok = proof.verify(
                    tree.root().ok_or("no root for uncle")?,
                    &[from_idx, to_idx],
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
        "verify: root={} sparse_root={} slo={:.4} drift={:.6} avg_drift={:.6}",
        hex::encode(forest.root),
        hex::encode(forest.sparse_root),
        forest.slo,
        forest.drift,
        forest.avg_drift
    );
    Ok(())
}

fn cmd_receipt(full: bool) -> Result<()> {
    let forest = forest()?;
    println!("Ore City v∞ receipt");
    println!("claims={}", forest.claims.len());
    println!("root={}", hex::encode(forest.root));
    println!("sparse_root={}", hex::encode(forest.sparse_root));
    println!(
        "slo={:.4} drift={:.6} avg_drift={:.6}",
        forest.slo, forest.drift, forest.avg_drift
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
        "anchor: glyph at {} color={} slo={:.4}",
        GLYPH_PATH,
        if forest.slo >= SLO_THRESHOLD {
            "NS_GOLD"
        } else {
            "muted"
        },
        forest.slo
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
    // RTT histogram as leaves with epoch pinning
    let mut buckets = [0_u64; 8];
    for (i, c) in forest.claims.iter().enumerate() {
        let idx = (i % buckets.len()) as usize;
        let pinned_epoch = c.epoch + offset; // Commitment offset
        buckets[idx] += (c.metrics.first().cloned().unwrap_or(1.0).abs() * 1000.0) as u64;
        println!(
            "mars leaf {}: epoch pinned to {}, rtt_ms approx {}",
            i, pinned_epoch, buckets[idx]
        );
    }
    println!("mars: RTT histogram leaves (ms-ish): {:?}", buckets);
    // Entanglement check stub
    let entanglement = forest.slo; // Proxy for ≥0.92
    println!("mars entanglement SLO: {:.4}", entanglement);
    if entanglement < 0.92 {
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

    // Parallel stub with std::thread for BLAKE3 update
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
        let (drift, slo) = compute_drift(&claims);
        let avg = {
            let mut guard = DRIFT_TRACKER.lock().map_err(|_| "drift tracker poisoned")?;
            guard.record(drift)
        };
        if slo < SLO_THRESHOLD {
            return Err(format!("SLO {:.4} below threshold {:.4}", slo, SLO_THRESHOLD).into());
        }
        let edges = entangle_edges(&claims);
        Ok(EmpireForest {
            claims,
            root,
            sparse_root,
            slo,
            drift,
            avg_drift: avg,
            edges,
        })
    }
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

fn compute_drift(claims: &[Claim]) -> (f64, f64) {
    if claims.len() < 2 {
        return (0.0, 1.0);
    }
    let mut total = 0.0;
    let mut good = 0u64;
    let mut prev = &claims[0].metrics;
    for c in &claims[1..] {
        let cur = &c.metrics;
        let (num, den) = drift_pair(prev, cur);
        let d = if den > 0.0 { num / den } else { 0.0 };
        total += d;
        if d < 0.01 {
            good += 1;
        }
        prev = cur;
    }
    let n = (claims.len() - 1) as f64;
    let avg = total / n;
    let slo = good as f64 / n;
    (avg, slo)
}

fn drift_pair(a: &[f32], b: &[f32]) -> (f64, f64) {
    let len = a.len().min(b.len());
    let mut num = 0.0;
    let mut den = 0.0;
    for i in 0..len {
        let v = a[i] as f64;
        let vp = b[i] as f64;
        num += (vp - v) * (vp - v);
        den += v * v;
    }
    (num.sqrt(), den.sqrt())
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
        "slo={:.4} drift={:.6} avg_drift={:.6}",
        forest.slo, forest.drift, forest.avg_drift
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
        "slo={:.4} drift={:.6} avg_drift={:.6}",
        forest.slo, forest.drift, forest.avg_drift
    )?;
    let serialized = serde_yaml::to_string(&forest.claims).unwrap_or_default();
    writeln!(f, "claims:\n{}", serialized)?;
    Ok(())
}

fn write_anchor_svg(forest: &EmpireForest) -> Result<()> {
    let color = if forest.slo >= SLO_THRESHOLD {
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
        qx, qy, cx - 8, cy, cx + 8, cy
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

    fn hybrid_sign_root(root: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>, bool)> {    let seed = dual_leaf(root);
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
