# How the charter works — four diagrams

Source for these lives here as Mermaid so they diff, version, and cannot rot
into stale screenshots. GitHub renders them inline.

---

## 1 · Tamper detection: re-hashing moves the break, it does not hide it

The counterintuitive one. Editing a link and *fixing its hash* does not repair
the chain — it relocates the failure to the **next** link, because that link
still commits to the old hash.

```mermaid
flowchart TB
    subgraph s1["1 · Honest chain"]
        direction LR
        H0["seq 0<br/>hash = A"] --> H1["seq 1<br/>prev = A<br/>hash = B"] --> H2["seq 2<br/>prev = B<br/>hash = C"]
    end

    subgraph s2["2 · Content edited, hash left alone"]
        direction LR
        N0["seq 0<br/>hash = A"] --> N1["seq 1 · EDITED<br/>prev = A<br/>hash = B"] --> N2["seq 2<br/>prev = B<br/>hash = C"]
    end

    subgraph s3["3 · Content edited AND re-hashed"]
        direction LR
        R0["seq 0<br/>hash = A"] --> R1["seq 1 · EDITED<br/>prev = A<br/>hash = B*"] --> R2["seq 2<br/>prev = B<br/>hash = C"]
    end

    s2 -.->|"content hash mismatch at seq 1"| F2["caught"]
    s3 -.->|"linkage break at seq 2<br/>(seq 2 still points at old B)"| F3["caught"]

    classDef bad fill:#3a1414,stroke:#e74c3c,color:#f4d0cc
    classDef ok fill:#12281a,stroke:#2ecc71,color:#cfe9d8
    class N1,R2 bad
    class F2,F3 ok
```

To hide an edit you must rewrite every link after it — which is exactly the
whole-chain regeneration that externally published tip hashes are there to
catch. See *Honest limits* in the README.

---

## 2 · Correctable, not erasable

A reversal is a **new link that references the decision it corrects**. The
original is never edited and never deleted. The full history — the ban, the
appeal, the overturn, the unban — stays readable and attributable.

```mermaid
flowchart LR
    D["seq 12 · enforcement.action<br/><b>BAN</b> player 7f3a<br/>reason code from sealed policy"]
    A["seq 47 · appeal.decision<br/><b>OVERTURNED</b><br/>refs seq 12"]
    R["seq 48 · enforcement.reversal<br/><b>UNBAN</b> player 7f3a<br/>authorized by seq 47"]

    D --> A --> R
    D -.->|"still present, unedited"| R

    classDef keep fill:#2b2110,stroke:#c8941a,color:#f0e2c2
    class D,A,R keep
```

An unban with no overturned decision behind it is refused at the API — and if
someone writes one straight to the chain, `audit()` names it.

---

## 3 · Two questions, two functions

Most "immutable ledger" designs answer the first and quietly imply they have
answered the second. They are different questions, and a perfectly intact
record can document an abuse of legitimate power.

```mermaid
flowchart TB
    C[("chain.jsonl")]
    C --> V["<b>verify()</b><br/>Was history altered?"]
    C --> A["<b>audit()</b><br/>Was authority abused<br/>inside valid history?"]

    V --> VD["content edits<br/>re-hashed edits<br/>deletions and reordering<br/>cross-chain replay<br/>forged genesis"]
    A --> AD["reversal with no overturned decision<br/>unban written around the gate<br/>receipt that fails the sealed price sheet<br/>an appeal decided twice"]

    classDef q fill:#101c2c,stroke:#58a6ff,color:#d6e6fb
    classDef d fill:#1a1a1a,stroke:#555,color:#cfcfcf
    class V,A q
    class VD,AD d
```

---

## 4 · The Ark: lapse, and the latch

Liveness is a sealed heartbeat. If the gap between signals exceeds the lapse
threshold, the commitment triggers — and it **latches**: a silence that has
already elapsed cannot be un-elapsed by a later heartbeat, and the terms
reported are the ones in force when the silence began.

```mermaid
flowchart LR
    K["ark.commitment<br/>package · license<br/>lapse threshold"] --> HB1["heartbeat"] --> HB2["heartbeat"] --> HB3["heartbeat"]
    HB3 -->|"silence exceeds<br/>lapse threshold"| T["<b>TRIGGERED</b><br/>terms = those in force<br/>when the silence began"]
    T -.->|"a later heartbeat<br/>cannot un-trigger it"| T

    classDef live fill:#12281a,stroke:#2ecc71,color:#cfe9d8
    classDef fired fill:#3a1414,stroke:#e74c3c,color:#f4d0cc
    classDef commit fill:#2b2110,stroke:#c8941a,color:#f0e2c2
    class HB1,HB2,HB3 live
    class T fired
    class K commit
```

Two further rules harden this: the effective threshold is the **smallest**
lapse period ever committed (terms can only tighten), and the API refuses an
amendment that would lengthen it.

**The limit, stated plainly:** heartbeats and cessation events are both written
by the operator. It is a dead man's switch operated by the dead man. External
anchoring is what would make it adversarial rather than merely honest — and
that is not built yet.
