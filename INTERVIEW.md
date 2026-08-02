# Interview Guide — Adversarial LLM Testing (Phishing Classifier)

This is your cheat-sheet for talking about the project. Read it once, run
`python run_demo.py` once, and you'll be able to explain it cold.

---

## 30-second pitch

> "I built a red-team harness for a phishing email classifier. It classifies
> emails as phishing or legit, then **probes the model's decision boundary** by
> applying the evasion techniques real phishers use — homoglyphs, link
> shorteners, header alignment — and measures which ones flip the verdict. It
> also extracts phishing IOCs like malicious URLs and spoofed sender metadata
> into structured, defanged reports. The interesting finding was that no single
> evasion beat the classifier, but a **stacked** attack evaded it 100% of the
> time — and hiding the URL behind a shortener was the highest-leverage move."

## The one-line version (for a CV screen)

> "Adversarial evaluation of a phishing classifier: perturbation-based
> decision-boundary probing to surface evasion weaknesses, plus structured IOC
> extraction."

---

## STAR framing

- **Situation:** Phishing classifiers (heuristic or LLM-based) are deployed as a
  front-line filter, but attackers actively try to evade them. A model's
  accuracy on clean data says nothing about its robustness under adversarial
  input.
- **Task:** Measure *where* a classifier's decision breaks — not just whether
  it's accurate, but which small, meaning-preserving changes flip its verdict.
- **Action:** Built a Python harness with (1) a pluggable classifier (offline
  heuristic + OpenAI-compatible LLM backend), (2) a library of adversarial
  perturbations, (3) a prober that sweeps each perturbation across strengths and
  records boundary crossings, and (4) an IOC extractor + report generator.
- **Result:** On the test classifier, single techniques never evaded it, but a
  combined attack evaded 100% of seeds; identified URL-shortener obfuscation as
  the top weakness and recommended expanding shortened links before scoring and
  avoiding over-reliance on any single signal family.

---

## Key concepts you must be able to define

**Decision boundary.** The surface where the model's output flips from one class
to the other. For a probabilistic classifier it's where `P(phishing) = 0.5`. A
sample near the boundary needs only a small nudge to be reclassified.

**Adversarial / evasion example.** An input crafted to be misclassified while
keeping its true meaning. Here: an email that's *still* phishing to a human but
that the classifier now calls legit.

**Semantics-preserving perturbation.** A transform that changes the surface form
but not the intent — e.g. swapping the letter `o` for a Cyrillic look-alike so
"password" no longer matches a keyword filter but still reads as "password".

**Boundary probing (what this project does).** Systematically applying
perturbations at increasing strength to find the *minimum* change that flips the
verdict. The set of cheap flips = the model's weaknesses.

**IOC (Indicator of Compromise).** An observable that signals malicious
activity — malicious URLs, look-alike domains, IP-literal links, mismatched
email headers. **Defanging** (`http`→`hxxp`, `.`→`[.]`) makes them safe to put
in a report.

---

## How it works (the flow you'd draw on a whiteboard)

```
email ──> classifier ──> P(phishing), label, reasons
                 │
   (if flagged phishing)
                 ▼
   for each perturbation, for each strength:
        perturb(email) ──> classifier ──> did the label flip? score drop?
                 │
                 ▼
   combined attack = chain the techniques that helped
                 │
                 ▼
   report: per-technique evasion rate, min flip strength, most effective
```

- **Classifier** is a logistic scorer over interpretable features (urgency,
  credential asks, look-alike URL, reply-to mismatch, ...). Kept simple *on
  purpose* — an interpretable target means every flip has a traceable cause. The
  same interface swaps in an LLM (Fireworks/OpenAI) with no other code change.
- **Only correctly-flagged phishing is probed** — you can't measure evasion of a
  detection that never fired. Good methodological point to mention.
- **Perturbations return copies** and are strength-parameterised so you can find
  the boundary, not just pass/fail.

---

## The finding, and why it matters

- The classifier used **defence in depth**: several independent signals (bad
  URL, spoofed header, urgent language). Knock out one and the others still
  push it over 0.5 — so **no single technique evaded it**.
- But stack the techniques and the score collapses below 0.5 → **100% combined
  evasion**. Lesson: *robustness to individual attacks doesn't imply robustness
  to combined ones.*
- **`url_shortener` was the strongest single lever** (largest average score
  drop) because the model leaned heavily on URL structure; a shortener removes
  the look-alike domain, bad TLD, and IP-literal signals in one move.
- **Defensive recommendations:** expand shortened URLs before scoring; don't let
  one signal family dominate the score; weight *combinations* of weak signals.

### Verified result: heuristic vs a real LLM

I ran the same probe against a live LLM backend (Fireworks AI, `gpt-oss-120b`)
and the offline heuristic. Same seeds, same 8 perturbations:

| Classifier | Clean accuracy | Verdict | Combined-attack evasion |
|------------|---------------|---------|-------------------------|
| Heuristic (feature scorer) | 11/11 | **JOINTLY BRITTLE** | **100%** |
| LLM (`gpt-oss-120b`) | 11/11 | **ROBUST** | **0%** |

- The LLM **resisted every technique**, including sending from a clean
  `gmail.com` address — because it reasons about the message's *intent*
  (credential-harvesting body) rather than matching surface features.
- Sharpest concrete contrast: the heuristic treated a `bit.ly` link as *clean*
  (evasion win); the LLM explicitly flagged it — "uses a short URL instead of an
  official link." Same input, opposite call. That's a real, demonstrable
  heuristic weakness the LLM doesn't share.
- Takeaway: surface-feature classifiers are cheap and interpretable but brittle
  under stacked evasion; an LLM is far more robust to obfuscation but slower and
  costlier — so use the LLM to *stress-test and backstop* the fast filter.

---

## Likely questions & crisp answers

**Q: Is this offensive tooling?**
A: No — it's a defender-side evaluation harness on synthetic data. It measures a
classifier you own so you can harden it. All links are fake and defanged; there
are no real payloads.

**Q: Where's the "LLM" part?**
A: The classifier backend is pluggable. Offline it's an interpretable heuristic
for reproducibility; flip `PHISHPROBE_BACKEND=llm` and it classifies through an
OpenAI-compatible model (I used Fireworks AI). The probing methodology is
identical regardless of backend — that's the point: it's model-agnostic.

**Q: Why a heuristic classifier and not a trained ML model?**
A: The project's contribution is the *probing and reporting methodology*, not a
SOTA detector. An interpretable target makes the boundary analysis
explainable — I can attribute every flip to a specific feature. The same harness
works against a trained model or an LLM unchanged.

**Q: How do you measure "decision boundary"?**
A: I sweep each perturbation across strengths 0.25→1.0 and record the smallest
strength that flips the label (min flip strength) and the change in P(phishing).
Small flip strength = the sample sat close to the boundary along that axis.

**Q: How would you extend it?**
A: Add a real labelled corpus (e.g. Enron + a phishing set) and a trained model;
add automated/greedy search for the minimal evasive perturbation; add
statistical significance across many seeds; wire the IOC output into a SIEM or
MISP; and test transferability — does an evasion found against the heuristic also
fool the LLM?

**Q: What did you learn?**
A: That evaluating a classifier on clean accuracy is not enough; you have to
adversarially stress the boundary. And that combined, weak perturbations are
more dangerous than any single strong one — which changes how you'd design the
detector's scoring.

**Q: How do you keep the reports safe to handle?**
A: Every indicator is defanged before it's written, so a URL in a report can't
be clicked by accident, and the sample data contains only synthetic look-alike
domains.

---

## Machine-learning questions (the `ml/` notebook)

This is the trained-model half — the classic ML an interviewer will drill on.

**Q: Walk me through the ML pipeline.**
A: Load a labelled dataset of 10k URLs with 16 features → stratified train/test
split → scale features in a `Pipeline` → train logistic regression → evaluate with
accuracy, precision, recall, F1, ROC-AUC and a confusion matrix → compare against
Decision Tree, Random Forest, SVM, k-NN → confirm stability with 5-fold CV.

**Q: Why logistic regression first?**
A: It's the interpretable linear baseline. It outputs a probability via the sigmoid,
it's fast, and its coefficients tell you *which features* drive the "phishing"
decision — I can literally read why a URL was flagged.

**Q: You also tried linear regression — why is that the wrong tool?**
A: Linear regression predicts an unbounded number, not a probability — my outputs ran
below 0 and above 1 — and it optimises squared error, not classification loss. You can
threshold it at 0.5 but it underperforms. It's the textbook reason logistic regression
exists.

**Q: Random Forest beat logistic regression — so why not just ship it?**
A: RF won on F1 (~0.86 vs ~0.76) because it captures non-linear feature interactions.
But logistic regression is interpretable and cheaper, and in security "why did you
block this?" matters. I'd weigh accuracy against explainability and latency, not just
pick the top F1.

**Q: Your logistic model had precision ~0.92 but recall ~0.65. What does that mean?**
A: At the 0.5 threshold it rarely false-alarms (high precision) but misses ~35% of
phishing (lower recall). I can trade one for the other by moving the threshold — that
trade-off is exactly what the ROC curve plots. Which way you tune depends on the cost
of a miss vs a false alarm.

**Q: Why accuracy *and* F1 — isn't accuracy enough?**
A: On a balanced 50/50 set accuracy is okay, but it hides the precision/recall split,
and on imbalanced real traffic accuracy is misleading (a "always legit" model scores
high). F1 (harmonic mean of precision and recall) is the honest single number.

**Q: How did you guard against overfitting / a lucky split?**
A: A held-out test set the model never trained on, plus 5-fold cross-validation — the
logistic F1 was ~0.767 with std ~0.01, so it's stable, not a fluke of one split.

**Q: How does the ML notebook relate to the adversarial `phishprobe` part?**
A: The notebook proves I can *build* an accurate detector. `phishprobe` asks the next
question — *is it robust?* — by perturbing inputs to find where the decision flips. A
good test score isn't the same as resistance to evasion.

---

## Honest note (for you, not the interviewer)

This repo is a clean, working reconstruction of the project idea. Before you
present it: run `python run_demo.py` and read the two reports so the numbers and
findings are yours to explain, not memorised. If asked for specifics, speak to
what the code actually does — you can open it live. Consider tightening the CV
date to when you built/rebuilt it if that's more accurate.

---

## Two-minute demo script

1. `python run_demo.py` — talk through the three phases as they print.
2. Open `reports/probe_report.md` — point at the combined-attack 100% row and
   the per-seed detail.
3. Open `reports/ioc_report.md` — show a phishing email's extracted IOCs
   (look-alike domain, reply-to mismatch) vs a legit email with none.
4. `python -m phishprobe classify --backend llm` — (if you set a Fireworks key)
   show the same pipeline running against a real model.
5. Open `ml/phishing_ml.ipynb` — the trained-model half: scroll to the model-
   comparison table, the logistic-regression coefficients, and the ROC curves.
   This is the "I trained and evaluated real classifiers" story.
