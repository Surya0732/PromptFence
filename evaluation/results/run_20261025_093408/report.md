# PromptFence Security Evaluation Report

**Run Timestamp**: 20261025_093408  
**Policy Enforcement Profile**: `balanced`  
**Configured Local Model**: `qwen2.5:1.5b` (Ollama)  
**Dataset Evaluated**: `evaluation\dataset.jsonl` (100 test cases)  

---

## 1. Executive Summary & Benchmark Notice

This report presents a quantitative security evaluation of **PromptFence** indirect prompt injection detectors across three operating modes:
- **`rules`**: Ultra-fast deterministic phrase matching catalog.
- **`llm`**: Local open-weight semantic intent classification using Ollama (`qwen2.5:1.5b`).
- **`hybrid`**: Multi-signal ensemble merging rule signatures and semantic findings.

> **Notice: Synthetic Benchmark Limitation**:  
> The evaluation dataset is a curated synthetic benchmark designed for reproducible, standardized security testing. It is **not** a statistically representative sample of live production traffic. Real-world injection attempts may exhibit novel phrasing, multi-turn context dependencies, or obfuscation techniques beyond synthetic suites. Prompt injection defense is probabilistic; auxiliary models provide defense-in-depth and do not replace backend tool allowlists, argument validation ceilings, or deterministic policy constraints.

---

## 2. Comparative Security Performance

| Mode | Coverage | Accuracy | Precision | Recall | F1 Score | FPR | FNR | Mean Latency | Median Latency | Errors |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **rules** | 100.0% | 93.00% | 97.78% | 88.00% | 92.63% | 2.00% | 12.00% | 0.07 ms | 0.07 ms | 0 |

### Metric Definitions & Decision Mapping
- **Positive Class**: Malicious prompt injection / security threat indicators present.
- **Negative Class**: Benign / harmless content.
- **Decision Mapping**:
  - `allow` -> **`benign`**: Input evaluated without actionable policy violations.
  - `review` -> **`malicious`**: Indicator findings detected (e.g. instruction overrides); autonomous agent action halted pending manual human inspection.
  - `block` -> **`malicious`**: High-severity indicator detected in serious attack categories; immediate containment enforced.
  - `error` -> **`error`**: Detector unavailability or timeout; recorded strictly as an error and **never** counted as a clean allow.
- **Accuracy**: `(TP + TN) / Total Evaluated Cases`
- **Precision**: `TP / (TP + FP)` (proportion of flagged inputs that were genuine attacks).
- **Recall (Sensitivity)**: `TP / (TP + FN)` (proportion of genuine attacks successfully detected).
- **F1 Score**: Harmonic mean of Precision and Recall (`2 * P * R / (P + R)`).
- **False-Positive Rate (FPR)**: `FP / (FP + TN)` (benign cases erroneously flagged as threats).
- **False-Negative Rate (FNR)**: `FN / (FN + TP)` (missed attacks permitted without detection).
- **Coverage**: Evaluated cases / total dataset cases.

---

## 3. Dataset Composition

- **Total Test Cases**: 100
- **Label Split**:
  - Benign: 50 cases
  - Malicious: 50 cases
- **Attack Category Distribution**:
  - `none` (benign): 50
  - `instruction_override`: 14
  - `secret_extraction`: 12
  - `data_exfiltration`: 12
  - `unauthorized_tool_use`: 12
- **Difficulty Breakdown**:
  - `basic`: 37
  - `intermediate`: 32
  - `adversarial`: 31

---

## 4. Key Findings & Behavioral Analysis

1. **Deterministic Rule Engine (`rules`)**:
   - Sub-millisecond latency (typically < 1.0 ms) makes it suitable for high-throughput gateway filtering.
   - Extremely high precision on known phrase signatures.
   - Susceptible to paraphrased, steganographic, or novel injection framing outside signature catalogs.
2. **Local LLM Detector (`llm`)**:
   - Evaluates natural language semantics and semantic intent beyond exact literal strings.
   - Subject to inference latency (~4–8s on CPU-only 8 GB RAM hardware).
   - In the event of service downtime, fails safe by emitting an explicit HTTP 503 rather than false approval.
3. **Hybrid Ensemble Mode (`hybrid`)**:
   - Combines deterministic speed and zero-trust certainty with probabilistic semantic detection.
   - Enforces the **Non-Cancellation Guarantee**: a benign or low-risk model output cannot cancel a high-severity rule detection.
   - Features **Graceful Degradation**: if Ollama inference fails, the rule engine findings are preserved and policy evaluation proceeds under a `degraded` operational status.
