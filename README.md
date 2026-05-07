# SchemaMind: An LLM-Enhanced Static Knowledge Framework for Smart Contract Vulnerability Detection

This repository contains the official implementation and supplementary artifacts of **SchemaMind**, an LLM-enhanced framework for smart contract vulnerability detection. SchemaMind is designed to bridge the semantic gap in retrieval and reduce the efficiency bottlenecks of repeated on-the-fly reasoning in LLM-based smart contract auditing.

## Overview

SchemaMind combines three core components:

- **PHCM** (Progressive Hinton-Correction Mechanism) for iterative label correction during offline knowledge construction
- **SRSP-KB** (Static Reusable Structure-Semantic Pattern Knowledge Base) for storing reusable structured vulnerability knowledge
- **HSSR** (Hybrid Structure-Semantic Retrieval) for retrieving in-context examples using both code structure and semantic pattern information

This repository currently provides the core code, the online supplementary appendix, and the self-generated benign samples used to enhance the evaluation benchmark.

## Repository Structure

```text
SchemaMind/
├── dataset/
│   ├── .gitkeep
│   └── benign.zip
├── utils/
│   ├── .gitkeep
│   └── tools_session.py
├── .gitkeep
├── build_pattern_database.py
├── embedding.py
├── query_with_pattern.py
├── Appendix.pdf
└── README.md
```

### Main Files

- **`build_pattern_database.py`**  
  Builds the static reusable structure-semantic pattern knowledge base (SRSP-KB).

- **`embedding.py`**  
  Generates vector representations for code snippets and pattern descriptions.

- **`query_with_pattern.py`**  
  Supports retrieval and inference using the hybrid structure-semantic matching pipeline.

- **`utils/tools_session.py`**  
  Utility functions used by the pipeline.

## Supplementary Material

**[Download Appendix.pdf](./Appendix.pdf)**

The appendix serves as the online supplementary material for the paper. It provides additional technical details to support the transparency and reproducibility of SchemaMind, including:

- structured examples of vulnerable and safe patterns in the SRSP-KB
- prompt designs for PHCM and final inference
- detailed dataset composition
- extended experimental results and ablation studies

## Dataset

The evaluation of **SchemaMind** relies on three primary data components. Due to original licensing and redistribution restrictions, only the self-generated benign samples are directly hosted in this repository.

### Data Availability

- **Self-generated benign samples (available in this repository)**  
  To improve benchmark complexity and reduce label leakage, we replaced simplistic benign samples in SolidiFI with **1,619 high-quality, non-trivial benign samples**.  
  Location: [`dataset/benign.zip`](./dataset/benign.zip)

- **Vulnerable samples (source corpus)**  
  The smart contract corpus used for constructing the **SRSP-KB** is derived from the work of *Qian et al.*  
  Source: [ACM Digital Library](https://dl.acm.org/doi/abs/10.1145/3543507.3583367)

- **Vulnerability injection benchmark (SolidiFI)**  
  The original evaluation benchmark and vulnerability patterns are based on **SolidiFI**.  
  Source: [ACM Digital Library](https://dl.acm.org/doi/abs/10.1145/3395363.3397385)

### Dataset Statistics

The final unified test set used in our experiments contains **5,676 samples**:

- **None:** 1,619
- **Overflow-Underflow:** 1,333
- **Timestamp-Dependency:** 1,381
- **Re-Entrancy:** 1,343

## Reproducibility Notes

At a high level, reproducing the evaluation pipeline involves:

1. obtaining the original vulnerable corpora from the cited external sources
2. using the benign samples provided in this repository to construct the enhanced test set
3. building the SRSP-KB through offline knowledge distillation
4. generating embeddings for code snippets and pattern descriptions
5. running hybrid retrieval and final LLM-based inference

For prompt details, benchmark composition, and extended experimental results, please refer to **Appendix.pdf**.

## Notes

- This repository redistributes only the artifacts that can be openly shared.
- Third-party datasets remain subject to their original licenses and access policies.
- Additional citation information can be added after formal publication.
