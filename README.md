# SchemaMind: An LLM-Enhanced Static Knowledge Framework for Smart Contract Vulnerability Detection

This repository contains the official implementation of **SchemaMind**, a novel framework designed to bridge the semantic gap and resolve efficiency bottlenecks in smart contract security auditing. 

## Supplementary Material
**[Download Appendix.pdf](./Appendix.pdf)**
> This appendix serves as a comprehensive technical supplement to the main text, providing the necessary artifacts to ensure the transparency and reproducibility of the SchemaMind framework. It consolidates the operational logic of the Progressive Hinton-Correction Mechanism (PHCM), SRSP-KB schemas, prompt designs, and extended experimental results.

## 📂 Dataset

The evaluation of **SchemaMind** relies on three primary data components. Please note that only the self-generated high-quality samples are hosted in this repository due to original licensing and data distribution policies.

### 1. Data Availability
* **Enhancement: Self-Generated Benign Samples (Available here):** To ensure complexity and prevent label leakage, we replaced simplistic benign samples in SolidiFI with **1,619 high-quality, non-trivial benign samples**.
   Located at: [`SchemaMind/dataset/`](./dataset)
* **Vulnerable Samples (Source Corpus):** The smart contract corpus used for constructing the **SRSP-KB** is derived from the research by *Qian et al.*. Please refer to the [official ACM DL page](https://dl.acm.org/doi/abs/10.1145/3543507.3583367) for access to the original bytecode dataset.
* **Vulnerability Injection Benchmark (SolidiFI):** The initial test set framework and vulnerability patterns are based on the **SolidiFI** benchmark. Interested researchers should consult the [official ACM DL page](https://dl.acm.org/doi/abs/10.1145/3395363.3397385) for the bug injection methodology and dataset.

### 2. Dataset Statistics
The final unified test set used in our experiments comprises **5,676 samples**.
