import os
import json
import numpy as np
from collections import defaultdict


try:
    from utils.tools_session import Detector
    from embedding import get_embedding_for_single_text
except ModuleNotFoundError:
    import sys

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from utils.tools_session import Detector
    from embedding import get_embedding_for_single_text

TEST_SET_BASE_DIR = r""
TEST_SET_CONFIG = {
    "Reentrancy": os.path.join(TEST_SET_BASE_DIR, "RE"),
    "Timestamp Dependency": os.path.join(TEST_SET_BASE_DIR, "TP"),
    "Integer Overflow/Underflow": os.path.join(TEST_SET_BASE_DIR, "OF"),
    "None": os.path.join(TEST_SET_BASE_DIR, "None")
}

DB_PATH = r""
CORPUS_BASE_DIR = r""
OUTPUT_DIR = r""


K_PATTERNS = a
LOW_QUALITY_WEIGHT = 1
CODE_SIM_WEIGHT = α
PATTERN_SIM_WEIGHT = β
PROMPT_CHAR_LIMIT_THRESHOLD = 22000


MULTI_CLASS_INFERENCE_PROMPT = """
You are a smart contract vulnerability detector.
Your task is to analyze the "SMART CONTRACT CODE TO ANALYZE" and classify it into ONE of the following four categories:
- "Reentrancy"
- "Timestamp Dependency"
- "Integer Overflow/Underflow"
- "None" (if it does not contain any of the three vulnerabilities)

You are provided with {k_patterns} examples to guide your decision. Each example includes an abstract Pattern and the concrete Source Code.
**Crucial Instruction:** You must synthesize information from BOTH the abstract patterns AND the concrete source code examples to make your final decision. Compare the target code against these comprehensive examples.

--- COMPREHENSIVE EXAMPLES ---
{relevant_patterns}
--------------------------------

--- SMART CONTRACT CODE TO ANALYZE ---
{target_code}
------------------------------------

Based on your comprehensive analysis, which ONE of the four categories does the code belong to?
Respond ONLY with a JSON object in the following format.

Example for a vulnerable contract:
{{"classification": "Reentrancy", "reason": "The contract makes an external call before updating the user's balance, following a classic reentrancy pattern."}}

Example for a safe contract:
{{"classification": "None", "reason": "The code is secure from the specified vulnerabilities. State updates precede external calls, and arithmetic operations are safe."}}

Your JSON response:
"""

def load_pattern_db(db_path):
    print(f" loading'{db_path}' ...")
    if not os.path.exists(db_path):
        print(f"cant find: {db_path}");
        return None
    with open(db_path, 'r', encoding='utf-8') as f: db = json.load(f)
    print(f"all: {len(db)} 。")
    return db


def cosine_similarity(v1, v2):
    norm_v1, norm_v2 = np.linalg.norm(v1), np.linalg.norm(v2)
    if norm_v1 == 0 or norm_v2 == 0: return 0.0
    return np.dot(v1, v2) / (norm_v1 * norm_v2)


def find_top_k_patterns(target_code_vector, db, k):
    all_patterns = []
    for entry in db:
        code_sim_score = cosine_similarity(target_code_vector, np.array(entry['code_embedding']))
        pattern_sim_score = cosine_similarity(target_code_vector, np.array(entry['pattern_embedding']))
        hybrid_score = (CODE_SIM_WEIGHT * code_sim_score) + (PATTERN_SIM_WEIGHT * pattern_sim_score)
        quality_weight = 1.0 if entry.get('quality_tag', 'high_quality') == 'high_quality' else LOW_QUALITY_WEIGHT
        final_score = hybrid_score * quality_weight
        all_patterns.append((final_score, entry))
    all_patterns.sort(key=lambda x: x[0], reverse=True)
    return [item[1] for item in all_patterns[:k]]


def load_example_source_code(filename):
    for root, _, files in os.walk(CORPUS_BASE_DIR):
        if filename in files:
            with open(os.path.join(root, filename), 'r', encoding='utf-8') as f:
                return f.read()
    print(f"corpus {CORPUS_BASE_DIR} cant find {filename}")
    return "Source code not found."


def main():
    if not os.path.exists(OUTPUT_DIR): os.makedirs(OUTPUT_DIR)

    detector = Detector('')
    db = load_pattern_db(DB_PATH)
    if db is None: return

    test_files = []
    print("\n scanning...")
    for label, folder_path in TEST_SET_CONFIG.items():
        if os.path.exists(folder_path):
            for filename in os.listdir(folder_path):
                if filename.endswith('.sol'):
                    test_files.append({"path": os.path.join(folder_path, filename), "ground_truth": label})
        else:
            print(f"cant find: {folder_path}")

    total_files = len(test_files)
    print(f"find： {total_files} example")

    all_results = []
    skipped_files = []

    for i, test_case in enumerate(test_files):
        file_path, ground_truth_label = test_case['path'], test_case['ground_truth']
        file_name = os.path.basename(file_path)
        print(f"\n--- testing ({i + 1}/{total_files}): {file_name} (Ground Truth: {ground_truth_label}) ---")

        with open(file_path, 'r', encoding='utf-8') as f:
            target_code = f.read()
        target_code_vector = get_embedding_for_single_text(target_code)
        top_patterns = find_top_k_patterns(target_code_vector, db, k=K_PATTERNS)

        patterns_text = ""
        for j, p in enumerate(top_patterns):
            knowledge = p.get('distilled_knowledge', {})
            pattern_type_str = f"VULNERABLE ({knowledge.get('vulnerability_name')})" if knowledge.get(
                'pattern_type') == 'vulnerable' else "SAFE"
            source_code = load_example_source_code(p.get('source_file'))
            patterns_text += f"--- EXAMPLE #{j + 1}: A **{pattern_type_str} PATTERN** ---\n"
            patterns_text += "1. Abstract Pattern:\n" + json.dumps(knowledge, indent=2) + "\n"
            patterns_text += "2. Concrete Source Code:\n```solidity\n" + source_code + "\n```\n\n"

        final_prompt = MULTI_CLASS_INFERENCE_PROMPT.format(
            k_patterns=len(top_patterns),
            relevant_patterns=patterns_text,
            target_code=target_code
        )

        final_result_json, _ = detector.detect(final_prompt)
        predicted_label = final_result_json.get("classification", "Error") if final_result_json else "Error"
        print(f"  -> 结果: Ground Truth: {ground_truth_label}, Predicted: {predicted_label}")
        all_results.append({"file": file_name, "ground_truth": ground_truth_label, "prediction": predicted_label,
                            "details": final_result_json})


    labels = list(TEST_SET_CONFIG.keys())
    label_to_index = {label: i for i, label in enumerate(labels)}
    confusion_matrix = np.zeros((len(labels), len(labels)), dtype=int)

    for result in all_results:
        gt = result['ground_truth']
        pred = result['prediction']
        if gt in label_to_index and pred in label_to_index:
            gt_idx = label_to_index[gt]
            pred_idx = label_to_index[pred]
            confusion_matrix[gt_idx, pred_idx] += 1

    per_class_metrics = {}
    for i, label in enumerate(labels):
        TP = confusion_matrix[i, i]
        FP = np.sum(confusion_matrix[:, i]) - TP
        FN = np.sum(confusion_matrix[i, :]) - TP
        TN = np.sum(confusion_matrix) - (TP + FP + FN)

        accuracy = (TP + TN) / (TP + TN + FP + FN) if (TP + TN + FP + FN) > 0 else 0
        precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        recall = TP / (TP + FN) if (TP + FN) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        per_class_metrics[label] = {
            "Accuracy": accuracy, "Precision": precision,
            "Recall": recall, "F1-score": f1_score,
            "TP": int(TP), "FP": int(FP), "FN": int(FN), "TN": int(TN)
        }

    overall_accuracy = np.trace(confusion_matrix) / np.sum(confusion_matrix)
    macro_precision = np.mean([metrics['Precision'] for metrics in per_class_metrics.values()])
    macro_recall = np.mean([metrics['Recall'] for metrics in per_class_metrics.values()])
    macro_f1_score = np.mean([metrics['F1-score'] for metrics in per_class_metrics.values()])

    report = f"""
======================================================================
       (k={K_PATTERNS})
======================================================================
all: {total_files}

(Confusion Matrix) ---
 predicted ->{labels}
 actual
{np.array2string(confusion_matrix, separator=', ')}

----------------------------------------------------------------------
 (Per-Class Metrics) ---
----------------------------------------------------------------------
"""
    header = f"{'CLASS':<30} | {'ACCURACY':<10} | {'PRECISION':<10} | {'RECALL':<10} | {'F1-SCORE':<10} | {'TP':<5} | {'FP':<5} | {'FN':<5}"
    report += header + "\n" + "-" * len(header) + "\n"
    for label, metrics in per_class_metrics.items():
        report += f"{label:<30} | {metrics['Accuracy']:.2%}{'':<3} | {metrics['Precision']:.2%}{'':<2} | {metrics['Recall']:.2%}{'':<3} | {metrics['F1-score']:.4f}{'':<3} | {metrics['TP']:<5} | {metrics['FP']:<5} | {metrics['FN']:<5}\n"

    report += f"""
----------------------------------------------------------------------
---  (Overall Framework Metrics) ---
----------------------------------------------------------------------
 (Overall Accuracy): {overall_accuracy:.2%}
-  (Avg Precision): {macro_precision:.2%}
-  (Avg Recall):   {macro_recall:.2%}
-  ( Avg F1-Score):  {macro_f1_score:.4f}
======================================================================
"""
    print(report)

    summary_path = os.path.join(OUTPUT_DIR, 'classification_summary_multi_class.json')
    with open(summary_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2)
    print(f"saving in: {summary_path}")

    report_path = os.path.join(OUTPUT_DIR, 'final_metrics_report_multi_class.txt')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"saved in: {report_path}")


if __name__ == "__main__":
    main()