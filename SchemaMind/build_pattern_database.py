import os
import json
import numpy as np
from time import sleep


try:
    from utils.tools_session import Detector
except ModuleNotFoundError:
    import sys

    sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
    from utils.tools_session import Detector
from embedding import get_embedding_for_single_text

CORPUS_BASE_DIR = r""
CORPUS_CONFIG = {
    "positive/single_RE": {"Reentrancy": "yes", "Timestamp Dependency": "no", "Integer Overflow/Underflow": "no"},
    "positive/single_TP": {"Reentrancy": "no", "Timestamp Dependency": "yes", "Integer Overflow/Underflow": "no"},
    "positive/single_OF": {"Reentrancy": "no", "Timestamp Dependency": "no", "Integer Overflow/Underflow": "yes"},
    "positive/multi_RE_TP": {"Reentrancy": "yes", "Timestamp Dependency": "yes", "Integer Overflow/Underflow": "no"},
    "positive/multi_RE_OF": {"Reentrancy": "yes", "Timestamp Dependency": "no", "Integer Overflow/Underflow": "yes"},
    "positive/multi_TP_OF": {"Reentrancy": "no", "Timestamp Dependency": "yes", "Integer Overflow/Underflow": "yes"},
    "positive/multi_RE_TP_OF": {"Reentrancy": "yes", "Timestamp Dependency": "yes",
                                "Integer Overflow/Underflow": "yes"},
    "negative/none": {"Reentrancy": "no", "Timestamp Dependency": "no", "Integer Overflow/Underflow": "no"}
}
OUTPUT_DB_PATH = r""
RETHINK_LIMIT = a


MULTI_LABEL_DETECTION_PROMPT = """
You are a smart contract vulnerability detector. For the following code, please determine if it contains EACH of the listed vulnerabilities: "Reentrancy", "Timestamp Dependency", "Integer Overflow/Underflow".
Your response MUST be a JSON object where each key is a vulnerability type and its value is either "yes" or "no". Example format: {{"Reentrancy": "no", "Timestamp Dependency": "yes", "Integer Overflow/Underflow": "no"}}
--- CODE TO ANALYZE ---
{code_snippet}
-----------------------
Your JSON response:
"""


SOFT_RETHINK_FN_TEMPLATE = """
Your previous analysis may have been incorrect, potentially missing a vulnerability. Let's think step by step.
Hint: {specific_hint_str}
IMPORTANT: Your response MUST strictly follow the original JSON format with three keys: "Reentrancy", "Timestamp Dependency", and "Integer Overflow/Underflow", and their values must be "yes" or "no". Do NOT add any other keys or nesting.
--- CODE TO ANALYZE ---
{code_snippet}
-----------------------
Your new JSON response:
"""
HARD_RETHINK_FN_TEMPLATE = """
Your previous analysis was incorrect. You failed to identify the vulnerability/vulnerabilities in the code.
The provided code snippet may only have vulnerabilities related to: **{possible_labels_str}**.
Hint: {specific_hint_str}
IMPORTANT: Your response MUST strictly follow the original JSON format with three keys: "Reentrancy", "Timestamp Dependency", and "Integer Overflow/Underflow", and their values must be "yes" or "no". Do NOT add any other keys or nesting.
--- CODE TO ANALYZE ---
{code_snippet}
-----------------------
Your new JSON response:
"""

SOFT_RETHINK_FP_TEMPLATE = """
Your previous analysis may have been incorrect, potentially identifying a vulnerability where none exists. Let's think step by step.
Hint: {specific_hint_str}
IMPORTANT: Your response MUST strictly follow the original JSON format with three keys: "Reentrancy", "Timestamp Dependency", and "Integer Overflow/Underflow", and their values must be "yes" or "no". Do NOT add any other keys or nesting.
--- CODE TO ANALYZE ---
{code_snippet}
-----------------------
Your new JSON response:
"""
HARD_RETHINK_FP_TEMPLATE = """
Your previous analysis was incorrect. You incorrectly identified a vulnerability in this safe code.
The code may be actually SAFE from the vulnerability you identified.
Hint: {specific_hint_str}
IMPORTANT: Your response MUST strictly follow the original JSON format with three keys: "Reentrancy", "Timestamp Dependency", and "Integer Overflow/Underflow", and their values must be "yes" or "no". Confirm why it is safe.
--- CODE TO ANALYZE ---
{code_snippet}
-----------------------
Your new JSON response:
"""

FORCED_VULNERABLE_DISTILLATION_TEMPLATE = """
You are a world-class smart contract security expert. The following Solidity code snippet IS VULNERABLE to **{vulnerability_name}**.
Your task is to distill the core FLAW into a structured "Vulnerability Pattern". IMPORTANT: Your "vulnerability_pattern_description" MUST be concise, under 80 words.
Please respond ONLY with a JSON object in the format: {{"vulnerability_name": "{vulnerability_name}", "pattern_type": "vulnerable", "vulnerability_pattern_description": "...", "trigger_condition": "...", "fix_pattern": "..."}}
--- VULNERABLE CODE TO ANALYZE ({vulnerability_name}) ---
{code_snippet}
"""
FORCED_SAFE_DISTILLATION_PROMPT = """
You are a world-class smart contract security expert. The following Solidity code snippet IS SAFE from Reentrancy, Timestamp Dependency, and Integer Overflow/Underflow.
Your task is to distill the core SAFE PRACTICE into a structured "Safety Pattern". IMPORTANT: Your "safety_pattern_description" MUST be concise, under 80 words.
Please respond ONLY with a JSON object in the format: {{"vulnerability_name": "none", "pattern_type": "safe", "safety_pattern_description": "...", "mitigation_factor": "...", "guideline": "..."}}
--- SAFE CODE TO ANALYZE ---
{code_snippet}
"""

HINT_MAPPING_V6 = {
    "Reentrancy": {
        "fn_soft": "Let's re-examine the sequence of operations. Does the contract interact with an external address? If so, carefully check what happens to the contract's state *before* and *after* that interaction.",
        "fn_hard": "Look for an external call (like `.call.value()`) that happens BEFORE a state update (like `balance -= amount`). Specifically, does the code follow the Checks-Effects-Interactions pattern?",
        "fp_soft": "Let's re-evaluate the external call. Are there any security mechanisms or patterns in place (like a reentrancy guard or state updates happening first) that would prevent a recursive call from causing harm?",
        "fp_hard": "Re-examine the external call. Is there a `nonReentrant` modifier being used? Or is the state update correctly performed *before* the external call, strictly following the Checks-Effects-Interactions pattern?"
    },
    "Timestamp Dependency": {
        "fn_soft": "Let's re-examine how the contract handles time-sensitive logic. Could the timing be influenced externally in a critical way?",
        "fn_hard": "Look for the use of 'block.timestamp' or 'now' to control critical logic, like fund transfers or determining a winner. Consider how a miner could manipulate this value.",
        "fp_soft": "Let's re-evaluate the use of time-related variables. Is their usage truly critical for security, or are they used for non-critical purposes like logging or within a safe time range?",
        "fp_hard": "Re-examine the use of 'block.timestamp'. Is it used for non-critical purposes (like logging) or are there other conditions that prevent miner manipulation? Does it only provide a loose time bound rather than controlling a specific transaction?"
    },
    "Integer Overflow/Underflow": {
        "fn_soft": "Let's re-examine the arithmetic operations. Could any calculation produce an unexpected result due to the nature of integer types in Solidity?",
        "fn_hard": "Look for arithmetic operations (+, -, *) on integer types that lack checks for upper or lower bounds. Does the code use a SafeMath library or a Solidity version >=0.8.0?",
        "fp_soft": "Let's re-evaluate the arithmetic operations. Are there any protective mechanisms or contextual factors (like `require` checks before the operation) that might prevent this potential vulnerability?",
        "fp_hard": "Re-examine the arithmetic operation. Is a SafeMath library being used, or is the Solidity compiler version 0.8.0 or higher? These provide default overflow/underflow protection. Are there explicit `require` checks before the operation?"
    }
}


def is_prediction_correct(prediction_json, ground_truth_dict):
    if not isinstance(prediction_json, dict) or not all(
        key in prediction_json for key in ground_truth_dict): return False
    return all(prediction_json[key] == value for key, value in ground_truth_dict.items())


def determine_error_and_generate_hints(ground_truth, prediction, hint_level='soft'):
    prediction = prediction if isinstance(prediction, dict) else {}

    missed_vulns = [k for k, v in ground_truth.items() if v == "yes" and prediction.get(k) != "yes"]
    wrongly_found_vulns = [k for k, v in ground_truth.items() if v == "no" and prediction.get(k) == "yes"]

    if wrongly_found_vulns:
        error_type = 'FP'
        labels_str = " and ".join(wrongly_found_vulns)
        hints_str = " ".join([HINT_MAPPING_V6[label][f'fp_{hint_level}'] for label in wrongly_found_vulns])

    elif missed_vulns:
        error_type = 'FN'

        all_ground_truth_vulns = [k for k, v in ground_truth.items() if v == "yes"]
        labels_str = " and ".join(all_ground_truth_vulns)
        hints_str = " ".join([HINT_MAPPING_V6[label][f'fn_{hint_level}'] for label in all_ground_truth_vulns])

    else:
        error_type = 'FN'
        all_vulns = [k for k, v in ground_truth.items() if v == "yes"]
        if all_vulns:
            labels_str = " and ".join(all_vulns)
            hints_str = " ".join([HINT_MAPPING_V6[label][f'fn_{hint_level}'] for label in all_vulns])
        else:
            error_type = 'FP'
            labels_str = "a potential"
            hints_str = "Please re-examine the code to confirm why it is SAFE from all vulnerabilities. Focus on finding security best practices."

    return error_type, labels_str, hints_str


def process_snippet(detector, code_snippet, file_name, ground_truth):
    print(f"\n--- Processing: {file_name} (Ground Truth: {json.dumps(ground_truth)}) ---")

    final_classification, quality_tag = None, "high_quality"
    conversation_history = []

    print(f"  - Attempt 1 (Initial Judgement)...")
    result, response_msg = detector.detect(MULTI_LABEL_DETECTION_PROMPT.format(code_snippet=code_snippet),
                                           conversation_history=None)
    if response_msg:
        conversation_history.append(
            {'role': 'user', 'content': MULTI_LABEL_DETECTION_PROMPT.format(code_snippet=code_snippet)})
        conversation_history.append(response_msg)

    if result and is_prediction_correct(result, ground_truth):
        print("  - LLM prediction is CORRECT.")
        final_classification = ground_truth
    else:
        print(f"  - LLM prediction is INCORRECT. Predicted: {json.dumps(result)}. Starting rethink...")
        for i in range(RETHINK_LIMIT):
            attempt_num, prompt = i + 2, ""
            hint_level = 'soft' if i == 0 else 'hard'

            error_type, labels_str, hints_str = determine_error_and_generate_hints(ground_truth, result, hint_level)

            if error_type == 'FP':
                template = SOFT_RETHINK_FP_TEMPLATE if hint_level == 'soft' else HARD_RETHINK_FP_TEMPLATE
                print(f"  - Attempt {attempt_num} ({hint_level.capitalize()} Rethink for FP)...")
                prompt = template.format(code_snippet=code_snippet, possible_labels_str=labels_str,
                                         specific_hint_str=hints_str)
            else:
                template = SOFT_RETHINK_FN_TEMPLATE if hint_level == 'soft' else HARD_RETHINK_FN_TEMPLATE
                print(f"  - Attempt {attempt_num} ({hint_level.capitalize()} Rethink for FN)...")
                prompt = template.format(code_snippet=code_snippet, possible_labels_str=labels_str,
                                         specific_hint_str=hints_str)

            result, response_msg = detector.detect(prompt, conversation_history=conversation_history)
            if response_msg:
                conversation_history.append({'role': 'user', 'content': prompt})
                conversation_history.append(response_msg)

            if result and is_prediction_correct(result, ground_truth):
                print("  - LLM prediction is CORRECT after rethink.")
                final_classification = ground_truth
                break
            else:
                print(f"  - LLM prediction still INCORRECT. Predicted: {json.dumps(result)}")
            sleep(5)

    if final_classification is None:
        print(f"  - LLM failed after {RETHINK_LIMIT} retries. Forcing label...")
        quality_tag, final_classification = "low_quality", ground_truth

    db_entries = []
    vulnerable_labels = [label for label, is_vuln in final_classification.items() if is_vuln == "yes"]

    if not vulnerable_labels:
        print(f"  - Distilling pattern (Type: Safe, Quality: {quality_tag})...")
        distilled_knowledge, _ = detector.detect(FORCED_SAFE_DISTILLATION_PROMPT.format(code_snippet=code_snippet))
        if distilled_knowledge and distilled_knowledge.get("safety_pattern_description"):
            desc = distilled_knowledge["safety_pattern_description"]
            db_entries.append({"source_file": file_name, "ground_truth": "none", "quality_tag": quality_tag,
                               "distilled_knowledge": distilled_knowledge,
                               "pattern_embedding": get_embedding_for_single_text(desc).tolist(),
                               "code_embedding": get_embedding_for_single_text(code_snippet).tolist()})
    else:
        for vuln_name in vulnerable_labels:
            print(f"  - Distilling pattern (Type: {vuln_name}, Quality: {quality_tag})...")
            distilled_knowledge, _ = detector.detect(
                FORCED_VULNERABLE_DISTILLATION_TEMPLATE.format(vulnerability_name=vuln_name, code_snippet=code_snippet))
            if distilled_knowledge and distilled_knowledge.get("vulnerability_pattern_description"):
                desc = distilled_knowledge["vulnerability_pattern_description"]
                db_entries.append({"source_file": file_name, "ground_truth": vuln_name, "quality_tag": quality_tag,
                                   "distilled_knowledge": distilled_knowledge,
                                   "pattern_embedding": get_embedding_for_single_text(desc).tolist(),
                                   "code_embedding": get_embedding_for_single_text(code_snippet).tolist()})

    if not db_entries:
        print("  - ERROR: Failed to distill any valid knowledge. Skipping this file.")
        return None

    return db_entries


def main():
    detector = Detector('')
    vulnerability_database = []
    for folder_suffix, ground_truth in CORPUS_CONFIG.items():
        folder_path = os.path.join(CORPUS_BASE_DIR, folder_suffix)
        print(f"\n[PHASE] Processing Folder: {folder_path}")
        if not os.path.exists(folder_path):
            print(f"  - WARNING: Folder not found, skipping: {folder_path}")
            continue
        for filename in os.listdir(folder_path):
            if filename.endswith('.sol'):
                file_path = os.path.join(folder_path, filename)
                with open(file_path, 'r', encoding='utf-8') as f:
                    code = f.read()
                db_entries = process_snippet(detector, code, filename, ground_truth)
                if db_entries:
                    vulnerability_database.extend(db_entries)
    with open(OUTPUT_DB_PATH, 'w', encoding='utf-8') as f:
        json.dump(vulnerability_database, f, indent=2)
    print(f"savein: {OUTPUT_DB_PATH}")


if __name__ == "__main__":
    main()