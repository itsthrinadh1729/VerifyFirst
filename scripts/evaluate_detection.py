import os
import csv
import sys
import asyncio
from typing import Dict, List, Any

# Ensure backend can be imported
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from backend.detection.engine.scorer import analyze_url_security
from backend.detection.intelligence.service import ThreatIntelService
from backend.detection.intelligence.schemas import ThreatIntelResult
from backend.detection.analysis.fusion import fuse_evidence

# Mock the GSB provider to simulate a real API key for testing known threat domains
class MockGSBProvider:
    async def check_url(self, url: str) -> ThreatIntelResult:
        known_bad = ["ianfette.org", "testsafebrowsing", "eicar"]
        is_bad = any(b in url for b in known_bad)
        if is_bad:
            return ThreatIntelResult(available=True, is_malicious=True, confidence="high", source="GSB", reason="Mocked Match")
        return ThreatIntelResult(available=True, is_malicious=False, confidence="high", source="GSB", reason=None)
    async def start(self): pass
    async def stop(self): pass

class Evaluator:
    def __init__(self, csv_path: str):
        self.csv_path = csv_path
        self.dataset = []
        self.intel_service = ThreatIntelService(provider=MockGSBProvider())

    def load_dataset(self):
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Exclude UNKNOWN from strict metrics
                if row['actual_label'] == 'UNKNOWN':
                    continue
                self.dataset.append(row)
        print(f"Loaded {len(self.dataset)} URLs for evaluation.")

    def _calc_metrics(self, y_true: List[str], y_pred: List[str], print_confusion=True):
        tp = fn = fp = tn = 0
        for true, pred in zip(y_true, y_pred):
            if true == 'PHISHING' and pred == 'PHISHING':
                tp += 1
            elif true == 'PHISHING' and pred == 'SAFE':
                fn += 1
            elif true == 'SAFE' and pred == 'PHISHING':
                fp += 1
            elif true == 'SAFE' and pred == 'SAFE':
                tn += 1

        accuracy = (tp + tn) / len(y_true) if y_true else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        fnr = fn / (tp + fn) if (tp + fn) > 0 else 0.0

        print(f"  Accuracy:  {accuracy:.2%}")
        print(f"  Precision: {precision:.2%}")
        print(f"  Recall:    {recall:.2%}")
        print(f"  F1 Score:  {f1:.2f}")
        print(f"  FPR:       {fpr:.2%}")
        print(f"  FNR:       {fnr:.2%}")

        if print_confusion:
            print("\n  Confusion Matrix:")
            print(f"                 Actual")
            print(f"              SAFE   PHISHING")
            print(f"Pred SAFE      {tn:<4}     {fn:<4}")
            print(f"Pred PHISHING  {fp:<4}     {tp:<4}")
            print()
            
        return {"tp": tp, "fn": fn, "fp": fp, "tn": tn}

    async def run_evaluation(self):
        self.load_dataset()
        
        await self.intel_service.start()
        
        y_true = [row['actual_label'] for row in self.dataset]
        y_heuristics = []
        y_gsb = []
        y_combined = []
        
        # Details for analysis
        fp_details = []
        fn_details = []
        
        # Category breakdown
        category_tp = {}
        category_total = {}

        print("\n=== Pass 1: Evaluating Heuristics Only ===")
        for row in self.dataset:
            res = analyze_url_security(row['url'])
            # Convert status to PHISHING/SAFE for evaluation. 
            # DANGEROUS/SUSPICIOUS both count as PHISHING (i.e. flagged).
            pred = 'PHISHING' if res.status in ('DANGEROUS', 'SUSPICIOUS') else 'SAFE'
            y_heuristics.append(pred)

        self._calc_metrics(y_true, y_heuristics, print_confusion=False)

        print("\n=== Pass 2: Evaluating Threat Intelligence Only ===")
        for row in self.dataset:
            # Only consider GSB "Match" as PHISHING. NO MATCH is SAFE.
            intel = await self.intel_service.check_url(row['url'])
            pred = 'PHISHING' if (intel.available and intel.is_malicious) else 'SAFE'
            y_gsb.append(pred)

        self._calc_metrics(y_true, y_gsb, print_confusion=False)

        print("\n=== Pass 3: Evaluating Combined System ===")
        for i, row in enumerate(self.dataset):
            h_res = analyze_url_security(row['url'])
            intel = await self.intel_service.check_url(row['url'])
            final = fuse_evidence(h_res, intel)
            
            pred = 'PHISHING' if final.status in ('DANGEROUS', 'SUSPICIOUS') else 'SAFE'
            y_combined.append(pred)
            
            true_label = row['actual_label']
            cat = row['category']
            
            # Category stats (only for PHISHING class)
            if true_label == 'PHISHING':
                category_total[cat] = category_total.get(cat, 0) + 1
                if pred == 'PHISHING':
                    category_tp[cat] = category_tp.get(cat, 0) + 1
            
            # FP / FN analysis
            if true_label == 'SAFE' and pred == 'PHISHING':
                fp_details.append({"url": row['url'], "score": final.risk_score, "reasons": final.reasons})
            elif true_label == 'PHISHING' and pred == 'SAFE':
                fn_details.append({"url": row['url'], "score": final.risk_score, "reasons": final.reasons, "category": cat})

        self._calc_metrics(y_true, y_combined, print_confusion=True)
        
        await self.intel_service.stop()

        print("=== Category Detection Rates (Combined) ===")
        for cat in sorted(category_total.keys()):
            tp = category_tp.get(cat, 0)
            total = category_total[cat]
            rate = tp / total if total > 0 else 0
            print(f"{cat:<20}: {rate:.0%} ({tp}/{total})")

        print("\n=== False Positives (Legitimate flagged as Phishing) ===")
        if not fp_details:
            print("None")
        for fp in fp_details:
            print(f"URL: {fp['url']}")
            print(f"Score: {fp['score']}")
            print("Reasons:")
            for r in fp['reasons']:
                print(f"  - {r.rule}: {r.message}")
            print()

        print("=== False Negatives (Phishing missed by engine) ===")
        if not fn_details:
            print("None")
        for fn in fn_details:
            print(f"URL: {fn['url']}")
            print(f"Category: {fn['category']}")
            print(f"Score: {fn['score']}")
            print("Reasons:")
            for r in fn['reasons']:
                print(f"  - {r.rule}: {r.message}")
            print()


if __name__ == "__main__":
    csv_path = os.path.join(os.path.dirname(__file__), "..", "evaluation", "urls.csv")
    evaluator = Evaluator(csv_path)
    asyncio.run(evaluator.run_evaluation())
