import os
import glob
from ai.inference import IPsecClassifier

clf = IPsecClassifier('models')
base = 'C:/Users/Shrey/Downloads/sih26-dataset'
correct = 0
total = 0

print("="*75)
print(f"{'CATEGORY':15s} | {'FILE':20s} | {'EXPECTED':8s} | {'PREDICTED':9s} | {'CONF':6s} | {'STATUS'}")
print("="*75)

for cat in sorted(os.listdir(base)):
    cdir = os.path.join(base, cat)
    if not os.path.isdir(cdir):
        continue
    expected = 'bulk' if cat in ['bulk_transfer', 'fragmented'] else ('voip' if 'voip' in cat else cat)
    for f in sorted(glob.glob(os.path.join(cdir, '*.pcap'))):
        try:
            res = clf.predict_pcap(f)
            pred = res['traffic_classification']['predicted_primary_profile']
            conf = res['traffic_classification']['confidence_score']
            is_correct = (pred == expected)
            if is_correct:
                correct += 1
            total += 1
            status = "MATCH [OK]" if is_correct else "MISMATCH"
            print(f"{cat:15s} | {os.path.basename(f):20s} | {expected:8s} | {pred:9s} | {conf*100:5.1f}% | {status}")
        except Exception as e:
            print(f"Failed {f}: {e}")

print("="*75)
print(f"\nFinal File-Level Accuracy on Downloads/sih26-dataset: {correct}/{total} ({correct/total*100:.2f}%)\n")
