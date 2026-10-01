# ML Results

These values were produced by running `python ml/train_model.py --data data/network_traffic.csv` on the included 5,000-record synthetic dataset.

| Model | Accuracy | Precision | Recall | F1 |
|---|---:|---:|---:|---:|
| Logistic Regression | 98.72% | 100.00% | 96.34% | 98.14% |
| Random Forest | 99.68% | 100.00% | 99.08% | 99.54% |
| Isolation Forest | N/A | 89.14% | 90.16% | 89.65% |

Confusion matrices and raw values are stored in `models/ml_metrics.json`.

These metrics describe performance on this synthetic dataset and should not be treated as evidence of production detection performance.
