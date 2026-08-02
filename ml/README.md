# ML — Phishing Website Classifier (trained models)

The **trained-model** core of the project: a classic supervised-learning pipeline that
classifies URLs as **phishing** or **legitimate**, evaluated with accuracy,
precision, recall, F1, ROC-AUC, and a confusion matrix.

This complements the [`phishprobe`](../README.md) package: this notebook shows you can
*build* a detector; `phishprobe` then *adversarially tests* one.

## Contents

| File | What it is |
|------|-----------|
| `phishing_ml.ipynb` | The notebook — run this. Outputs and plots are already baked in. |
| `phishing_ml.py` | Script export of the same pipeline (for running without Jupyter). |
| `data/urldata.csv` | The dataset (10,000 URLs, 16 features, balanced 50/50). |
| `requirements.txt` | numpy, pandas, scikit-learn, matplotlib, jupyter. |

## Dataset

10,000 URLs — **5,000 phishing / 5,000 legitimate** — with 16 numeric URL/domain
features (`Have_IP`, `TinyURL`, `Prefix/Suffix`, `iFrame`, `Domain_Age`, …) and a
binary `Label` (1 = phishing, 0 = legitimate). Derived from the UCI *Phishing
Websites* research; obtained from
[shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques](https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques)
(`DataFiles/5.urldata.csv`).

## Run it

```bash
pip install -r requirements.txt
jupyter notebook phishing_ml.ipynb      # interactive
# or, without Jupyter:
python phishing_ml.py
```

## What the notebook does

1. Load + explore the data (class balance, feature-vs-label correlation).
2. Stratified train/test split; feature scaling inside a `Pipeline`.
3. **Logistic Regression** — the interpretable linear model — with full metrics,
   a confusion matrix, and a coefficient plot (which features drive "phishing").
4. **Linear Regression** baseline, to show *why* it's the wrong tool for a yes/no task.
5. **Model comparison** — Logistic Regression vs Decision Tree, Random Forest,
   SVM, k-NN — as a metrics table, a bar chart, and ROC curves.
6. 5-fold **cross-validation** to check the headline score is stable.

## Results (from the executed notebook)

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|-------|----------|-----------|--------|-----|---------|
| Random Forest | 0.868 | 0.926 | 0.800 | **0.858** | 0.926 |
| k-NN | 0.848 | 0.873 | 0.813 | 0.842 | 0.898 |
| SVM (RBF) | 0.833 | 0.983 | 0.678 | 0.802 | 0.891 |
| Decision Tree | 0.823 | 0.992 | 0.650 | 0.786 | 0.876 |
| Logistic Regression | 0.797 | 0.923 | 0.647 | 0.761 | 0.874 |

**Takeaways:** Random Forest leads; Logistic Regression is the most *interpretable*
(readable coefficients) but here has the lowest F1 — high precision (~0.92), lower
recall (~0.65), i.e. it rarely false-alarms but misses phishing it's unsure about.
Linear regression underperforms and emits non-probability outputs. 5-fold F1 for
logistic regression is stable at ~0.767 (std ~0.01).

> A strong test-set score answers *"is it accurate?"* — not *"is it robust?"*. That
> second question is what the `phishprobe` adversarial harness measures.
