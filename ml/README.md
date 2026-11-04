# Phishing URL classifier

A notebook that trains a few classifiers to tell phishing URLs from legitimate ones. It's separate from the `phishprobe` package.

The data is 10,000 URLs (half phishing) with 16 features, based on the UCI Phishing Websites dataset. It comes from [shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques](https://github.com/shreyagopal/Phishing-Website-Detection-by-Machine-Learning-Techniques).

```bash
pip install -r requirements.txt
jupyter notebook phishing_ml.ipynb
```

## Results

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|-------|----------|-----------|--------|-----|---------|
| Random Forest | 0.868 | 0.926 | 0.800 | 0.858 | 0.926 |
| k-NN | 0.848 | 0.873 | 0.813 | 0.842 | 0.898 |
| SVM (RBF) | 0.833 | 0.983 | 0.678 | 0.802 | 0.891 |
| Decision Tree | 0.823 | 0.992 | 0.650 | 0.786 | 0.876 |
| Logistic Regression | 0.797 | 0.923 | 0.647 | 0.761 | 0.874 |

Random forest does best. Logistic regression has the lowest F1, but you can read its coefficients to see why a URL got flagged. Its precision is high and its recall is low, so it rarely false-alarms but misses a lot of phishing.
