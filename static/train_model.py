"""
Train_Model.py  —  ScamShield AI
=================================
Put this file in the SAME folder as your CSV files, then run:
    python Train_Model.py

Handles: CEAS_08, dataset, Enron, Ling, Nazario,
         Nigerian_Fraud, SpamAssasin, phishing_email
"""

import os, sys, json, pickle, warnings
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                              f1_score, confusion_matrix, classification_report)
from sklearn.utils import shuffle

warnings.filterwarnings("ignore")

# ── Find the folder that actually contains the CSV/XLSX files ─────────────────
# Check: (1) folder of this script, (2) current working directory
_script_dir = os.path.dirname(os.path.abspath(__file__))
_cwd        = os.getcwd()

def _has_data(folder):
    """Return True if any CSV/XLSX file exists in folder."""
    for f in os.listdir(folder):
        if f.lower().endswith((".csv", ".xlsx")):
            return True
    return False

if _has_data(_script_dir):
    BASE_DIR = _script_dir
elif _has_data(_cwd):
    BASE_DIR = _cwd
else:
    BASE_DIR = _script_dir  # fallback

print(f"\n{'='*60}")
print(f"  ScamShield AI — Model Training")
print(f"  Working folder: {BASE_DIR}")
print(f"{'='*60}")

# ── List every file in the folder so user can see what was found ──────────────
print("\n  Files detected in folder:")
all_files = [f for f in os.listdir(BASE_DIR)
             if f.lower().endswith((".csv", ".xlsx"))]
for f in sorted(all_files):
    size_mb = os.path.getsize(os.path.join(BASE_DIR, f)) / 1_048_576
    print(f"    {f:<35} {size_mb:>7.1f} MB")
if not all_files:
    print("    *** NO CSV/XLSX FILES FOUND ***")
    print(f"    Make sure Train_Model.py is in the same folder as your datasets.")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
# GENERIC LOADER  — works for any CSV/XLSX with text + label columns
# ══════════════════════════════════════════════════════════════════════════════

TEXT_HINTS  = ["body","text","email","content","message","subject",
               "mail","payload","data"]
LABEL_HINTS = ["label","spam","class","target","category","type",
               "is_spam","flag","phishing"]

def find_col(df, hints):
    for col in df.columns:
        for h in hints:
            if h.lower() == col.lower().strip():
                return col
    for col in df.columns:
        for h in hints:
            if h.lower() in col.lower():
                return col
    return None

def normalize_label(series):
    s = series.astype(str).str.strip().str.lower()
    mapping = {
        "spam":1,"1":1,"1.0":1,"yes":1,"junk":1,"phishing":1,"fraud":1,
        "ham":0,"0":0,"0.0":0,"no":0,"legitimate":0,"notspam":0,"safe":0,
    }
    return s.map(mapping)

def load_dataset_file(filepath):
    """Universal loader. Returns DataFrame with columns: text, label."""
    name = os.path.basename(filepath)
    ext  = os.path.splitext(filepath)[1].lower()
    try:
        if ext == ".csv":
            for enc in ["utf-8","latin-1","cp1252","utf-8-sig"]:
                try:
                    df = pd.read_csv(filepath, encoding=enc, low_memory=False)
                    break
                except (UnicodeDecodeError, Exception):
                    continue
        else:
            df = pd.read_excel(filepath, engine="openpyxl")
    except Exception as e:
        print(f"  [!!] Cannot read {name}: {e}")
        return None

    df.columns = df.columns.str.strip()  # remove whitespace from col names

    print(f"\n  {name}")
    print(f"    Rows   : {len(df):,}")
    print(f"    Columns: {list(df.columns)}")

    text_col  = find_col(df, TEXT_HINTS)
    label_col = find_col(df, LABEL_HINTS)

    # ── Special handling: Nigerian_Fraud / phishing_email may have no label col
    if label_col is None:
        fname_lower = name.lower()
        if any(k in fname_lower for k in ["nigerian","fraud","phishing"]):
            print(f"    No label col found — treating all rows as SPAM (1)")
            label_series = pd.Series([1]*len(df))
        else:
            print(f"    [!!] No label column found — skipping")
            return None
    else:
        label_series = normalize_label(df[label_col])

    if text_col is None:
        print(f"    [!!] No text column found — skipping")
        return None

    # Combine subject + body if both present
    subject_col = find_col(df, ["subject","title","sub"])
    if subject_col and subject_col != text_col:
        combined_text = (df[subject_col].fillna("").astype(str) + " " +
                         df[text_col].fillna("").astype(str))
    else:
        combined_text = df[text_col].fillna("").astype(str)

    out = pd.DataFrame({"text": combined_text, "label": label_series})
    out = out.dropna(subset=["label"])
    out = out[out["label"].isin([0,1])]
    out = out[out["text"].str.strip().str.len() > 10]

    spam_n = (out.label==1).sum()
    ham_n  = (out.label==0).sum()
    print(f"    Spam   : {spam_n:,}  |  Ham: {ham_n:,}  |  Loaded: {len(out):,}")
    return out


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
print("\n\n[1] Loading all datasets...\n")

frames = []
for fname in sorted(all_files):
    fpath = os.path.join(BASE_DIR, fname)
    df = load_dataset_file(fpath)
    if df is not None and len(df) > 0:
        frames.append(df)

if not frames:
    print("\n[!!] No data loaded. Exiting.")
    sys.exit(1)

# ── Combine ───────────────────────────────────────────────────────────────────
print(f"\n\n[2] Combining {len(frames)} dataset(s)...\n")
combined = pd.concat(frames, ignore_index=True)
combined = shuffle(combined, random_state=42).reset_index(drop=True)
combined = combined.drop_duplicates(subset=["text"]).reset_index(drop=True)

total      = len(combined)
total_spam = (combined.label==1).sum()
total_ham  = (combined.label==0).sum()
print(f"  Total unique samples : {total:,}")
print(f"  Spam (1)             : {total_spam:,}  ({total_spam/total*100:.1f}%)")
print(f"  Ham  (0)             : {total_ham:,}  ({total_ham/total*100:.1f}%)")

# ── Split ─────────────────────────────────────────────────────────────────────
print(f"\n[3] Train/test split (80/20 stratified)...\n")
X = combined["text"].values
y = combined["label"].values
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
print(f"  Train: {len(X_train):,}  |  Test: {len(X_test):,}")

# ── Vectorize ─────────────────────────────────────────────────────────────────
print(f"\n[4] Fitting TF-IDF vectorizer...\n")
vectorizer = TfidfVectorizer(
    ngram_range=(1, 2),
    max_features=75000,
    sublinear_tf=True,
    strip_accents="unicode",
    analyzer="word",
    min_df=2,
)
X_train_vec = vectorizer.fit_transform(X_train)
X_test_vec  = vectorizer.transform(X_test)
print(f"  Vocabulary size: {len(vectorizer.vocabulary_):,} features")

# ── Train ─────────────────────────────────────────────────────────────────────
print(f"\n[5] Training Logistic Regression...\n")
model = LogisticRegression(
    C=1.0, solver="lbfgs", max_iter=1000,
    class_weight="balanced", random_state=42, n_jobs=-1,
)
model.fit(X_train_vec, y_train)
print(f"  Training complete.")

# ── Evaluate ──────────────────────────────────────────────────────────────────
print(f"\n[6] Evaluating on test set...\n")
y_pred = model.predict(X_test_vec)
acc  = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, zero_division=0)
rec  = recall_score(y_test, y_pred, zero_division=0)
f1   = f1_score(y_test, y_pred, zero_division=0)
cm   = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

print(classification_report(y_test, y_pred, target_names=["Ham","Spam"]))
print(f"  Accuracy  : {acc*100:.2f}%")
print(f"  Precision : {prec*100:.2f}%")
print(f"  Recall    : {rec*100:.2f}%")
print(f"  F1 Score  : {f1*100:.2f}%")
print(f"  TN={int(tn):,}  FP={int(fp):,}  FN={int(fn):,}  TP={int(tp):,}")

# ── Cross-validation ──────────────────────────────────────────────────────────
print(f"\n[7] 5-fold cross-validation...\n")
X_all_vec  = vectorizer.transform(X)
cv_scores  = cross_val_score(model, X_all_vec, y, cv=5, scoring="f1", n_jobs=-1)
print(f"  CV F1: {cv_scores.mean()*100:.2f}% (+/- {cv_scores.std()*100:.2f}%)")

# ── Save model ────────────────────────────────────────────────────────────────
print(f"\n[8] Saving model.pkl and vectorizer.pkl...\n")
with open(os.path.join(BASE_DIR,"model.pkl"),"wb") as f:
    pickle.dump(model, f)
with open(os.path.join(BASE_DIR,"vectorizer.pkl"),"wb") as f:
    pickle.dump(vectorizer, f)
print(f"  [OK] model.pkl saved")
print(f"  [OK] vectorizer.pkl saved")

# ── Save real stats.json ──────────────────────────────────────────────────────
print(f"\n[9] Saving stats.json...\n")
stats = {
    "accuracy":        round(acc*100,  2),
    "precision":       round(prec*100, 2),
    "recall":          round(rec*100,  2),
    "f1_score":        round(f1*100,   2),
    "cv_f1_mean":      round(cv_scores.mean()*100, 2),
    "cv_f1_std":       round(cv_scores.std()*100,  2),
    "model_type":      "LogisticRegression",
    "vectorizer_type": "TfidfVectorizer",
    "max_features":    75000,
    "ngram_range":     "1-2",
    "training_samples":int(len(X_train)),
    "test_samples":    int(len(X_test)),
    "total_samples":   int(total),
    "spam_count":      int(total_spam),
    "ham_count":       int(total_ham),
    "datasets_loaded": len(frames),
    "dataset_files":   [os.path.basename(f)
                        for f in [os.path.join(BASE_DIR,n) for n in sorted(all_files)]
                        if os.path.exists(f)],
    "confusion_matrix":{"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp)},
}
with open(os.path.join(BASE_DIR,"stats.json"),"w") as f:
    json.dump(stats, f, indent=2)
print(f"  [OK] stats.json saved")

print(f"\n{'='*60}")
print(f"  TRAINING COMPLETE")
print(f"  Accuracy : {acc*100:.2f}%   F1 : {f1*100:.2f}%")
print(f"  Trained on {total:,} emails from {len(frames)} file(s)")
print(f"  Now run:  python app.py")
print(f"{'='*60}\n")
