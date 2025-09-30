# scripts/test_ember.py
import os, numpy as np, lightgbm as lgb
from sklearn.metrics import accuracy_score, roc_auc_score, classification_report, confusion_matrix, roc_curve, average_precision_score
import matplotlib.pyplot as plt

DATA_DIR   = r"data\ember2018"
MODEL_PATH = os.path.join(DATA_DIR, "ember_model_2018.txt")
FEATURE_DIM = 2381
ARTIFACTS = os.path.join(DATA_DIR, "artifacts"); os.makedirs(ARTIFACTS, exist_ok=True)

def load_memmaps(data_dir):
    import os, numpy as np
    FEATURE_DIM = 2381

    # X_test: always float32 vectors
    xt_path = os.path.join(data_dir, "X_test.dat")
    bytes_xt = os.path.getsize(xt_path)
    n_rows = bytes_xt // (FEATURE_DIM * np.dtype(np.float32).itemsize)
    X_test = np.memmap(xt_path, dtype=np.float32, mode="r", shape=(n_rows, FEATURE_DIM))
    
    # y_test: could be uint8, int32, or float32 (for 0.0/1.0 labels)
    yt_path = os.path.join(data_dir, "y_test.dat")
    bytes_yt = os.path.getsize(yt_path)
    
    # Check expected size for possible dtypes, using the correct n_rows
    expected_bytes_uint8 = n_rows * np.dtype(np.uint8).itemsize
    expected_bytes_int32 = n_rows * np.dtype(np.int32).itemsize
    expected_bytes_float32 = n_rows * np.dtype(np.float32).itemsize
    
    if bytes_yt == expected_bytes_uint8:
        y_dtype = np.uint8
    elif bytes_yt == expected_bytes_int32:
        y_dtype = np.int32
    elif bytes_yt == expected_bytes_float32:
        y_dtype = np.float32
    else:
        raise ValueError(
            f"y_test.dat size {bytes_yt} doesn’t match {n_rows} rows for "
            "uint8, int32, or float32 dtypes."
        )
        
    # 1. Read the data from the memmap
    y_test_memmap = np.memmap(yt_path, dtype=y_dtype, mode="r", shape=(n_rows,))
    
    # 2. **CRUCIAL FIX: Force a copy into a standard NumPy array**
    # This ensures the subsequent type casting works correctly, 
    # even if y_dtype was float32.
    y_test_copy = np.array(y_test_memmap)
    y_test_copy = np.array(y_test_memmap)
    y_test = (y_test_copy > 0.5).astype(np.int32)

    return X_test, y_test

def main():
    print("Loading model:", MODEL_PATH)
    model = lgb.Booster(model_file=MODEL_PATH)
    print("Loaded. Num features:", model.num_feature())

    print("Loading test memmaps…")
    X_test, y_test = load_memmaps(DATA_DIR)
    print("Shapes:", X_test.shape, y_test.shape)

    print("Predicting…")
    y_proba = model.predict(X_test)               # probabilities in [0,1]
    y_pred  = (y_proba >= 0.5).astype(int)

    # Basic metrics
    acc  = accuracy_score(y_test, y_pred)
    auc  = roc_auc_score(y_test, y_proba)
    ap   = average_precision_score(y_test, y_proba)
    cm   = confusion_matrix(y_test, y_pred)
    print(f"\nAccuracy@0.5: {acc:.4f}")
    print(f"ROC AUC:      {auc:.4f}")
    print(f"Avg Precision: {ap:.4f}")
    print("\nConfusion matrix @0.5:\n", cm)
    print("\nClassification report @0.5:\n", classification_report(y_test, y_pred, digits=4))

    # Find threshold for ~1% FPR (useful in malware)
    fpr, tpr, thr = roc_curve(y_test, y_proba)
    import numpy as np
    idx = np.searchsorted(fpr, 0.01) if len(thr)>0 else 0
    best_thr = float(thr[min(idx, len(thr)-1)]) if len(thr)>0 else 0.5
    y_pred_fpr1 = (y_proba >= best_thr).astype(int)
    cm1 = confusion_matrix(y_test, y_pred_fpr1)
    print(f"\nThreshold at ~1% FPR: {best_thr:.4f}")
    print("Confusion matrix @~1% FPR:\n", cm1)

    # Save ROC/PR curves
    plt.figure(); plt.plot(fpr, tpr); plt.plot([0,1],[0,1],'--'); plt.xlabel("FPR"); plt.ylabel("TPR"); plt.title(f"ROC (AUC={auc:.4f})")
    roc_path = os.path.join(ARTIFACTS, "roc_curve.png"); plt.savefig(roc_path, dpi=160, bbox_inches="tight"); plt.close()
    from sklearn.metrics import precision_recall_curve
    prec, rec, _ = precision_recall_curve(y_test, y_proba)
    plt.figure(); plt.plot(rec, prec); plt.xlabel("Recall"); plt.ylabel("Precision"); plt.title(f"PR (AP={ap:.4f})")
    pr_path = os.path.join(ARTIFACTS, "pr_curve.png"); plt.savefig(pr_path, dpi=160, bbox_inches="tight"); plt.close()
    print("Saved:", roc_path, "and", pr_path)

    # Feature importance (sanity)
    gains = model.feature_importance(importance_type="gain")
    splits = model.feature_importance(importance_type="split")
    print("\nTop 10 features by gain:")
    top = np.argsort(gains)[-10:][::-1]
    for i in top:
        print(f"  idx={i:4d}  gain={gains[i]:.1f}  splits={splits[i]}")

if __name__ == "__main__":
    main()
