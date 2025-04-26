#!/usr/bin/env python3
import argparse
import pandas as pd
import numpy as np
import warnings
import joblib
from time import time
from tqdm import tqdm
from sklearn.model_selection import train_test_split, ParameterSampler, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline as SklearnPipeline
from sklearn.metrics import (
    accuracy_score, classification_report,
    roc_curve, precision_recall_curve, confusion_matrix
)
import matplotlib.pyplot as plt

# Import imblearn pipeline and SMOTE if available
try:
    from imblearn.pipeline import Pipeline as ImbPipeline
    from imblearn.over_sampling import SMOTE
except ImportError:
    ImbPipeline = None
    SMOTE = None

warnings.filterwarnings('ignore')

def main(args):
    # Step 1: Load datasets
    t0 = time()
    emails   = pd.read_csv(args.email_path)
    features = pd.read_csv(args.feat_path)
    print(f"[{time()-t0:.1f}s] Loaded {args.email_path!r} & {args.feat_path!r}")

    # Step 2: Merge & define columns
    t0 = time()
    text_col  = 'Email_Text'
    label_col = 'Type'
    df = pd.concat([
        emails.reset_index(drop=True),
        features.reset_index(drop=True)
    ], axis=1)
    # Drop unused columns
    df = df.drop(columns=[c for c in ('number','Email_Type') if c in df])
    # Ensure text column is string and no missing
    df[text_col] = df[text_col].fillna('').astype(str)
    print(f"[{time()-t0:.1f}s] Merged DF with {df.shape[0]} rows")

    # Step 3: Prepare X, y and preprocessing
    t0 = time()
    X = df.drop(columns=[label_col])
    y = df[label_col]
    numeric_cols = [c for c in X.columns if c != text_col]
    # Impute numeric, vectorize text
    preprocessor = ColumnTransformer([
        ('num', SimpleImputer(strategy='median'), numeric_cols),
        ('text', TfidfVectorizer(max_df=0.9, min_df=5, ngram_range=(1,2)), text_col)
    ])
    print(f"[{time()-t0:.1f}s] Prep ready ({len(numeric_cols)} numeric cols + text)")

    # Step 4: Build pipeline with optional SMOTE
    t0 = time()
    enh = args.enhancements
    if 4 in enh and ImbPipeline and SMOTE:
        pipeline = ImbPipeline([
            ('prep', preprocessor),
            ('smote', SMOTE(random_state=42)),
            ('clf', RandomForestClassifier(random_state=42, class_weight='balanced'))
        ])
        smote_status = 'on'
    else:
        if 4 in enh:
            print("⚠️ SMOTE requested but imblearn missing; skipping SMOTE")
        pipeline = SklearnPipeline([
            ('prep', preprocessor),
            ('clf', RandomForestClassifier(random_state=42, class_weight='balanced'))
        ])
        smote_status = 'off'
    print(f"[{time()-t0:.1f}s] Pipeline built (SMOTE={smote_status})")

    # Step 5: Hyperparameter search with progress bar
    t0 = time()
    param_dist = {
        'clf__n_estimators':      [100, 200, 500],
        'clf__max_depth':         [None, 10, 20, 30],
        'clf__min_samples_split': [2, 5, 10],
        'clf__min_samples_leaf':  [1, 2, 4],
        'clf__max_features':      ['auto', 'sqrt']
    }
    if 5 in enh:
        param_dist.update({
            'prep__text__max_df':      [0.8, 0.9, 1.0],
            'prep__text__min_df':      [3, 5, 10],
            'prep__text__ngram_range': [(1,1), (1,2), (1,3)],
        })
    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    param_list = list(ParameterSampler(param_dist, n_iter=20, random_state=42))
    best_score = -np.inf
    best_params = None
    print("🔎 Running hyperparameter search...")
    for params in tqdm(param_list, desc="Params"):
        pipeline.set_params(**params)
        try:
            scores = cross_val_score(pipeline, Xtr, ytr, cv=5, scoring='accuracy', n_jobs=-1)
            m = scores.mean()
            if m > best_score:
                best_score, best_params = m, params
        except Exception as e:
            print(f"⚠️ Params {params} failed: {e}")
    print(f"[{time()-t0:.1f}s] Search done; best CV={best_score:.4f}")

    # Step 6: Refit best model & evaluate
    t0 = time()
    pipeline.set_params(**best_params)
    pipeline.fit(Xtr, ytr)
    ypred = pipeline.predict(Xte)
    acc = accuracy_score(yte, ypred)
    print(f"[{time()-t0:.1f}s] Training complete")
    print("\n🏆 Best params:", best_params)
    print(f"✅ Test accuracy: {acc:.4f}")
    print(classification_report(yte, ypred))

    # Optional reports
    if 1 in enh:
        probs = pipeline.predict_proba(Xte)[:,1]
        fpr, tpr, _ = roc_curve(yte, probs)
        pr_p, pr_r, _ = precision_recall_curve(yte, probs)
        cm = confusion_matrix(yte, ypred)
        plt.figure(); plt.plot(fpr, tpr); plt.title('ROC Curve')
        plt.figure(); plt.plot(pr_r, pr_p); plt.title('Precision-Recall')
        plt.figure(); plt.imshow(cm, cmap=plt.cm.Blues)
        plt.title('Confusion Matrix'); plt.colorbar()
        plt.xticks([0,1], ['Legit','Phish']); plt.yticks([0,1], ['Legit','Phish'])
        plt.show()
    if 3 in enh:
        imps = pipeline.named_steps['clf'].feature_importances_
        feats = numeric_cols + list(pipeline.named_steps['prep']
                                     .named_transformers_['text']
                                     .get_feature_names_out())
        top20 = pd.Series(imps, index=feats).nlargest(20)
        print("\n🔥 Top 20 feature importances:")
        print(top20.to_string())

    # Live classification & export
    print("\n=== Live classification ===")
    sample = input("Paste one email to classify:\n")
    df_s = pd.DataFrame([{text_col: sample}]).assign(**{c:0 for c in numeric_cols})
    df_s[text_col] = df_s[text_col].astype(str)
    pred = pipeline.predict(df_s)[0]
    print("→ Prediction:", "Phishing" if pred==1 else "Legitimate")
    if input("Export model? (y/n): ").lower().startswith('y'):
        joblib.dump(pipeline, 'rf_phish_model.joblib')
        print("✔ Saved to rf_phish_model.joblib")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Train RF phishing detector")
    parser.add_argument(
        '--enhancements', '-e', nargs='+', type=int, default=[1,2,3,4,5],
        help="1=metrics 2=CV report 3=feat imp 4=SMOTE 5=TF-IDF search"
    )
    parser.add_argument(
        '--email-path', '-i',
        default=r"E:\grad project\new model\Merged_Cleaned_Emails.csv",
        help="Path to cleaned emails CSV"
    )
    parser.add_argument(
        '--feat-path', '-f',
        default=r"E:\grad project\new model\Datasetadvanced.csv",
        help="Path to numeric features CSV"
    )
    args = parser.parse_args()
    main(args)
