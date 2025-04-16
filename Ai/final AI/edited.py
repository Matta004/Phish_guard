import pandas as pd
import numpy as np
import joblib
import re
import nltk
from tqdm import tqdm
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import StringTensorType
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

# Download necessary NLTK resources
nltk.download('stopwords')
nltk.download('wordnet')

# Load dataset
def load_and_prepare_data(file_path):
    df = pd.read_csv(file_path)
    if 'number' in df.columns:
        df = df.drop(columns=['number'])
    df.columns = ['text', 'label']
    df['text'] = df['text'].fillna('').str.strip()
    return df

# Text cleaning function
def clean_text(text):
    text = text.lower()
    text = re.sub(r'http\S+|www\S+|https\S+', '', text, flags=re.MULTILINE)
    text = re.sub(r'[^a-zA-Z\s]', '', text)
    tokens = text.split()
    stop_words = set(stopwords.words('english'))
    tokens = [word for word in tokens if word not in stop_words]
    lemmatizer = WordNetLemmatizer()
    tokens = [lemmatizer.lemmatize(word) for word in tokens]
    return ' '.join(tokens)

# Preprocess data
def preprocess_text(df):
    df['label'] = df['label'].apply(lambda x: 1 if x == 'Phishing Email' else 0)
    tqdm.pandas(desc="Cleaning text")
    df['cleaned_text'] = df['text'].progress_apply(clean_text)
    X = df['cleaned_text']
    y = df['label']
    return X, y

# Train and save the model
def train_model(X, y, n_splits=10):
    vectorizer = TfidfVectorizer(max_features=5000, ngram_range=(1,2))
    X_tfidf = vectorizer.fit_transform(X)

    joblib.dump(vectorizer, "tfidf_vectorizer.pkl")  # Save vectorizer

    clf = SGDClassifier(loss='log_loss', 
                        max_iter=1000, 
                        tol=1e-3, 
                        early_stopping=True, 
                        n_iter_no_change=5, 
                        validation_fraction=0.2, 
                        random_state=42)
    
    print("Performing cross-validation...")
    cross_val_scores = cross_val_score(clf, X_tfidf, y, cv=n_splits, scoring='accuracy', n_jobs=-1)
    print(f"Cross-validation scores: {cross_val_scores}")
    print(f"Average cross-validation score: {np.mean(cross_val_scores)}")

    clf.fit(X_tfidf, y)  # Train model
    return vectorizer, clf

# Convert model to ONNX format
def convert_model_to_onnx(vectorizer, model, output_path):
    pipeline = Pipeline([('tfidf', vectorizer), ('clf', model)])
    initial_type = [('text_input', StringTensorType([None, 1]))]
    onnx_model = convert_sklearn(pipeline, initial_types=initial_type)

    with open(output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    print(f"Model saved in ONNX format at '{output_path}'")

# Main execution
file_path = 'E:/grad project/code/Ai/trialanderror/Merged_Cleaned_Emails.csv'
df = load_and_prepare_data(file_path)
X, y = preprocess_text(df)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

vectorizer, model = train_model(X_train, y_train)

# Convert model to ONNX
onnx_output_path = "phishing_email_pipeline.onnx"
convert_model_to_onnx(vectorizer, model, onnx_output_path)
