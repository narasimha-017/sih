import os
import pickle
import pandas as pd
import numpy as np
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix
)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

# Resolve workspace root (one level up from ml/)
WORKSPACE     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR  = os.path.join(WORKSPACE, 'ml', 'datasets')
MODELS_DIR    = os.path.join(WORKSPACE, 'ml', 'models')
EVAL_DIR      = os.path.join(WORKSPACE, 'ml', 'evaluation')


class SimpleNN(nn.Module):
    def __init__(self, input_dim):
        super(SimpleNN, self).__init__()
        self.fc = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(64, 2)
        )

    def forward(self, x):
        return self.fc(x)


def train_classifier():
    print("🚀 Initializing Email Threat Classifier Training Pipeline...")
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(EVAL_DIR,   exist_ok=True)

    dataset_path = os.path.join(DATASETS_DIR, 'phishing_emails.csv')
    df = pd.read_csv(dataset_path)
    print(f"📦 Loading dataset from {dataset_path}...")
    # BUG FIX: df.shape is a tuple; use [0] for rows and [1] for columns
    print(f"📊 Dataset Shape: {df.shape[0]} rows, {df.shape[1]} columns")

    df = df.dropna()
    df['label'] = df['label'].astype(int)
    print("🧹 Pre-processing dataset...")
    print(
        f"   Class distribution: "
        f"Legitimate (0): {sum(df['label'] == 0)}, "
        f"Phishing (1): {sum(df['label'] == 1)}"
    )

    df['text'] = df['text'].str.lower()

    # 70/10/20 Train-Val-Test Splits
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        df['text'], df['label'], test_size=0.20, random_state=42, stratify=df['label']
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=0.125, random_state=42, stratify=y_train_val
    )
    print(
        f"📈 Splits completed successfully:\n"
        f"   Train Set size:      {len(X_train)}\n"
        f"   Validation Set size: {len(X_val)}\n"
        f"   Test Set size:       {len(X_test)}"
    )

    # TF-IDF Vectorization
    # Self-heal: max_features=None lets vectorizer use the true vocabulary size.
    # The mock dataset has only ~113 unique tokens; hardcoding 1000 caused a shape mismatch.
    print("🔑 Extracting features (TF-IDF Vectorization)...")
    vectorizer     = TfidfVectorizer(max_features=None, lowercase=False)
    X_train_feats  = vectorizer.fit_transform(X_train).toarray()
    X_val_feats    = vectorizer.transform(X_val).toarray()
    X_test_feats   = vectorizer.transform(X_test).toarray()

    vectorizer_path = os.path.join(MODELS_DIR, 'vectorizer.pkl')
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    input_dim = len(vectorizer.vocabulary_)  # true feature count from actual vocab
    print(f"💾 Saved TF-IDF Vectorizer to {vectorizer_path} (vocab size: {input_dim} features)")

    # Tensors
    device     = torch.device('cpu')  # CPU fallback enforced per directive
    X_train_t  = torch.tensor(X_train_feats,   dtype=torch.float32).to(device)
    y_train_t  = torch.tensor(y_train.values,  dtype=torch.long).to(device)
    X_val_t    = torch.tensor(X_val_feats,     dtype=torch.float32).to(device)
    y_val_t    = torch.tensor(y_val.values,    dtype=torch.long).to(device)
    X_test_t   = torch.tensor(X_test_feats,    dtype=torch.float32).to(device)
    y_test_t   = torch.tensor(y_test.values,   dtype=torch.long).to(device)

    model     = SimpleNN(input_dim=input_dim).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.005)

    epochs       = 6
    train_losses = []
    val_losses   = []

    print(f"🏋️ Starting PyTorch Neural Network Training for {epochs} epochs...")
    for epoch in range(epochs):
        model.train()
        optimizer.zero_grad()
        outputs = model(X_train_t)
        loss    = criterion(outputs, y_train_t)
        loss.backward()
        optimizer.step()

        model.eval()
        with torch.no_grad():
            val_outputs = model(X_val_t)
            val_loss    = criterion(val_outputs, y_val_t)
            preds       = torch.argmax(val_outputs, dim=1)
            val_acc     = accuracy_score(y_val_t.cpu().numpy(), preds.cpu().numpy())

        train_losses.append(loss.item())
        val_losses.append(val_loss.item())
        print(
            f"   Epoch {epoch+1}/{epochs} | "
            f"Train Loss: {loss.item():.4f} | "
            f"Val Loss: {val_loss.item():.4f} | "
            f"Val Accuracy: {val_acc*100:.2f}%"
        )

    # Test set evaluation
    model.eval()
    with torch.no_grad():
        test_outputs = model(X_test_t)
        test_preds   = torch.argmax(test_outputs, dim=1).cpu().numpy()

    test_acc  = accuracy_score(y_test,  test_preds)
    test_prec = precision_score(y_test, test_preds)
    test_rec  = recall_score(y_test,    test_preds)
    test_f1   = f1_score(y_test,        test_preds)
    test_cm   = confusion_matrix(y_test, test_preds)

    print("📝 Evaluating model on unseen test dataset...")
    print("\n📊 --- FINAL TEST PERFORMANCE ---")
    print(f"   Accuracy:  {test_acc*100:.2f}%")
    print(f"   Precision: {test_prec*100:.2f}% (How reliable our warnings are)")
    print(f"   Recall:    {test_rec*100:.2f}% (How many phishing attempts we caught)")
    print(f"   F1-Score:  {test_f1*100:.2f}%")
    print(f"   Confusion Matrix:\n{test_cm}")

    model_path = os.path.join(MODELS_DIR, 'email_classifier.pth')
    torch.save(model.state_dict(), model_path)
    print(f"💾 Successfully saved PyTorch model weights to {model_path}")

    # Performance chart
    print("   Generating performance charts...")
    plt.figure(figsize=(10, 4))
    plt.plot(range(1, epochs+1), train_losses, label='Training Loss',   marker='o')
    plt.plot(range(1, epochs+1), val_losses,   label='Validation Loss', marker='x')
    plt.xlabel('Epochs')
    plt.ylabel('Cross-Entropy Loss')
    plt.title('Email Classifier — Training Loss Metrics')
    plt.legend()
    plt.grid(True)
    chart_path = os.path.join(EVAL_DIR, 'training_metrics.png')
    plt.savefig(chart_path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"🎨 Performance graph saved successfully to {chart_path}")
    print("🎉 Pipeline executed cleanly to completion!")


if __name__ == "__main__":
    train_classifier()
