import os
import re
import pickle
import torch
import torch.nn as nn

# Resolve workspace root (three levels up: backend/app/parser/ → workspace)
WORKSPACE = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)
MODELS_DIR = os.path.join(WORKSPACE, 'ml', 'models')


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


class RealtimeAIClassifier:
    def __init__(self):
        try:
            vectorizer_path = os.path.join(MODELS_DIR, 'vectorizer.pkl')
            model_path      = os.path.join(MODELS_DIR, 'email_classifier.pth')

            with open(vectorizer_path, 'rb') as f:
                self.vectorizer = pickle.load(f)

            input_dim = len(self.vectorizer.vocabulary_)  # match trained model dimensions
            self.model = SimpleNN(input_dim=input_dim)
            self.model.load_state_dict(
                torch.load(model_path, map_location=torch.device('cpu'))
            )
            self.model.eval()
            print("🧠 Real-time AI Email Threat Classifier successfully loaded.")
        except Exception as e:
            print(f"⚠️ Error loading local classifier weights: {e}. Model fallback initiated.")
            self.vectorizer = None

    def predict(self, text):
        """Returns phishing class probability (float 0.0–1.0)."""
        if self.vectorizer is None:
            return 0.50  # Low-accuracy fallback

        features = self.vectorizer.transform([text.lower()]).toarray()
        feats_t  = torch.tensor(features, dtype=torch.float32)

        with torch.no_grad():
            outputs = self.model(feats_t)
            probs   = torch.softmax(outputs, dim=1).numpy()

        # BUG FIX: probs.shape == (1, 2) — index [0][1] for the phishing class probability
        return float(probs[0][1])


def parse_incoming_email(raw_email_json):
    """
    Parses headers and extracts body elements from raw incoming payload.
    Identifies urgent indicators, Reply-To mismatches, and auth flags.
    """
    headers = raw_email_json.get("headers", {})
    body    = raw_email_json.get("body", "")

    sender   = headers.get("From",          "unknown@sender.com")
    subject  = headers.get("Subject",       "")
    reply_to = headers.get("Reply-To",      sender)
    spf      = headers.get("Received-SPF",  "FAIL").upper()
    dkim     = headers.get("DKIM-Signature","FAIL").upper()
    dmarc    = headers.get("DMARC-Status",  "FAIL").upper()

    # Reply-To anomaly check
    reply_to_mismatch = reply_to != sender

    # Extract structural links
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)

    # Run PyTorch classification
    classifier    = RealtimeAIClassifier()
    ai_phish_prob = classifier.predict(body)

    return {
        "sender":               sender,
        "subject":              subject,
        "reply_to":             reply_to,
        "reply_to_mismatch":    reply_to_mismatch,
        "auth_status":          {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "urls":                 list(set(urls)),
        "ai_threat_probability": ai_phish_prob,
    }


if __name__ == "__main__":
    test_payload = {
        "headers": {
            "From":             "support@chase-security-update.net",
            "Subject":          "URGENT: Your bank account is locked!",
            "Reply-To":         "attacker-inbox@anonymous-mail.ru",
            "Received-SPF":     "FAIL",
            "DKIM-Signature":   "FAIL",
        },
        "body": (
            "URGENT: Your bank account is locked! Please verify at once: "
            "http://chase-security-update.net/auth. Provide credit card credentials."
        ),
    }
    result = parse_incoming_email(test_payload)
    print("\n📩 --- PARSED TEST EMAIL RESULT ---")
    print(f"   Sender:         {result['sender']}")
    print(f"   Subject:        {result['subject']}")
    print(f"   Reply-To:       {result['reply_to']} (Mismatch: {result['reply_to_mismatch']})")
    print(f"   Auth Status:    SPF={result['auth_status']['spf']} | DKIM={result['auth_status']['dkim']} | DMARC={result['auth_status']['dmarc']}")
    print(f"   URLs Found:     {result['urls']}")
    print(f"   AI Threat Prob: {result['ai_threat_probability'] * 100:.2f}%")
