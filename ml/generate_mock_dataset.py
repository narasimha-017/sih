import os
import pandas as pd
import numpy as np

# Resolve workspace root so the script works from any cwd
WORKSPACE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASETS_DIR = os.path.join(WORKSPACE, 'ml', 'datasets')


def generate_dataset():
    os.makedirs(DATASETS_DIR, exist_ok=True)

    phishing_templates = [
        "URGENT: Your account has been suspended! Please click here to verify: http://verification-chase-update.net/login. Enter your routing card numbers immediately.",
        "Invoice Payment Request: Wire transfer authorization of $4,500 needed. Send funds to Routing: 021000021, Account: 98127391823. Confirm back quickly.",
        "Verify your account status. Security breach detected in your department. Input your credentials to bypass holding: http://unsecured-relay.net/auth.",
        "ATTENTION: CEO requests your response on wire verification instructions. Do not share details with third-party vendors."
    ]

    legit_templates = [
        "Hi Team, please find attached the meeting notes and project outline from our weekly review. Looking forward to your comments.",
        "Weekly status update: Q3 analytics report completed. Please view the dashboard on our internal intranet.",
        "Dinner invitation this Friday: Let's catch up on project milestones. Let me know your dietary restrictions.",
        "Thank you for contacting customer support. Your ticket #49102 has been successfully resolved and closed."
    ]

    records = []
    for _ in range(1000):
        records.append({"text": np.random.choice(phishing_templates), "label": 1})
        records.append({"text": np.random.choice(legit_templates),    "label": 0})

    df = pd.DataFrame(records)
    out_path = os.path.join(DATASETS_DIR, 'phishing_emails.csv')
    df.to_csv(out_path, index=False)
    print(f"✅ Successfully generated 2000 mock emails at {out_path}")


if __name__ == "__main__":
    generate_dataset()
