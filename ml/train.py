import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report


# ============================================================
# 1. CREATE TRAINING DATASET
# ============================================================

data = [
    # malicious, suspicious, abuse_score, reports,
    # related_iocs, sources, ports, vulnerabilities,
    # recent_activity, reputation, risk

    [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, "LOW"],
    [0, 0, 0, 2, 1, 1, 1, 0, 0, 10, "LOW"],
    [0, 0, 5, 5, 1, 2, 1, 0, 0, 20, "LOW"],
    [0, 0, 10, 10, 2, 2, 2, 0, 0, 30, "LOW"],

    [1, 1, 25, 20, 2, 2, 2, 0, 1, 10, "MEDIUM"],
    [1, 2, 35, 30, 3, 3, 3, 1, 1, 5, "MEDIUM"],
    [2, 1, 40, 40, 4, 3, 3, 1, 1, 0, "MEDIUM"],
    [2, 2, 45, 50, 5, 3, 4, 1, 1, -10, "MEDIUM"],

    [4, 2, 55, 70, 6, 3, 5, 2, 1, -20, "HIGH"],
    [5, 3, 65, 90, 7, 4, 6, 2, 1, -30, "HIGH"],
    [6, 4, 75, 120, 8, 4, 7, 3, 1, -40, "HIGH"],
    [8, 5, 85, 150, 10, 4, 8, 4, 1, -50, "HIGH"],

    [10, 6, 90, 180, 12, 4, 10, 5, 1, -60, "CRITICAL"],
    [12, 8, 95, 250, 15, 5, 12, 6, 1, -70, "CRITICAL"],
    [15, 10, 100, 400, 20, 5, 15, 8, 1, -80, "CRITICAL"],
]


columns = [
    "malicious_count",
    "suspicious_count",
    "abuse_confidence_score",
    "total_reports",
    "related_ioc_count",
    "source_count",
    "port_count",
    "vulnerability_count",
    "recent_activity",
    "reputation",
    "risk"
]

df = pd.DataFrame(data, columns=columns)


# ============================================================
# 2. DISPLAY DATASET
# ============================================================

print("\n======================================")
print("OSINT ML TRAINING DATASET")
print("======================================")

print("\nDataset:")
print(df)

print("\nDataset shape:", df.shape)

print("\nRisk distribution:")
print(df["risk"].value_counts())


# ============================================================
# 3. SPLIT FEATURES AND TARGET
# ============================================================

X = df.drop("risk", axis=1)
y = df["risk"]


# ============================================================
# 4. TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42,
    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# ============================================================
# 5. TRAIN RANDOM FOREST
# ============================================================

model = RandomForestClassifier(
    n_estimators=200,
    random_state=42,
    class_weight="balanced"
)

model.fit(X_train, y_train)


# ============================================================
# 6. EVALUATE MODEL
# ============================================================

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\n======================================")
print("MODEL PERFORMANCE")
print("======================================")

print("\nAccuracy:", round(accuracy * 100, 2), "%")

print("\nClassification Report:")
print(classification_report(y_test, y_pred, zero_division=0))


# ============================================================
# 7. FEATURE IMPORTANCE
# ============================================================

feature_importance = pd.DataFrame({
    "feature": X.columns,
    "importance": model.feature_importances_
})

feature_importance = feature_importance.sort_values(
    by="importance",
    ascending=False
)

print("\n======================================")
print("FEATURE IMPORTANCE")
print("======================================")

print(feature_importance)


# ============================================================
# 8. SAVE MODEL
# ============================================================

model_path = "ml/risk_model.pkl"

joblib.dump(model, model_path)

print("\n======================================")
print("MODEL SAVED")
print("======================================")

print(f"\nModel saved to: {model_path}")