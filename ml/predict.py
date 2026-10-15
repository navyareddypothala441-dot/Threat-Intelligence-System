"""
Machine Learning Risk Prediction
OSINT Threat Intelligence Platform

Compatible with the existing app.py.

Expected app.py call:

predict_risk(
    malicious_count=...,
    suspicious_count=...,
    abuse_confidence_score=...,
    total_reports=...,
    related_ioc_count=...,
    source_count=...,
    port_count=...,
    vulnerability_count=...,
    recent_activity=...,
    reputation=...
)
"""

import os
from pathlib import Path

import joblib
import pandas as pd


# ============================================================
# MODEL LOCATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

MODEL_PATHS = [
    BASE_DIR / "risk_model.pkl",
    BASE_DIR / "model.pkl",
    BASE_DIR / "random_forest_model.pkl",
    BASE_DIR.parent / "risk_model.pkl",
    BASE_DIR.parent / "model.pkl",
    BASE_DIR.parent / "random_forest_model.pkl",
]


# ============================================================
# FEATURE ORDER
# ============================================================

FEATURE_COLUMNS = [
    "malicious_count",
    "suspicious_count",
    "abuse_confidence_score",
    "total_reports",
    "related_ioc_count",
    "source_count",
    "port_count",
    "vulnerability_count",
    "recent_activity",
    "reputation"
]


# ============================================================
# FIND MODEL
# ============================================================

def find_model():

    for path in MODEL_PATHS:

        if path.exists():

            try:

                model = joblib.load(
                    path
                )

                print(
                    f"ML model loaded: {path}"
                )

                return model

            except Exception as e:

                print(
                    f"Could not load model {path}: {e}"
                )

    return None


# ============================================================
# SAFE NUMBER
# ============================================================

def safe_number(
    value,
    default=0
):

    try:

        if value is None:
            return default

        if isinstance(value, str):

            value = value.strip()

            if value == "":
                return default

        return float(value)

    except (
        ValueError,
        TypeError
    ):

        return default


# ============================================================
# SAFE INTEGER
# ============================================================

def safe_integer(
    value,
    default=0
):

    try:

        return int(
            safe_number(
                value,
                default
            )
        )

    except (
        ValueError,
        TypeError
    ):

        return default


# ============================================================
# NORMALIZE LABEL
# ============================================================

def normalize_label(label):

    """
    Convert different model labels into the platform's
    standard risk labels.
    """

    if label is None:
        return "UNKNOWN"

    text = str(
        label
    ).strip().upper()

    # --------------------------------------------------------
    # Direct labels
    # --------------------------------------------------------

    if text in [
        "LOW",
        "MEDIUM",
        "SUSPICIOUS",
        "HIGH",
        "CRITICAL"
    ]:

        return text

    # --------------------------------------------------------
    # Common variations
    # --------------------------------------------------------

    mapping = {

        "0": "LOW",
        "1": "MEDIUM",
        "2": "HIGH",
        "3": "CRITICAL",

        "LOW RISK": "LOW",
        "MEDIUM RISK": "MEDIUM",
        "HIGH RISK": "HIGH",
        "CRITICAL RISK": "CRITICAL",

        "SAFE": "LOW",
        "BENIGN": "LOW",

        "SUSPICIOUS": "SUSPICIOUS",
        "MALICIOUS": "HIGH"
    }

    return mapping.get(
        text,
        "UNKNOWN"
    )


# ============================================================
# GET CLASS NAME
# ============================================================

def get_class_name(
    model,
    class_value
):

    """
    Convert numeric model class into its actual class name
    using model.classes_ when available.
    """

    try:

        classes = getattr(
            model,
            "classes_",
            None
        )

        if classes is None:
            return class_value

        # Find matching class
        for cls in classes:

            if str(cls) == str(class_value):

                return cls

        # Numeric index
        try:

            index = int(
                class_value
            )

            if 0 <= index < len(classes):

                return classes[index]

        except (
            ValueError,
            TypeError
        ):

            pass

    except Exception:

        pass

    return class_value


# ============================================================
# MAIN PREDICTION FUNCTION
# ============================================================

def predict_risk(
    malicious_count=0,
    suspicious_count=0,
    abuse_confidence_score=0,
    total_reports=0,
    related_ioc_count=0,
    source_count=0,
    port_count=0,
    vulnerability_count=0,
    recent_activity=False,
    reputation=0
):

    """
    Predict IOC risk using the trained Random Forest model.

    IMPORTANT:
    This function keeps the exact parameter names expected by
    the existing app.py.
    """

    # ========================================================
    # SAFE CONVERSION
    # ========================================================

    malicious_count = safe_integer(
        malicious_count
    )

    suspicious_count = safe_integer(
        suspicious_count
    )

    abuse_confidence_score = safe_integer(
        abuse_confidence_score
    )

    total_reports = safe_integer(
        total_reports
    )

    related_ioc_count = safe_integer(
        related_ioc_count
    )

    source_count = safe_integer(
        source_count
    )

    port_count = safe_integer(
        port_count
    )

    vulnerability_count = safe_integer(
        vulnerability_count
    )

    reputation = safe_integer(
        reputation
    )

    recent_activity = (
        1
        if str(recent_activity).lower()
        in [
            "true",
            "1",
            "yes"
        ]
        else 0
    )

    # ========================================================
    # CREATE DATAFRAME
    # ========================================================

    features = {
        "malicious_count": [
            malicious_count
        ],

        "suspicious_count": [
            suspicious_count
        ],

        "abuse_confidence_score": [
            abuse_confidence_score
        ],

        "total_reports": [
            total_reports
        ],

        "related_ioc_count": [
            related_ioc_count
        ],

        "source_count": [
            source_count
        ],

        "port_count": [
            port_count
        ],

        "vulnerability_count": [
            vulnerability_count
        ],

        "recent_activity": [
            recent_activity
        ],

        "reputation": [
            reputation
        ]
    }

    X = pd.DataFrame(
        features,
        columns=FEATURE_COLUMNS
    )

    # ========================================================
    # FIND MODEL
    # ========================================================

    model = find_model()

    if model is None:

        return {
            "available": False,
            "risk": "UNKNOWN",
            "prediction": "UNKNOWN",
            "confidence": 0.0,
            "score": None,
            "risk_score": None,
            "probabilities": {},
            "error": (
                "Random Forest model file was not found."
            )
        }

    # ========================================================
    # PREDICTION
    # ========================================================

    try:

        prediction = model.predict(
            X
        )

        raw_prediction = prediction[0]

        class_name = get_class_name(
            model,
            raw_prediction
        )

        risk = normalize_label(
            class_name
        )

        # ====================================================
        # PROBABILITIES
        # ====================================================

        probabilities = {}

        if hasattr(
            model,
            "predict_proba"
        ):

            probability_array = model.predict_proba(
                X
            )[0]

            classes = getattr(
                model,
                "classes_",
                []
            )

            for cls, probability in zip(
                classes,
                probability_array
            ):

                cls_name = normalize_label(
                    cls
                )

                probabilities[
                    cls_name
                ] = round(
                    float(probability) * 100,
                    2
                )

        # ====================================================
        # CONFIDENCE
        # ====================================================

        if probabilities:

            confidence = max(
                probabilities.values()
            )

        else:

            confidence = 0.0

        # ====================================================
        # CALCULATE DISPLAY SCORE
        # ====================================================

        score_mapping = {

            "LOW": 20,

            "MEDIUM": 40,

            "SUSPICIOUS": 60,

            "HIGH": 80,

            "CRITICAL": 100
        }

        risk_score = score_mapping.get(
            risk
        )

        # ====================================================
        # RESULT
        # ====================================================

        return {

            "available": True,

            "risk": risk,

            "prediction": risk,

            "confidence": round(
                confidence,
                2
            ),

            "score": risk_score,

            "risk_score": risk_score,

            "probabilities": probabilities,

            "model": "Random Forest"
        }

    except Exception as e:

        print(
            f"ML prediction error: {e}"
        )

        return {

            "available": False,

            "risk": "UNKNOWN",

            "prediction": "UNKNOWN",

            "confidence": 0.0,

            "score": None,

            "risk_score": None,

            "probabilities": {},

            "error": str(e),

            "model": "Random Forest"
        }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 60)

    print(
        "RANDOM FOREST PREDICTION TEST"
    )

    print("=" * 60)

    result = predict_risk(

        malicious_count=0,

        suspicious_count=0,

        abuse_confidence_score=0,

        total_reports=7,

        related_ioc_count=22,

        source_count=4,

        port_count=15,

        vulnerability_count=0,

        recent_activity=True,

        reputation=114
    )

    print("\nResult:")

    print(
        result
    )

    print("\n" + "=" * 60)