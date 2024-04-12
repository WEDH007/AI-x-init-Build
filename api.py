from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import requests
import datetime
from joblib import load
from using_trained_model import preprocess_df

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for development. Be more restrictive for production.
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

model_path = 'random_forest_model.joblib'
scaler_path = 'scaler.joblib'
feature_columns_path = 'feature_columns.joblib'

rf_classifier = load(model_path)
scaler = load(scaler_path)
feature_columns = load(feature_columns_path)

precision = {
    "ddos": 0.95,
    "dos": 0.95,
    "injection": 0.98,
    "normal": 1.00,
    "password": 0.87,
    "scanning": 0.65,
    "xss": 0.67
}

def send_alert(alert_data):
    headers = {'Content-Type': 'application/json'}
    response = requests.post(
        # "https://spring2024-alerts.onrender.com/api/alerts",
        "http://127.0.0.1:5000/api/alerts",
        headers=headers,
        json=alert_data
    )
    try:
        response.raise_for_status()
        # If you want to log the successful response, uncomment the next line
        print(f"Alert sent successfully: {response.text}")
    except requests.exceptions.HTTPError as err:
        # Log the error
        print(f"Error sending alert: {err}")

def epoch_to_date(epoch_timestamp):
    """Converts an epoch timestamp to a human-readable date."""
    return datetime.datetime.fromtimestamp(epoch_timestamp).strftime('%Y-%m-%d %H:%M:%S')


@app.post("/detect-attacks/")
async def detect_attacks(file: UploadFile = File(...)):
    df = pd.read_csv(file.file)

    df_preprocessed, _ = preprocess_df(df, scaler)
    df_aligned = df_preprocessed.reindex(columns=feature_columns, fill_value=0)

    predictions = rf_classifier.predict(df_aligned)
    df['type'] = predictions


    # for index, row in df.iterrows():
    #     if row['type'] != 'normal':``
    #         precision_score = precision.get(row['type'], "N/A")
    #         probability = f"{precision_score * 100}%" if precision_score != "N/A" else "N/A"
    #         alert_data = {
    #             "attack": row["type"],
    #             "probability": probability,
    #             "date": epoch_to_date(row['ts']),
    #             "src_ip": row["src_ip"],
    #         }
    #         send_alert(alert_data)

    modified_csv_path = "modified_with_predictions.csv"
    df.to_csv(modified_csv_path, index=False)

    return FileResponse(path=modified_csv_path, filename="modified_with_predictions.csv")
