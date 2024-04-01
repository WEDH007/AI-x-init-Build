from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
from using_trained_model import preprocess_df, load
from joblib import load
import requests

app = FastAPI()

# CORS middleware configuration for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins for development. Be more restrictive for production.
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)

# Assuming your model, scaler, and feature columns are loaded here
model_path = 'random_forest_model.joblib'
scaler_path = 'scaler.joblib'
feature_columns_path = 'feature_columns.joblib'

rf_classifier = load(model_path)
scaler = load(scaler_path)
feature_columns = load(feature_columns_path)

# Example F1-scores dictionary - replace with your actual data
f1_scores = {
    "ddos": 0.88,
    "dos": 0.98,
    "injection": 0.95,
    "normal": 1.00,  # It's unlikely you will need an F1-score for normal traffic, but it's included for completeness
    "password": 0.89,
    "scanning": 0.89,
    "xss": 0.86
}


@app.post("/detect-attacks/")
async def detect_attacks(file: UploadFile = File(...)):
    df = pd.read_csv(file.file)
    
    # Preprocess the DataFrame
    df_preprocessed, _ = preprocess_df(df, scaler, is_prediction=True)
    df_aligned = df_preprocessed.reindex(columns=feature_columns, fill_value=0)
    
    # Make predictions
    predictions = rf_classifier.predict(df_aligned)
    df['type'] = predictions
    
    # Iterate over each row to send data for detected attacks
    # for index, row in df.iterrows():
    #     if row['type'] != 'normal':
    #         f1_score = f1_scores.get(row['type'], "N/A")  # Get the F1-score for the attack type
    #         probability = f"{f1_score}%" if f1_score != "N/A" else "N/A"
    #         alert_data = {
    #             "attack": row["type"],
    #             "probability": probability,
    #             "date": row["ts"],
    #             "src_ip": row["src_ip"],
    #         }
    #         # Send the alert data to the specified endpoint
    #         response = requests.post("https://spring2024-alerts.onrender.com/api/alerts", json=alert_data)
    #         # Consider logging the response or handling errors as necessary
            
    # Save the modified DataFrame with predictions to a new CSV file
    modified_csv_path = "modified_with_predictions.csv"
    df.to_csv(modified_csv_path, index=False)
    
    return FileResponse(path=modified_csv_path, filename="modified_with_predictions.csv")
