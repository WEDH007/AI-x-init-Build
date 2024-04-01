import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from joblib import load
import time

def preprocess_df(df, scaler=None, is_prediction=False):
    features_to_drop = ['src_ip', 'dst_ip', 'src_port', 'service', 'dst_port', 'ssl_version', 'ssl_cipher', 'ssl_subject', 'ssl_issuer', 'dns_query', 'dns_qclass', 'dns_qtype', 'dns_rcode', 'http_request_body_len', 'http_version', 'http_trans_depth', 'http_method', 'http_uri', 'http_response_body_len', 'http_status_code', 'http_user_agent', 'http_orig_mime_types', 'http_resp_mime_types', 'weird_name', 'weird_addl', 'weird_notice']
    
    if 'ts' in df.columns:
        features_to_drop.append('ts')
    
    df = df.drop(columns=features_to_drop, errors='ignore')  # Use errors='ignore' to ignore missing columns
    
    categorical_cols = df.select_dtypes(include=['object', 'bool']).columns.tolist()
    
    if is_prediction:
        # If 'type' column exists and it's a prediction scenario, we won't remove it but ensure it's not treated as a feature
        if 'type' in categorical_cols:
            categorical_cols.remove('type')
    else:
        # For training or evaluation, ensure 'type' column is removed from features but preserved in DataFrame if necessary
        if 'type' in df.columns:
            df['label'] = df['type']  # Optionally preserve 'type' information if needed
            df = df.drop(columns=['type'])
    
    numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
    df[numeric_cols] = df[numeric_cols].apply(lambda x: x.fillna(x.median()))
    df[categorical_cols] = df[categorical_cols].apply(lambda x: x.fillna(x.mode()[0]))
    df = pd.get_dummies(df, columns=categorical_cols, drop_first=True)
    
    if scaler is None:
        scaler = StandardScaler()
        df[numeric_cols] = scaler.fit_transform(df[numeric_cols])
    else:
        df[numeric_cols] = scaler.transform(df[numeric_cols])
    
    return df, scaler


try:
    start_time = time.time()
    print("Loading model and scaler...")
    rf_classifier = load('random_forest_model.joblib')
    scaler = load('scaler.joblib')
    feature_columns = load('feature_columns.joblib')

    print("Loading and preprocessing new dataset...")
    file_path = 'test_network.csv'  # Update with your CSV file path
    new_data = pd.read_csv(file_path)
    # Temporarily save the true labels for classification report
    true_labels = new_data['type'].copy()
    new_data_preprocessed, _ = preprocess_df(new_data, scaler, is_prediction=True)

    # Align features for prediction
    new_data_aligned = new_data_preprocessed.reindex(columns=feature_columns, fill_value=0)

    print("Predicting...")
    predictions = rf_classifier.predict(new_data_aligned)

    print("Generating classification report...")
    report = classification_report(true_labels, predictions)
    print(report)

    # Optionally, save the predictions
    new_data['predictions'] = predictions
    new_data.to_csv('predictions_with_report.csv', index=False)
    print("Predictions and classification report saved.")

    end_time = time.time()
    print(f"Total runtime: {end_time - start_time:.2f} seconds")
except Exception as e:
    print(f"An error occurred: {e}")
