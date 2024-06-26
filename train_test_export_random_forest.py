import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler
from joblib import dump
import time

# Define the preprocess_df function
def preprocess_df(df, scaler=None):
    features_to_drop = ['src_ip', 'dst_ip', 'src_port', 'service', 'dst_port', 'ssl_version', 'ssl_cipher', 'ssl_subject', 'ssl_issuer', 'dns_query', 'dns_qclass', 'dns_qtype', 'dns_rcode', 'http_request_body_len', 'http_version', 'http_trans_depth', 'http_method', 'http_uri', 'http_response_body_len', 'http_status_code', 'http_user_agent', 'http_orig_mime_types', 'http_resp_mime_types', 'weird_name', 'weird_addl', 'weird_notice', 'label']
    if 'ts' in df.columns:
        features_to_drop.append('ts')
    df = df.drop(columns=features_to_drop)
    categorical_cols = df.select_dtypes(include=['object', 'bool']).columns.tolist()
    categorical_cols.remove('type')
    numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
    df[numeric_cols] = df[numeric_cols].apply(lambda x: x.fillna(x.median()))
    df[categorical_cols] = df[categorical_cols].apply(lambda x: x.fillna(x.mode()[0]))
    df = pd.get_dummies(df, columns=categorical_cols)
    
    if scaler is None:
        scaler = StandardScaler()
        df[numeric_cols] = scaler.fit_transform(df[numeric_cols])
    else:
        df[numeric_cols] = scaler.transform(df[numeric_cols])
        
    return df, scaler


try:
    start_time = time.time()
    print("Starting script execution...")

    # Load the dataset
    print("Loading initial dataset...")
    load_start = time.time()
    df = pd.read_csv('Merged_Network_dataset.csv')
    load_end = time.time()
    print(f"Initial dataset loaded in {load_end - load_start:.2f} seconds.")

    # Preprocess the data using the preprocess_df function
    print("Preprocessing initial data...")
    preprocess_start = time.time()
    df, scaler = preprocess_df(df)
    preprocess_end = time.time()
    print(f"Initial data preprocessed in {preprocess_end - preprocess_start:.2f} seconds.")

    # Split the dataset into training and testing sets
    print("Splitting dataset...")
    split_start = time.time()
    X = df.drop('type', axis=1)
    y = df['type']
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    split_end = time.time()
    print(f"Dataset split in {split_end - split_start:.2f} seconds.")

    # Train the Random Forest model
    print("Training model...")
    training_start = time.time()
    rf_classifier = RandomForestClassifier(n_estimators=5, criterion='entropy', random_state=42)
    # Save the column names of the processed training dataset
    feature_columns = X_train.columns
    dump(feature_columns, 'feature_columns.joblib')  # Save the feature names for later use
    rf_classifier.fit(X_train, y_train)
    training_end = time.time()
    print(f"Model trained in {training_end - training_start:.2f} seconds.")

    # Evaluate the model on the testing set
    print("Evaluating model on initial test data...")
    testing_start = time.time()
    y_pred = rf_classifier.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)
    testing_end = time.time()
    print(f"Model evaluated on initial test data in {testing_end - testing_start:.2f} seconds.")
    print(f'Initial Testing Accuracy: {accuracy:.2f}')
    print('Classification Report for initial test data:\n', report)

    # Save the model and the scaler for future use
    print("Saving model and scaler...")
    save_start = time.time()
    dump(rf_classifier, 'random_forest_model.joblib')
    dump(scaler, 'scaler.joblib')
    save_end = time.time()
    print(f"Model and scaler saved in {save_end - save_start:.2f} seconds.")

    # Load, preprocess, and test on new dataset
    print("Loading, preprocessing, and testing on new dataset...")
    new_load_start = time.time()
    new_data = pd.read_csv('test_network.csv')
    new_data, _ = preprocess_df(new_data, scaler)
    new_X = new_data.drop('type', axis=1).reindex(columns=X.columns, fill_value=0)
    new_y = new_data['type']
    new_load_end = time.time()
    print(f"New dataset loaded and preprocessed in {new_load_end - new_load_start:.2f} seconds.")

    # Predict and evaluate on the new dataset
    new_testing_start = time.time()
    new_y_pred = rf_classifier.predict(new_X)
    new_accuracy = accuracy_score(new_y, new_y_pred)
    new_report = classification_report(new_y, new_y_pred)
    new_testing_end = time.time()
    print(f"Testing on new data completed in {new_testing_end - new_testing_start:.2f} seconds.")
    print(f'Testing Accuracy of the Random Forest model on the new data: {new_accuracy:.2f}')
    print('Classification Report for the new dataset:\n', new_report)

    total_end_time = time.time()
    print(f"Total runtime: {total_end_time - start_time:.2f} seconds")
except Exception as e:
    print(f"An error occurred: {e}")
