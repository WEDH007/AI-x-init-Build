import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import RFE
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from joblib import dump
import time

# Function to preprocess the data
def preprocess_df(df):
    # Remove any non-numeric columns that cannot be converted directly to float
    non_numeric_columns = df.select_dtypes(include=['object', 'bool']).columns.tolist()
    df = pd.get_dummies(df, columns=non_numeric_columns, drop_first=True)
    
    # Fill any NaN values in numeric columns
    numeric_cols = df.select_dtypes(include=['float64', 'int64']).columns
    df[numeric_cols] = df[numeric_cols].apply(lambda x: x.fillna(x.median()))
    
    return df

try:
    start_time = time.time()
    print("Starting script execution...")

    # Load the dataset
    print("Loading initial dataset...")
    load_start = time.time()
    df = pd.read_csv('Merged_Network_dataset.csv')
    load_end = time.time()
    print(f"Initial dataset loaded in {load_end - load_start:.2f} seconds.")

    # Preprocess the entire dataset before feature selection and splitting
    df = preprocess_df(df)
    
    # Split data
    y = df['type']
    X = df.drop('type', axis=1)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

    # Initialize and fit RandomForest model for RFE
    print("Fitting model for RFE...")
    rfe_model = RandomForestClassifier(random_state=42)
    rfe = RFE(rfe_model, n_features_to_select=15)  # Adjust the number of features as needed
    rfe.fit(X_train, y_train)

    # Identify features to keep
    features_to_keep = X.columns[rfe.support_]
    print("Selected features:", features_to_keep)

    # Filter datasets to only use selected features
    X_train = X_train[features_to_keep]
    X_test = X_test[features_to_keep]

    # Train final model
    print("Training final model...")
    rf_classifier = RandomForestClassifier(random_state=42)
    rf_classifier.fit(X_train, y_train)

    # Evaluate model
    print("Evaluating model...")
    y_pred = rf_classifier.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred)
    print(f'Testing Accuracy: {accuracy:.2f}')
    print('Classification Report:\\n', report)

    # Save the model and the scaler for future use
    print("Saving model...")
    dump(rf_classifier, 'random_forest_model_rfe.joblib')

    total_end_time = time.time()
    print(f"Total runtime: {total_end_time - start_time:.2f} seconds")
except Exception as e:
    print(f"An error occurred: {e}")
