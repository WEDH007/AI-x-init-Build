import pandas as pd

def remove_specific_rows(input_csv_path, output_csv_path, types_to_remove):
    """
    Removes rows with specified types from a CSV file and saves the result to a new CSV file.

    Parameters:
    - input_csv_path: str. The path to the input CSV file.
    - output_csv_path: str. The path where the modified CSV file will be saved.
    - types_to_remove: list of str. Types of rows to remove.
    """
    # Load the CSV file into a DataFrame
    df = pd.read_csv(input_csv_path)
    
    # Remove rows where the 'type' column matches any of the specified types
    df_filtered = df[~df['type'].isin(types_to_remove)]
    
    # Save the filtered DataFrame to a new CSV file
    df_filtered.to_csv(output_csv_path, index=False)

# Specify the path to the uploaded file and the output file name
input_csv_path = 'train_test_network.csv'
output_csv_path = 'test_network.csv'

# Types of rows to remove
types_to_remove = ['backdoor', 'mitm', 'ransomware']

# Execute the function
remove_specific_rows(input_csv_path, output_csv_path, types_to_remove)

print(f"Filtered CSV saved to {output_csv_path}")
