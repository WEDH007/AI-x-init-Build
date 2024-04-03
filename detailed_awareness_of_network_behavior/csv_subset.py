import pandas as pd

def create_random_subset_without_column(input_csv_path, output_csv_path, percentage, column_to_remove):
    """
    Creates a random subset of a given CSV file and removes a specified column.
    This version allows for a subset size less than 1%.

    Parameters:
    - input_csv_path: str. The path to the input CSV file.
    - output_csv_path: str. The path where the subset CSV file will be saved.
    - percentage: float. The percentage of the original file to keep. Can be less than 1.
    - column_to_remove: str. The name of the column to remove from the DataFrame.
    """
    # Load the original CSV file
    df = pd.read_csv(input_csv_path)
    
    # Remove the specified column
    if column_to_remove in df.columns:
        df = df.drop(columns=[column_to_remove])
    
    # Calculate the number of rows to select based on the given percentage
    # Use round to ensure at least one row is selected for percentages less than 1
    subset_size = round(len(df) * (percentage / 100))
    subset_size = max(1, subset_size)  # Ensure at least one row is selected
    
    # If subset_size is larger than the DataFrame, sample the entire DataFrame without replacement
    if subset_size >= len(df):
        df_subset = df
    else:
        # Shuffle the DataFrame rows and select a subset
        df_subset = df.sample(n=subset_size).reset_index(drop=True)
    
    # Save the subset to a new CSV file
    df_subset.to_csv(output_csv_path, index=False)

# Example usage
input_csv_path = 'Network_dataset_10.csv'
output_csv_path = 'subset_10.csv'
percentage = 0.01  # Example: 0.1% of the original data
column_to_remove = 'type'  # Specify the column you want to remove

create_random_subset_without_column(input_csv_path, output_csv_path, percentage, column_to_remove)
