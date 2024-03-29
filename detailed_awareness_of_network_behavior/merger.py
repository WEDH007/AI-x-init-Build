import pandas as pd
from multiprocessing import Pool, cpu_count
import os

def read_csv(file_name):
    """
    Reads a CSV file into a DataFrame. Designed to be called in parallel.

    :param file_name: The name of the CSV file to read.
    :return: A DataFrame containing the data from the CSV file.
    """
    try:
        df = pd.read_csv(file_name)
        print(f"Successfully read {file_name}")
    except FileNotFoundError:
        print(f"File not found: {file_name}")
        return None
    return df

def merge_csv_files(dataset_numbers, output_file="Merged_Network_Dataset.csv"):
    """
    Merges specified CSV files into one, using multiprocessing to improve performance.

    :param dataset_numbers: A list of integers representing the dataset numbers to merge.
    :param output_file: The name of the output file.
    """
    base_filename = "Network_dataset_{}.csv"
    file_names = [base_filename.format(number) for number in dataset_numbers]

    with Pool(processes=cpu_count()) as pool:
        dataframes = pool.map(read_csv, file_names)

    # Filter out any None values returned by read_csv in case of file not found
    dataframes = [df for df in dataframes if df is not None]

    if dataframes:
        merged_df = pd.concat(dataframes, ignore_index=True)
        merged_df.to_csv(output_file, index=False)
        print(f"Datasets merged successfully into {output_file}")
    else:
        print("No datasets were merged.")

if __name__ == "__main__":
    dataset_numbers = [2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]  # Example set of dataset numbers to merge
    merge_csv_files(dataset_numbers)
