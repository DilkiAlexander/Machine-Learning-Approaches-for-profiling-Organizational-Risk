import pandas as pd
import os

# List of TSV files to shuffle and combine
tsv_files = [
    r'C:\predict-network-anomaly-new\predict-network-anomaly\1-training\SYN_ACK_FLOOD\Datasets\normal_data_1.tsv',
    r'C:\predict-network-anomaly-new\predict-network-anomaly\1-training\SYN_ACK_FLOOD\Datasets\normal_data_2.tsv',
    r'C:\predict-network-anomaly-new\predict-network-anomaly\1-training\SYN_ACK_FLOOD\Datasets\normal_data_3.tsv',
    r'C:\predict-network-anomaly-new\predict-network-anomaly\1-training\SYN_ACK_FLOOD\Datasets\SYN_Flood_data.tsv',
    r'C:\predict-network-anomaly-new\predict-network-anomaly\1-training\SYN_ACK_FLOOD\Datasets\ACK_Flood_data.tsv'
]

# Load and shuffle each TSV file, skipping missing files
shuffled_dfs = []
for file_path in tsv_files:
    if os.path.isfile(file_path):
        df = pd.read_csv(file_path, sep='\t')
        df_shuffled = df.sample(frac=1).reset_index(drop=True)
        shuffled_dfs.append(df_shuffled)
    else:
        print(f"File not found, skipping: {file_path}")

# Combine all shuffled dataframes into one
if shuffled_dfs:
    combined_df = pd.concat(shuffled_dfs).sample(frac=1).reset_index(drop=True)

    # Save the combined shuffled dataset to a new TSV file
    output_file_path = r'C:\predict-network-anomaly-new\predict-network-anomaly\1-training\SYN_ACK_FLOOD\Datasets\combined_shuffled_data.tsv'
    combined_df.to_csv(output_file_path, sep='\t', index=False)

    print(f'Combined shuffled dataset saved to {output_file_path}')
else:
    print("No files were processed.")
