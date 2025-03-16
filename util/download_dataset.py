import os
from kaggle.api.kaggle_api_extended import KaggleApi
import json

def rename_newest_file(folder_path, new_name):
    files = os.listdir(folder_path)
    full_paths = [os.path.join(folder_path, file) for file in files]
    files = [file for file in full_paths if os.path.isfile(file)]
    files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
    newest_file = files[0]
    new_name = new_name.replace('-', '_')
    os.rename(newest_file, os.path.join(folder_path, new_name))

def download_datasets_from_json(json_file, download_folder):
    api = KaggleApi()
    api.authenticate()

    with open(json_file, 'r') as file:
        datasets = json.load(file)

    # Download each dataset
    for dataset in datasets:
        try:
            print(f"Downloading dataset: {dataset['name']}")

            dataset_name_parts = dataset['name'].split('/')
            dataset_name = dataset_name_parts[-1].strip()

            api.dataset_download_files(dataset['name'], path=download_folder, unzip=True)

            # Rename downloaded files
            rename_newest_file(download_folder, dataset_name + '.csv')

            print(f"Downloaded dataset '{dataset['name']}' successfully.")
        except Exception as e:
            print(f"Failed to download dataset '{dataset['name']}': {e}")

json_file = "dataset_list.json"
download_folder = "datasets"

download_datasets_from_json(json_file, download_folder)
