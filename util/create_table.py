import pandas as pd
from sqlalchemy import create_engine, text
import configparser
import json

# Read dataset names and paths from JSON file
with open('dataset_list.json', 'r') as file:
    datasets = json.load(file)

config = configparser.ConfigParser()
config.read('config.ini')

database_url = f"postgresql://{config['Database']['Username']}:{config['Database']['Password']}@{config['Database']['Host']}/{config['Database']['Database']}"
engine = create_engine(database_url)


for dataset in datasets:
    dataset_name_parts = dataset['name'].split('/')
    dataset_name = dataset_name_parts[-1].strip().replace('-', '_')
    
    # Read the CSV file corresponding to the dataset
    file_path = f'datasets/{dataset_name}.csv'
    data = pd.read_csv(file_path)
    
    # Initialize the list of columns to keep with the primary attribute
    columns_to_keep = [dataset['primary_attribute']] if dataset['primary_attribute'] in data.columns else []
    
    # Add other attributes if they exist and are present in the data columns
    if 'other_attributes' in dataset:
        for attr in dataset['other_attributes']:
            if attr['attribute_name'] in data.columns:
                columns_to_keep.append(attr['attribute_name'])
            else:
                print(f"Warning: Column '{attr['attribute_name']}' not found in {dataset_name}.csv")

    # Check if there are any columns to keep, if not, skip to the next dataset
    if not columns_to_keep:
        print(f"No valid columns to keep for {dataset_name}. Skipping dataset.")
        continue

    filtered_data = data[columns_to_keep]
    
    # Create table from filtered CSV data
    filtered_data.to_sql(dataset_name, engine, if_exists='replace', index=False)
    print(f"Created table: {dataset_name}")

    new_table_name = dataset_name + '_user'
    # Adjust columns to include a 'userid' column
    user_columns = columns_to_keep + ['userid']
    empty_df = pd.DataFrame(columns=user_columns)
    try:
        empty_df.to_sql(new_table_name, engine, if_exists='fail', index=False)

        sql = text(f"ALTER TABLE {new_table_name} ADD CONSTRAINT {new_table_name+"_unique_userid"} UNIQUE (userid)") 
        with engine.connect() as con:
            con.execute(sql)
            con.commit()
        print(f"Created table: {new_table_name}")
    except ValueError as e:
        pass
