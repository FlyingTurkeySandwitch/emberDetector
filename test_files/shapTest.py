import shap
import lightgbm as lgbm
import numpy as np
import ember

import os
import pandas as pd 
import matplotlib.pyplot as plt 
from ember import features as ember_features

# Load EMBER
model_file_path='data/ember2018/ember_model_2018.txt'
lgbm_model = lgbm.Booster(model_file=model_file_path)


path = 'WhoIs/whois64.exe'

with open(path, "rb") as f:
    file_bytes = f.read()

extractor = ember.PEFeatureExtractor()

features = extractor.feature_vector(file_bytes)


# Reshape features to (1, num_features) and set type to float32
data_to_explain = features.reshape(1, -1).astype(np.float32)
 
 #  Create a TreeExplainer object
explainer = shap.TreeExplainer(lgbm_model)
shap_values = explainer.shap_values(data_to_explain)
#print first 10
# print(shap_values[0, :10])

#==========================================
# Get the SHAP values for the one sample
sample_shap_values = shap_values[0, :]

# Get the absolute (positive) impact
abs_shap_values = np.abs(sample_shap_values)

# Get the indices of the top 10 features
top_10_indices = np.argsort(abs_shap_values)[-10:]

print("Top 10 feature :", top_10_indices)
print("SHAP values:", sample_shap_values[top_10_indices])
#==========================================

sample_shap_values = shap_values[0, :] 

#feature_names = ember.LGBM_FEATURE_NAMES 
#feature_names = ember_features.LGBM_FEATURE_NAMES

feature_names = []
# --- Replace your old loop with this new one ---
print("Building feature names list...")
feature_names = []
for feature_obj in extractor.features:
    if hasattr(feature_obj, 'names'):
        # This is for objects like SectionInfo that have a .names list
        feature_names.extend(feature_obj.names)
    else:
        # This is for objects like ByteHistogram
        # It builds names like "ByteHistogram.0", "ByteHistogram.1", ...
        for i in range(feature_obj.dim):
            feature_names.append(f"{feature_obj.name}.{i}")

print(f"Feature names list built. Total names: {len(feature_names)}")
# -----------------------------------------------


# Create a Pandas DataFrame to hold everything
df = pd.DataFrame({
    'feature_name': feature_names,
    'feature_value': features, # The actual value from whois64.exe
    'shap_value': sample_shap_values
})

# Add a column for sorting
df['abs_shap_value'] = df['shap_value'].abs()

# Sort by most impactful (highest absolute SHAP value)
df_sorted = df.sort_values(by='abs_shap_value', ascending=False)

# Save to a CSV file in your test_files folder
output_csv_path = 'test_files/shap_analysis.csv'
df_sorted.to_csv(output_csv_path, index=False)

print(f"Successfully saved to {output_csv_path}")
print("\nTop 10 most impactful features for 'whois64.exe':")
print(df_sorted[['feature_name', 'shap_value']].head(10))

# --- 8. (NEW) Visualize the Top Features ---
print("\nGenerating SHAP summary bar plot...")

# We use shap_values[0:1,:] to keep the 2D shape SHAP expects
# We use data_to_explain for the feature values
shap.summary_plot(
    shap_values[0:1, :], 
    data_to_explain, 
    feature_names=feature_names, 
    plot_type="bar", 
    max_display=30 # Show the top 30
)