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
path = '50_both_payload'

with open(path, "rb") as f:
    file_bytes = f.read()

extractor = ember.PEFeatureExtractor()
features = extractor.feature_vector(file_bytes)

# Reshape features to (1, num_features) and set type to float32
data_to_explain = features.reshape(1, -1).astype(np.float32)

# Create a TreeExplainer object
explainer = shap.TreeExplainer(lgbm_model)
shap_values = explainer.shap_values(data_to_explain)

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
    'feature_value': features, 
    'shap_value': sample_shap_values
})

# Add a column for sorting
df['abs_shap_value'] = df['shap_value'].abs()

# Sort by most impactful (highest absolute SHAP value)
df_sorted = df.sort_values(by='abs_shap_value', ascending=False)

output_csv_path = 'test_files/shap_analysis.csv'
df_sorted.to_csv(output_csv_path, index=False)
print(f"Successfully saved to {output_csv_path}")

print("\nTop 10 most impactful features:")
print(df_sorted[['feature_name', 'shap_value']].head(10))


# graph 1

print("\nGenerating SHAP summary bar plot (absolute values)...")
plt.figure()
shap.summary_plot(
    shap_values[0:1, :], 
    data_to_explain, 
    feature_names=feature_names, 
    plot_type="bar", 
    max_display=10,
    show=False
)
plt.xlabel("Mean |SHAP Value| (Absolute Impact)")
plt.xlim(0, 1)
plt.tight_layout()
plt.savefig('test_files/shap_absolute.png', dpi=300, bbox_inches='tight')
#plt.show()

# graph 2
print("\nGenerating SHAP bar plot (positive values only)...")

# Filter only positive SHAP values
positive_mask = sample_shap_values > 0
positive_shap = sample_shap_values[positive_mask]
positive_features = data_to_explain[:, positive_mask]
positive_names = [feature_names[i] for i in range(len(feature_names)) if positive_mask[i]]

# Sort by value and get top 10
if len(positive_shap) > 0:
    top_10_positive_idx = np.argsort(positive_shap)[-10:]
    
    print("\nTop 10 most positive features:")
    for idx in top_10_positive_idx[::-1]:  # Reverse to show highest first
        print(f"{positive_names[idx]}: {positive_shap[idx]:.4f}")

    plt.figure(figsize=(10, 6))
    shap.summary_plot(
        positive_shap[top_10_positive_idx].reshape(1, -1),
        positive_features[:, top_10_positive_idx],
        feature_names=[positive_names[i] for i in top_10_positive_idx],
        plot_type="bar",
        show=False
    )
    plt.xlabel("Mean SHAP Value (Positive Impact)")
    plt.xlim(0, 1)
    plt.tight_layout()
    plt.savefig('test_files/shap_positive.png', dpi=300, bbox_inches='tight')
    #plt.show()
else:
    print("No positive SHAP values found.")

# graph 3

print("\nGenerating SHAP bar plot (negative values only)...")

# Filter only negative SHAP values
negative_mask = sample_shap_values < 0
negative_shap = sample_shap_values[negative_mask]
negative_names = [feature_names[i] for i in range(len(feature_names)) if negative_mask[i]]

# Sort by value (most negative first) and get top 10
if len(negative_shap) > 0:
    # Sort ascending to get most negative values first, then reverse for display
    top_10_negative_idx = np.argsort(negative_shap)[:min(10, len(negative_shap))]
    
    print("\nTop 10 most negative features:")
    for idx in top_10_negative_idx[::]:  # Reverse to show highest first
        print(f"{negative_names[idx]}: {negative_shap[idx]:.4f}")


    top_negative_values = negative_shap[top_10_negative_idx]
    top_negative_names = [negative_names[i] for i in top_10_negative_idx]
    
    # Create custom bar plot
    plt.figure(figsize=(10, 6))
    y_pos = np.arange(len(top_negative_values))
    plt.barh(y_pos, top_negative_values, color='#1E88E5')
    plt.yticks(y_pos, top_negative_names)
    plt.xlabel("Mean SHAP Value (Negative Impact)")
    plt.xlim(0, -1)  # Changed to go from 0 to -1
    plt.gca().invert_yaxis()  # Invert to show most negative at top
    plt.tight_layout()
    plt.savefig('test_files/shap_negative.png', dpi=300, bbox_inches='tight')
    #plt.show()
else:
    print("No negative SHAP values found.")

print("\nAll plots generated successfully!")