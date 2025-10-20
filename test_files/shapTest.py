import shap
import lightgbm as lgbm
import numpy as np

# 1. Load your pre-trained EMBER LightGBM model
lgbm_model = lgbm.Booster(model_file='ember/ember_model_2018.txt')

# 2. Create a TreeExplainer object
explainer = shap.TreeExplainer(lgbm_model)

# 4. Calculate the SHAP values for feature
for i in range (2381):
    shap_values = explainer.shap_values(i)
    print(f"feature number:{i} SHAP values: {shap_values.shape}")

 