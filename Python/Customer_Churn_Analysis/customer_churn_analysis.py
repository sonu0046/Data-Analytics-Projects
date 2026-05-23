import pandas as pd

df = pd.read_csv("customer_data.csv")

print("Total Customers:", len(df))
print("Average Monthly Charges:", df["MonthlyCharges"].mean())
print("Churn Count:")
print(df["Churn"].value_counts())
