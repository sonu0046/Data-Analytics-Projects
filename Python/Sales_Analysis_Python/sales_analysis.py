import pandas as pd

df = pd.read_csv("sales_data.csv")

print("Total Sales:", df["Sales"].sum())

print("\nTop Products:")
print(df.groupby("Product")["Sales"].sum().sort_values(ascending=False))
