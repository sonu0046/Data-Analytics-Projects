import pandas as pd

df = pd.read_csv("netflix_data.csv")

print("Total Titles:", len(df))
print("\nContent Type Count:")
print(df["Type"].value_counts())

print("\nGenre Count:")
print(df["Genre"].value_counts())
