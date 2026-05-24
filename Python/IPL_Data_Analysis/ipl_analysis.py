import pandas as pd

df = pd.read_csv("ipl_data.csv")

print("Total Matches:", len(df))
print("\nWinning Teams:")
print(df["Winner"].value_counts())

print("\nAverage Runs:")
print(df["Runs"].mean())
