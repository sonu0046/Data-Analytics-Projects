import pandas as pd

df = pd.read_csv("stock_data.csv")

print("Average Closing Price:", df["Close"].mean())
print("Highest Closing Price:", df["Close"].max())
print("Lowest Closing Price:", df["Close"].min())

print("\nStock Data Summary:")
print(df.describe())
