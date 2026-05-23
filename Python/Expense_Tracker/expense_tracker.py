import pandas as pd

df = pd.read_csv("expense_data.csv")

print("Total Expense:", df["Amount"].sum())

print("\nExpense by Category:")
print(df.groupby("Category")["Amount"].sum())

print("\nHighest Expense:")
print(df.loc[df["Amount"].idxmax()])
