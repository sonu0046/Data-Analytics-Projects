import pandas as pd

df = pd.read_csv("employee_data.csv")

print("Average Salary:", df["Salary"].mean())
print("Highest Salary:", df["Salary"].max())

dept_salary = df.groupby("Department")["Salary"].mean()
print("\nDepartment-wise Average Salary:")
print(dept_salary)

print("\nTotal Employees:", len(df))
