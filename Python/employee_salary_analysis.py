employees = {
    "John": 35000,
    "Riya": 42000,
    "Vikas": 38000,
    "Anita": 50000
}

average_salary = sum(employees.values()) / len(employees)

print("Average Salary:", average_salary)

for name, salary in employees.items():
    if salary > average_salary:
        print(name, "is above average")
