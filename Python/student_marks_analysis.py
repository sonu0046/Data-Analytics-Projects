students = {
    "Rahul": 85,
    "Priya": 92,
    "Amit": 78,
    "Sneha": 88,
    "Ravi": 95
}

average = sum(students.values()) / len(students)

top_student = max(students, key=students.get)

print("Average Marks:", average)
print("Top Student:", top_student)
