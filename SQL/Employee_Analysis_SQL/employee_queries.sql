SELECT COUNT(*) AS Total_Employees
FROM employees;

SELECT Department, AVG(Salary) AS Avg_Salary
FROM employees
GROUP BY Department;

SELECT *
FROM employees
ORDER BY Performance DESC;

SELECT Department, COUNT(*) AS Employee_Count
FROM employees
GROUP BY Department;
