-- Total Sales
SELECT SUM(SalesAmount) AS TotalSales
FROM Sales;

-- Monthly Sales
SELECT Month, SUM(SalesAmount) AS MonthlySales
FROM Sales
GROUP BY Month
ORDER BY Month;

-- Top Products
SELECT ProductName, SUM(SalesAmount) AS TotalSales
FROM Sales
GROUP BY ProductName
ORDER BY TotalSales DESC;

-- Top Customers
SELECT CustomerName, SUM(SalesAmount) AS TotalSales
FROM Sales
GROUP BY CustomerName
ORDER BY TotalSales DESC;
