-- Total Customers
SELECT COUNT(DISTINCT CustomerName) AS TotalCustomers
FROM Customers;

-- Top Spending Customers
SELECT CustomerName, SUM(PurchaseAmount) AS TotalSpent
FROM Customers
GROUP BY CustomerName
ORDER BY TotalSpent DESC;

-- Average Purchase Amount
SELECT AVG(PurchaseAmount) AS AvgPurchase
FROM Customers;

-- Customer-wise Revenue
SELECT CustomerName, SUM(PurchaseAmount) AS Revenue
FROM Customers
GROUP BY CustomerName;
