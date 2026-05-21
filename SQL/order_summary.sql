SELECT order_date,
SUM(amount) AS total_amount
FROM orders
GROUP BY order_date
ORDER BY order_date;
