CREATE TABLE sales (
    id INT,
    product_name VARCHAR(50),
    amount INT
);

SELECT product_name,
SUM(amount) AS total_sales
FROM sales
GROUP BY product_name;
