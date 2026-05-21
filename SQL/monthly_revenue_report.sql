SELECT month,
SUM(revenue) AS total_revenue
FROM revenue_data
GROUP BY month
ORDER BY total_revenue DESC;
