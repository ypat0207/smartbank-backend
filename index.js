const express = require("express");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
});

// Middleware to authenticate JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// Register
app.post("/api/auth/register", async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id",
      [username, email, hashedPassword]
    );
    res
      .status(201)
      .json({ message: "User registered", userId: result.rows[0].id });
  } catch (err) {
    res
      .status(400)
      .json({ message: "Error registering user", error: err.message });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ token, username: user.username });
  } catch (err) {
    res.status(500).json({ message: "Error logging in", error: err.message });
  }
});

// Get Transactions
app.get("/api/transactions", authenticateToken, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM transactions WHERE user_id = $1 ORDER BY date DESC",
    [req.user.id]
  );
  res.json(result.rows);
});

// Add Transaction (Auto-update budget if expense)
app.post("/api/transactions", authenticateToken, async (req, res) => {
  const { amount, category, type, description } = req.body;
  const currentMonth = new Date().toISOString().slice(0, 7); // e.g., '2025-02'
  try {
    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      const transResult = await client.query(
        "INSERT INTO transactions (user_id, amount, category, type, description) VALUES ($1, $2, $3, $4, $5) RETURNING *",
        [req.user.id, amount, category, type, description]
      );
      if (type === "expense") {
        await client.query(
          "INSERT INTO budgets (user_id, budget_amount, current_spent, month) VALUES ($1, 0, $2, $3) " +
            "ON CONFLICT (user_id, month) DO UPDATE SET current_spent = budgets.current_spent + $2",
          [req.user.id, amount, currentMonth]
        );
      }
      await client.query("COMMIT");
      res
        .status(201)
        .json({
          message: "Transaction added",
          transaction: transResult.rows[0],
        });
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  } catch (err) {
    res
      .status(400)
      .json({ message: "Error adding transaction", error: err.message });
  }
});

// Get Current Budget
app.get("/api/budget", authenticateToken, async (req, res) => {
  const currentMonth = new Date().toISOString().slice(0, 7);
  const result = await pool.query(
    "SELECT * FROM budgets WHERE user_id = $1 AND month = $2",
    [req.user.id, currentMonth]
  );
  res.json(
    result.rows[0] || {
      budget_amount: 0,
      current_spent: 0,
      month: currentMonth,
    }
  );
});

// Set/Update Budget
app.post("/api/budget", authenticateToken, async (req, res) => {
  const { budget_amount } = req.body;
  const currentMonth = new Date().toISOString().slice(0, 7);
  try {
    const result = await pool.query(
      "INSERT INTO budgets (user_id, budget_amount, month) VALUES ($1, $2, $3) " +
        "ON CONFLICT (user_id, month) DO UPDATE SET budget_amount = $2 RETURNING *",
      [req.user.id, budget_amount, currentMonth]
    );
    res.status(201).json({ message: "Budget set", budget: result.rows[0] });
  } catch (err) {
    console.log("Budget error:", err.message);
    res
      .status(400)
      .json({ message: "Error setting budget", error: err.message });
  }
});

// Get Insights (Income vs. Spending)
app.get("/api/insights", authenticateToken, async (req, res) => {
  const currentMonth = new Date().toISOString().slice(0, 7);
  const monthStart = `${currentMonth}-01`;
  const monthEnd = new Date(
    new Date(monthStart).setMonth(new Date(monthStart).getMonth() + 1)
  )
    .toISOString()
    .slice(0, 10);
  const income = await pool.query(
    "SELECT SUM(amount) FROM transactions WHERE user_id = $1 AND type = $2 AND date >= $3 AND date < $4",
    [req.user.id, "income", monthStart, monthEnd]
  );
  const expenses = await pool.query(
    "SELECT SUM(amount) FROM transactions WHERE user_id = $1 AND type = $2 AND date >= $3 AND date < $4",
    [req.user.id, "expense", monthStart, monthEnd]
  );
  res.json({
    totalIncome: income.rows[0].sum || 0,
    totalExpenses: expenses.rows[0].sum || 0,
  });
});

app.listen(process.env.PORT, () =>
  console.log(`Server running on port ${process.env.PORT}`)
);
