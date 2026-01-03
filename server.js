const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// =====================
// MIDDLEWARE
// =====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (HTML, CSS, JS)
app.use(express.static(path.join(__dirname, "public")));

// =====================
// IN-MEMORY DATA (TEMP)
// =====================
// NOTE: Later you can replace this with a database
const users = []; 
// user object example:
// {
//   username,
//   passwordHash,
//   role: "student" | "admin",
//   approved: true | false
// }

// =====================
// ROUTES
// =====================

// ✅ HOME → LOGIN PAGE
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

// =====================
// AUTH ROUTES
// =====================

// 🔐 REGISTER (PENDING APPROVAL)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Missing fields" });
  }

  const existingUser = users.find(u => u.username === username);
  if (existingUser) {
    return res.status(400).json({ message: "Username already exists" });
  }

  const passwordHash = await bcrypt.hash(password, 10);

  users.push({
    username,
    passwordHash,
    role: "student",
    approved: false
  });

  res.json({ message: "Registered successfully. Await admin approval." });
});

// 🔐 LOGIN
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  if (!user.approved) {
    return res.status(403).json({ message: "Account not approved yet" });
  }

  const validPassword = await bcrypt.compare(password, user.passwordHash);
  if (!validPassword) {
    return res.status(401).json({ message: "Invalid credentials" });
  }

  // Simple redirect logic
  if (user.role === "admin") {
    res.json({ redirect: "/admin.html" });
  } else {
    res.json({ redirect: "/student.html" });
  }
});

// =====================
// ADMIN ROUTES
// =====================

// 👮 APPROVE USER
app.post("/admin/approve", (req, res) => {
  const { username } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) {
    return res.status(404).json({ message: "User not found" });
  }

  user.approved = true;
  res.json({ message: "User approved" });
});

// 👮 VIEW USERS (ADMIN)
app.get("/admin/users", (req, res) => {
  res.json(users.map(u => ({
    username: u.username,
    role: u.role,
    approved: u.approved
  })));
});

// =====================
// SERVER START
// =====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
