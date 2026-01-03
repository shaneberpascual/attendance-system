const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const app = express();

app.use(express.json());
app.use(express.static("public"));

const SECRET = "attendance-secret";

// ======================
// DATABASE (IN-MEMORY)
// ======================
let users = [
  {
    id: 1,
    username: "admin",
    password: "$2b$10$8KpE6sZ8hVt3vYk7yq2FqOSk3L9a1sZJcYxXb8p1w2f9nQ7Y0Z2", 
    role: "admin",
    approved: true
  }
];

let pendingUsers = [];
let attendanceRecords = [];

// ======================
// MIDDLEWARE
// ======================
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.sendStatus(403);
  next();
}

// ======================
// REGISTER (PENDING)
// ======================
app.post("/api/register", async (req, res) => {
  const { username, password, department, quarter } = req.body;

  if (
    users.some(u => u.username === username) ||
    pendingUsers.some(u => u.username === username)
  ) {
    return res.json({ message: "Username already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  pendingUsers.push({
    id: Date.now(),
    username,
    password: hashedPassword,
    department,
    quarter,
    role: "student",
    approved: false
  });

  res.json({ message: "Registration submitted. Await admin approval." });
});

// ======================
// LOGIN
// ======================
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ message: "Invalid login" });

  if (!user.approved)
    return res.status(403).json({ message: "Account not approved yet" });

  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.status(401).json({ message: "Invalid login" });

  const token = jwt.sign(user, SECRET, { expiresIn: "8h" });
  res.json({ token, role: user.role });
});

// ======================
// ADMIN – VIEW PENDING
// ======================
app.get("/api/admin/pending", authenticate, adminOnly, (req, res) => {
  res.json(pendingUsers);
});

// ======================
// ADMIN – APPROVE USER
// ======================
app.post("/api/admin/approve/:id", authenticate, adminOnly, (req, res) => {
  const index = pendingUsers.findIndex(u => u.id == req.params.id);
  if (index === -1) return res.sendStatus(404);

  const user = pendingUsers.splice(index, 1)[0];
  user.approved = true;
  users.push(user);

  res.json({ message: "User approved successfully" });
});

// ======================
// ADMIN – RESET PASSWORD
// ======================
app.post("/api/admin/reset-password/:id", authenticate, adminOnly, async (req, res) => {
  const { newPassword } = req.body;

  const user = users.find(u => u.id == req.params.id);
  if (!user) return res.sendStatus(404);

  user.password = await bcrypt.hash(newPassword, 10);
  res.json({ message: "Password reset successfully" });
});

// ======================
// CHANGE PASSWORD (USER)
// ======================
app.post("/api/change-password", authenticate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.sendStatus(404);

  const match = await bcrypt.compare(currentPassword, user.password);
  if (!match)
    return res.status(400).json({ message: "Current password incorrect" });

  user.password = await bcrypt.hash(newPassword, 10);
  res.json({ message: "Password updated successfully" });
});

// ======================
// TIME IN
// ======================
app.post("/api/attendance", authenticate, (req, res) => {
  const today = new Date().toDateString();

  if (attendanceRecords.some(r => r.userId === req.user.id && r.date === today)) {
    return res.json({ message: "Already timed in today" });
  }

  attendanceRecords.push({
    userId: req.user.id,
    username: req.user.username,
    department: req.user.department,
    quarter: req.user.quarter,
    date: today,
    time: new Date().toLocaleTimeString()
  });

  res.json({ message: "Time In recorded successfully" });
});

// ======================
// STUDENT STATUS
// ======================
app.get("/api/my-attendance-status", authenticate, (req, res) => {
  const today = new Date().toDateString();
  const alreadyTimedIn = attendanceRecords.some(
    r => r.userId === req.user.id && r.date === today
  );
  res.json({ alreadyTimedIn });
});

// ======================
// STUDENT HISTORY
// ======================
app.get("/api/my-attendance", authenticate, (req, res) => {
  res.json(attendanceRecords.filter(r => r.userId === req.user.id));
});

// ======================
// START SERVER
// ======================
app.listen(3000, () => {
  console.log("Server running on http://localhost:3000");
});
