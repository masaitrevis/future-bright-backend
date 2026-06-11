require("dotenv").config();
const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const { v4: uuidv4 } = require("uuid");
const axios = require("axios");
const multer = require("multer");

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || "fbv-secret-key-2024";

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Ensure upload directories exist
const uploadsDir = path.join(__dirname, "uploads");
const coversDir = path.join(uploadsDir, "covers");
const booksDir = path.join(uploadsDir, "books");

[uploadsDir, coversDir, booksDir].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Serve static files (covers and downloads)
app.use("/uploads", express.static(uploadsDir));

// Database setup
const dbPath = path.join(__dirname, "db", "database.sqlite");
const dbDir = path.join(__dirname, "db");
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error("Database connection error:", err);
  } else {
    console.log("Connected to SQLite database");
    initializeDatabase();
  }
});

function initializeDatabase() {
  db.serialize(() => {
    // Products table
    db.run(`
      CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        author TEXT,
        description TEXT,
        price INTEGER NOT NULL,
        cover_image TEXT,
        file_path TEXT,
        category TEXT DEFAULT 'service',
        status TEXT DEFAULT 'active',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Orders table
    db.run(`
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        phone_number TEXT NOT NULL,
        mpesa_receipt TEXT,
        checkout_request_id TEXT,
        amount INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        download_token TEXT,
        download_expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id)
      )
    `);

    // Admin users table - with callback to ensure admin is created AFTER table exists
    db.run(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `, [], function(err) {
      if (err) {
        console.error("Error creating admin_users table:", err);
        return;
      }
      // Now safe to check/insert admin user
      db.get("SELECT * FROM admin_users WHERE username = ?", ["admin"], (err, row) => {
        if (err) {
          console.error("Error checking admin user:", err);
          return;
        }
        if (!row) {
          const defaultPassword = bcrypt.hashSync("admin123", 10);
          db.run(
            "INSERT INTO admin_users (username, password) VALUES (?, ?)",
            ["admin", defaultPassword],
            (err) => {
              if (err) console.error("Error creating admin user:", err);
              else console.log("Admin user created: admin / admin123");
            }
          );
        } else {
          console.log("Admin user already exists");
        }
      });
    });
  });
}

// Multer configuration for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === "cover") cb(null, coversDir);
    else if (file.fieldname === "book") cb(null, booksDir);
    else cb(null, uploadsDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}-${file.originalname}`;
    cb(null, uniqueName);
  },
});

const upload = multer({ storage });

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
};

// ============ AUTH ROUTES ============

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    "SELECT * FROM admin_users WHERE username = ?",
    [username],
    (err, user) => {
      if (err || !user) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const validPassword = bcrypt.compareSync(password, user.password);
      if (!validPassword) {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: "24h" }
      );

      res.json({ token, username: user.username });
    }
  );
});

// ============ PRODUCT ROUTES ============

// Get all products
app.get("/api/products", (req, res) => {
  db.all(
    "SELECT * FROM products WHERE status = 'active' ORDER BY created_at DESC",
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// Get single product
app.get("/api/products/:id", (req, res) => {
  db.get("SELECT * FROM products WHERE id = ?", [req.params.id], (err, row) => {
    if (err) return res.status(500).json({ error: err.message });
    if (!row) return res.status(404).json({ error: "Product not found" });
    res.json(row);
  });
});

// Create product (admin only)
app.post(
  "/api/products",
  authenticateToken,
  upload.fields([
    { name: "cover", maxCount: 1 },
    { name: "book", maxCount: 1 },
  ]),
  (req, res) => {
    const { title, author, description, price, category } = req.body;
    const coverImage = req.files["cover"] ? `/uploads/covers/${req.files["cover"][0].filename}` : null;
    const filePath = req.files["book"] ? `/uploads/books/${req.files["book"][0].filename}` : null;

    db.run(
      `INSERT INTO products (title, author, description, price, cover_image, file_path, category)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [title, author, description, price, coverImage, filePath, category || "service"],
      function (err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, message: "Product created successfully" });
      }
    );
  }
);

// Update product (admin only)
app.patch("/api/products/:id", authenticateToken, (req, res) => {
  const { title, author, description, price, status, category } = req.body;
  const updates = [];
  const values = [];

  if (title !== undefined) { updates.push("title = ?"); values.push(title); }
  if (author !== undefined) { updates.push("author = ?"); values.push(author); }
  if (description !== undefined) { updates.push("description = ?"); values.push(description); }
  if (price !== undefined) { updates.push("price = ?"); values.push(price); }
  if (status !== undefined) { updates.push("status = ?"); values.push(status); }
  if (category !== undefined) { updates.push("category = ?"); values.push(category); }
  updates.push("updated_at = CURRENT_TIMESTAMP");
  values.push(req.params.id);

  db.run(
    `UPDATE products SET ${updates.join(", ")} WHERE id = ?`,
    values,
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Product updated" });
    }
  );
});

// Delete product (admin only)
app.delete("/api/products/:id", authenticateToken, (req, res) => {
  db.get("SELECT file_path, cover_image FROM products WHERE id = ?", [req.params.id], (err, row) => {
    if (row) {
      // Delete files
      if (row.file_path) {
        const fp = path.join(__dirname, row.file_path);
        if (fs.existsSync(fp)) fs.unlinkSync(fp);
      }
      if (row.cover_image) {
        const cp = path.join(__dirname, row.cover_image);
        if (fs.existsSync(cp)) fs.unlinkSync(cp);
      }
    }

    db.run("DELETE FROM products WHERE id = ?", [req.params.id], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: "Product deleted" });
    });
  });
});

// ============ M-PESA INTEGRATION ============

const MPESA_CONFIG = {
  consumerKey: process.env.MPESA_CONSUMER_KEY || "",
  consumerSecret: process.env.MPESA_CONSUMER_SECRET || "",
  passkey: process.env.MPESA_PASSKEY || "",
  shortcode: process.env.MPESA_SHORTCODE || "174379",
  businessShortcode: process.env.MPESA_BUSINESS_SHORTCODE || "174379",
  callbackUrl: process.env.MPESA_CALLBACK_URL || "",
  environment: process.env.MPESA_ENVIRONMENT || "sandbox",
};

const getBaseUrl = () => {
  return MPESA_CONFIG.environment === "sandbox"
    ? "https://sandbox.safaricom.co.ke"
    : "https://api.safaricom.co.ke";
};

// Get M-Pesa access token
async function getAccessToken() {
  const auth = Buffer.from(
    `${MPESA_CONFIG.consumerKey}:${MPESA_CONFIG.consumerSecret}`
  ).toString("base64");

  const response = await axios.get(
    `${getBaseUrl()}/oauth/v1/generate?grant_type=client_credentials`,
    { headers: { Authorization: `Basic ${auth}` } }
  );

  return response.data.access_token;
}

// Initiate STK Push
app.post("/api/mpesa/stkpush", async (req, res) => {
  const { phoneNumber, amount, productId } = req.body;

  try {
    const token = await getAccessToken();
    const timestamp = new Date()
      .toISOString()
      .replace(/[^0-9]/g, "")
      .slice(0, 14);
    const password = Buffer.from(
      `${MPESA_CONFIG.shortcode}${MPESA_CONFIG.passkey}${timestamp}`
    ).toString("base64");

    const formattedPhone = phoneNumber.startsWith("0")
      ? `254${phoneNumber.slice(1)}`
      : phoneNumber;

    const response = await axios.post(
      `${getBaseUrl()}/mpesa/stkpush/v1/processrequest`,
      {
        BusinessShortCode: MPESA_CONFIG.businessShortcode,
        Password: password,
        Timestamp: timestamp,
        TransactionType: "CustomerPayBillOnline",
        Amount: amount,
        PartyA: formattedPhone,
        PartyB: MPESA_CONFIG.businessShortcode,
        PhoneNumber: formattedPhone,
        CallBackURL: MPESA_CONFIG.callbackUrl,
        AccountReference: `FBV-${productId}`,
        TransactionDesc: "Book Purchase",
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );

    // Use the REAL CheckoutRequestID from Safaricom
    const checkoutRequestId = response.data.CheckoutRequestID;

    // Save order
    const downloadToken = uuidv4();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    db.run(
      `INSERT INTO orders (product_id, phone_number, checkout_request_id, amount, status, download_token, download_expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [productId, formattedPhone, checkoutRequestId, amount, "pending", downloadToken, expiresAt.toISOString()],
      function (err) {
        if (err) console.error("Order save error:", err);
      }
    );

    res.json({
      success: true,
      checkoutRequestId: response.data.CheckoutRequestID,
      merchantRequestId: response.data.MerchantRequestID,
      message: "STK push sent to your phone. Please complete payment.",
    });
  } catch (error) {
    console.error("M-Pesa STK push error:", error.response?.data || error.message);
    res.status(500).json({
      error: "Failed to initiate payment",
      details: error.response?.data || error.message,
    });
  }
});

// M-Pesa Callback
app.post("/api/mpesa/callback", (req, res) => {
  const { Body } = req.body;

  if (!Body || !Body.stkCallback) {
    return res.status(400).json({ error: "Invalid callback" });
  }

  const callback = Body.stkCallback;
  const checkoutRequestId = callback.CheckoutRequestID;
  const resultCode = callback.ResultCode;
  const resultDesc = callback.ResultDesc;

  if (resultCode === 0) {
    // Payment successful
    const mpesaReceipt = callback.CallbackMetadata?.Item?.find(
      (item) => item.Name === "MpesaReceiptNumber"
    )?.Value;

    db.run(
      `UPDATE orders SET status = 'paid', mpesa_receipt = ? WHERE checkout_request_id = ?`,
      [mpesaReceipt, checkoutRequestId],
      function (err) {
        if (err) console.error("Callback update error:", err);
      }
    );
  } else {
    // Payment failed
    db.run(
      `UPDATE orders SET status = 'failed' WHERE checkout_request_id = ?`,
      [checkoutRequestId],
      function (err) {
        if (err) console.error("Callback update error:", err);
      }
    );
  }

  res.json({ ResultCode: 0, ResultDesc: "Success" });
});

// Check payment status
app.get("/api/mpesa/status/:checkoutRequestId", (req, res) => {
  const { checkoutRequestId } = req.params;

  db.get(
    `SELECT o.*, p.file_path, p.category, p.title FROM orders o
     JOIN products p ON o.product_id = p.id
     WHERE o.checkout_request_id = ?`,
    [checkoutRequestId],
    (err, order) => {
      if (err || !order) {
        return res.status(404).json({ error: "Order not found" });
      }

      res.json({
        status: order.status,
        mpesaReceipt: order.mpesa_receipt,
        downloadToken: order.status === "paid" ? order.download_token : null,
        downloadUrl:
          order.status === "paid"
            ? `${req.protocol}://${req.get("host")}/api/download/${order.download_token}`
            : null,
        hasFile: !!order.file_path,
        category: order.category,
        productTitle: order.title,
      });
    }
  );
});

// ============ DOWNLOAD ROUTES ============

app.get("/api/download/:token", (req, res) => {
  const { token } = req.params;

  db.get(
    `SELECT o.*, p.file_path, p.category, p.title FROM orders o
     JOIN products p ON o.product_id = p.id
     WHERE o.download_token = ? AND o.status = 'paid'`,
    [token],
    (err, order) => {
      if (err || !order) {
        return res.status(404).json({ error: "Download not found or payment not confirmed" });
      }

      if (new Date() > new Date(order.download_expires_at)) {
        return res.status(403).json({ error: "Download link has expired" });
      }

      // For services without files, return confirmation instead of download
      if (!order.file_path) {
        return res.json({
          type: "service",
          message: "Payment confirmed!",
          productTitle: order.title,
          category: order.category,
          mpesaReceipt: order.mpesa_receipt,
          details: "You will receive a confirmation call/email shortly with next steps.",
        });
      }

      const filePath = path.join(__dirname, order.file_path);
      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ error: "File not found" });
      }

      res.setHeader("Content-Disposition", `attachment; filename="${order.title}.pdf"`);
      res.setHeader("Content-Type", "application/pdf");
      fs.createReadStream(filePath).pipe(res);
    }
  );
});

// ============ ORDERS ROUTES (Admin) ============

app.get("/api/orders", authenticateToken, (req, res) => {
  db.all(
    `SELECT o.*, p.title as product_title FROM orders o
     JOIN products p ON o.product_id = p.id
     ORDER BY o.created_at DESC`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json(rows);
    }
  );
});

// ============ HEALTH CHECK ============

app.get("/api/health", (req, res) => {
  db.get("SELECT * FROM admin_users WHERE username = ?", ["admin"], (err, row) => {
    res.json({
      status: "ok",
      timestamp: new Date().toISOString(),
      adminExists: !!row,
      adminUsername: row ? row.username : null,
    });
  });
});

// Seed admin user (idempotent - safe to call multiple times)
app.post("/api/seed", (req, res) => {
  const defaultPassword = bcrypt.hashSync("admin123", 10);
  db.run(
    "INSERT OR REPLACE INTO admin_users (id, username, password) VALUES ((SELECT id FROM admin_users WHERE username = ?), ?, ?)",
    ["admin", "admin", defaultPassword],
    (err) => {
      if (err) {
        console.error("Seed error:", err);
        return res.status(500).json({ error: "Failed to seed admin user" });
      }
      res.json({ message: "Admin user seeded: admin / admin123" });
    }
  );
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`API base: http://localhost:${PORT}/api`);
});

module.exports = app;
