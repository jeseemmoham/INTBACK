const express = require("express");
const app = express();

const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");

dotenv.config();

// ================= MIDDLEWARE =================
app.use(cors());
app.use(express.json());
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 100,
});
app.use(limiter);

// ================= DB CONNECTION =================
async function connection() {
  try {
    await mongoose.connect(process.env.mongodburl);
    console.log("MongoDB connected");
  } catch (err) {
    console.log("DB connection error", err);
  }
}

// ================= SCHEMAS =================
const productSchema = new mongoose.Schema({
  title: { type: String, required: true },     // naruto-bag
  price: { type: Number, required: true },
  img: { type: String, required: true },
  category: { type: String, required: true },  // naruto / demon
});

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  password: { type: String, required: true },
});

// ================= MODELS =================
const finalproduct = mongoose.model("products", productSchema);
const usermodel = mongoose.model("users", userSchema);

// ================= AUTH ROUTES =================

// SIGNUP
app.post("/signup", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    const userExists = await usermodel.findOne({ username });
    if (userExists) {
      return res.json({ msg: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await usermodel.create({
      username,
      email,
      password: hashedPassword,
    });

    res.json({ msg: "Registration successful" });
  } catch (error) {
    res.json({ msg: error.message });
  }
});

// SIGNIN
app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await usermodel.findOne({ email });
    if (!user) {
      return res.json({ msg: "User not found" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.json({ msg: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user._id, email: user.email },
      process.env.SUPERKEY,
      { expiresIn: "1h" }
    );

    res.json({
      msg: "Login successful",
      token,
    });
  } catch (error) {
    res.json({ msg: error.message });
  }
});

// ================= PRODUCT ROUTES =================

// ADD PRODUCT
app.post("/products", async (req, res) => {
  try {
    const { title, price, img, category } = req.body;

    await finalproduct.create({
      title,
      price,
      img,
      category,
    });

    res.json({ msg: "Product added successfully" });
  } catch (error) {
    res.json({ msg: error.message });
  }
});

// GET ALL PRODUCTS + SEARCH
app.get("/products", async (req, res) => {
  try {
    const { search } = req.query;
    let products;

    if (search) {
      products = await finalproduct.find({
        title: { $regex: search, $options: "i" },
      });
    } else {
      products = await finalproduct.find();
    }

    if (products.length === 0) {
      return res.json({ msg: "Not Found", products: [] });
    }

    res.json({ products });
  } catch (error) {
    res.json({ msg: error.message });
  }
});

// UPDATE PRODUCT
app.put("/products/:id", async (req, res) => {
  try {
    const { id } = req.params;   // 👈 from URL
    const updateData = req.body; // img / title / price

    const updatedProduct = await finalproduct.findByIdAndUpdate(
      id,
      updateData,
      { new: true }
    );

    if (!updatedProduct) {
      return res.status(404).json({ msg: "Product not found" });
    }

    res.json({
      msg: "Product updated successfully",
      product: updatedProduct
    });
  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});



// DELETE PRODUCT
app.delete("/products/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const deletedProduct = await finalproduct.findByIdAndDelete(id);

    if (!deletedProduct) {
      return res.status(404).json({ msg: "Product not found" });
    }

    res.json({
      msg: "Product deleted successfully",
    });
  } catch (error) {
    res.status(500).json({ msg: error.message });
  }
});


// ================= SERVER =================
const port = process.env.PORT || 3000;

app.listen(port, async () => {
  console.log(`Server running on port ${port}`);
  await connection();
});
