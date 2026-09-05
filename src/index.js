import bcrypt from "bcryptjs";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import jwt from "jsonwebtoken";
import { MongoClient } from "mongodb";

dotenv.config();

const requiredEnvironment = ["MONGODB_URI", "JWT_SECRET"];
const missingEnvironment = requiredEnvironment.filter((name) => !process.env[name]);

if (missingEnvironment.length > 0) {
  throw new Error(`Missing environment variables: ${missingEnvironment.join(", ")}`);
}

const app = express();
const port = Number(process.env.PORT || 4000);
const mongoClient = new MongoClient(process.env.MONGODB_URI);
const users = mongoClient
  .db(process.env.MONGODB_DB || "pharmacare")
  .collection("users");

app.use(cors());
app.use(express.json());

const createToken = (user) =>
  jwt.sign(
    { sub: user._id.toString(), email: user.email, name: user.name },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "7d" },
  );

const normalizeEmail = (email) => email.trim().toLowerCase();

app.get("/api/health", (_request, response) => {
  response.json({ ok: true });
});

app.post("/api/auth/signup", async (request, response) => {
  try {
    const name = typeof request.body.name === "string" ? request.body.name.trim() : "";
    const email = typeof request.body.email === "string" ? normalizeEmail(request.body.email) : "";
    const password = typeof request.body.password === "string" ? request.body.password : "";

    if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8) {
      return response.status(400).json({ message: "Enter a valid name, email, and password of at least 8 characters." });
    }

    const existingUser = await users.findOne({ email });
    if (existingUser) {
      return response.status(409).json({ message: "An account with this email already exists." });
    }

    const user = {
      name,
      email,
      passwordHash: await bcrypt.hash(password, 12),
      createdAt: new Date(),
    };
    const result = await users.insertOne(user);
    const createdUser = { _id: result.insertedId, name, email };

    return response.status(201).json({
      user: createdUser,
      token: createToken(createdUser),
    });
  } catch (error) {
    console.error("Signup failed", error);
    return response.status(500).json({ message: "Unable to create your account right now." });
  }
});

app.post("/api/auth/login", async (request, response) => {
  try {
    const email = typeof request.body.email === "string" ? normalizeEmail(request.body.email) : "";
    const password = typeof request.body.password === "string" ? request.body.password : "";
    const user = await users.findOne({ email });

    if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
      return response.status(401).json({ message: "Invalid email or password." });
    }

    const safeUser = { _id: user._id, name: user.name, email: user.email };
    return response.json({ user: safeUser, token: createToken(safeUser) });
  } catch (error) {
    console.error("Login failed", error);
    return response.status(500).json({ message: "Unable to log in right now." });
  }
});

const start = async () => {
  await mongoClient.connect();
  await users.createIndex({ email: 1 }, { unique: true });
  app.listen(port, () => console.log(`PharmaCare API listening on port ${port}`));
};

start().catch((error) => {
  console.error("Server startup failed", error);
  process.exit(1);
});

// const uri = "mongodb+srv://pharmacyadmin:ArEAMijXmOY01F8b@cluster0.pvi1q6h.mongodb.net/?appName=Cluster0";