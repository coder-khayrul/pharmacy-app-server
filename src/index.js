import { createHash, randomInt, timingSafeEqual } from "node:crypto";
import cors from "cors";
import dotenv from "dotenv";
import express from "express";
import { applicationDefault, cert, getApp, getApps, initializeApp } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import jwt from "jsonwebtoken";
import { MongoClient } from "mongodb";
import nodemailer from "nodemailer";

dotenv.config();

const requiredEnvironment = ["MONGODB_URI", "JWT_SECRET"];
const missingEnvironment = requiredEnvironment.filter((name) => !process.env[name]);
if (missingEnvironment.length > 0) {
  throw new Error(`Missing environment variables: ${missingEnvironment.join(", ")}`);
}

const firebaseCredentials = process.env.FIREBASE_SERVICE_ACCOUNT_JSON
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)
  : null;
const firebaseApp = getApps().length
  ? getApp()
  : initializeApp({
      credential: firebaseCredentials ? cert(firebaseCredentials) : applicationDefault(),
      ...(process.env.FIREBASE_PROJECT_ID ? { projectId: process.env.FIREBASE_PROJECT_ID } : {}),
    });
const firebaseAuth = getAuth(firebaseApp);
const app = express();
const port = Number(process.env.PORT || 4000);
const mongoClient = new MongoClient(process.env.MONGODB_URI);
const verifications = mongoClient
  .db(process.env.MONGODB_DB || "pharmacare")
  .collection("signupVerifications");
const otpLifetimeMs = 10 * 60 * 1000;
const maxOtpAttempts = 5;

app.use(cors());
app.use(express.json({ limit: "16kb" }));

const normalizeEmail = (email) => email.trim().toLowerCase();
const hashCode = (code) => createHash("sha256").update(code).digest();
const toBuffer = (value) => {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) {
    return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  }
  if (
    value &&
    typeof value === "object" &&
    value.buffer instanceof Uint8Array &&
    Number.isInteger(value.position) &&
    value.position >= 0 &&
    value.position <= value.buffer.byteLength
  ) {
    return Buffer.from(value.buffer.buffer, value.buffer.byteOffset, value.position);
  }
  throw new TypeError("Stored signup verification hash is not a valid binary value.");
};
const isFirebaseCredentialError = (error) => error?.code === "app/invalid-credential";
const isFirebasePermissionError = (error) => error?.code === "auth/insufficient-permission";
const isFirebaseConfigurationError = (error) => error?.code === "auth/configuration-not-found";
const firebaseCredentialMessage =
  "Firebase Admin credentials are unavailable. Set FIREBASE_SERVICE_ACCOUNT_JSON on the server or configure Google Application Default Credentials.";
const firebasePermissionMessage =
  "Firebase Admin lacks permission to access Authentication. Grant the service account the Firebase Authentication Admin role in the configured Firebase project, then restart the server.";
const firebaseConfigurationMessage =
  "Firebase Authentication is not configured for the project used by the server. In Firebase Console, finish setting up Authentication and enable Email/Password sign-in for that project.";
const createMailer = () => {
  const { SMTP_HOST: host, SMTP_USER: user, SMTP_PASSWORD: password, SMTP_FROM: from } = process.env;
  if (!host || !user || !password || !from) {
    throw new Error("Email delivery is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD, and SMTP_FROM on the server.");
  }

  return nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT || 587),
    secure: process.env.SMTP_SECURE === "true",
    auth: { user, pass: password },
  });
};

app.get("/api/health", (_request, response) => response.json({ ok: true }));

app.post("/api/auth/signup/request-code", async (request, response) => {
  try {
    const name = typeof request.body.name === "string" ? request.body.name.trim() : "";
    const email = typeof request.body.email === "string" ? normalizeEmail(request.body.email) : "";
    if (name.length < 2 || name.length > 100 || !/^\S+@\S+\.\S+$/.test(email)) {
      return response.status(400).json({ message: "Enter a valid name and email address." });
    }

    let existingUser;
    try {
      existingUser = await firebaseAuth.getUserByEmail(email);
    } catch (error) {
      if (error.code !== "auth/user-not-found") throw error;
    }
    if (existingUser?.emailVerified) {
      return response.status(409).json({ message: "An account with this email already exists. Please log in." });
    }

    const pendingVerification = await verifications.findOne({ email });
    if (pendingVerification?.createdAt && Date.now() - pendingVerification.createdAt.getTime() < 60_000) {
      return response.status(429).json({ message: "Wait a minute before requesting another code." });
    }

    const code = randomInt(0, 1_000_000).toString().padStart(6, "0");
    const expiresAt = new Date(Date.now() + otpLifetimeMs);
    await createMailer().sendMail({
      from: process.env.SMTP_FROM,
      to: email,
      subject: "Your PharmaCare verification code",
      text: `Your PharmaCare email verification code is ${code}. It expires in 10 minutes. If you did not request this, you can ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;color:#123129;max-width:520px;margin:auto"><h2>Verify your email</h2><p>Use this code to finish creating your PharmaCare account:</p><p style="font-size:30px;font-weight:700;letter-spacing:8px;color:#0d7d5d">${code}</p><p>This code expires in 10 minutes. If you did not request it, you can ignore this email.</p></div>`,
    });
    await verifications.replaceOne(
      { email },
      { email, name, codeHash: hashCode(code), attempts: 0, expiresAt, createdAt: new Date() },
      { upsert: true },
    );
    return response.json({ message: "A 6-digit verification code was sent to your email." });
  } catch (error) {
    console.error("Signup verification request failed", error);
    const configurationError = error.message?.startsWith("Email delivery is not configured");
    const firebaseError = isFirebaseCredentialError(error);
    const permissionError = isFirebasePermissionError(error);
    const firebaseAuthConfigurationError = isFirebaseConfigurationError(error);
    return response.status(
      configurationError || firebaseError || permissionError || firebaseAuthConfigurationError ? 503 : 500,
    ).json({
      message: permissionError
        ? firebasePermissionMessage
        : firebaseAuthConfigurationError
          ? firebaseConfigurationMessage
          : firebaseError
            ? firebaseCredentialMessage
            : configurationError
              ? error.message
              : "Unable to send a verification code right now.",
    });
  }
});

app.post("/api/auth/signup/verify-code", async (request, response) => {
  try {
    const email = typeof request.body.email === "string" ? normalizeEmail(request.body.email) : "";
    const code = typeof request.body.code === "string" ? request.body.code : "";
    if (!/^\S+@\S+\.\S+$/.test(email) || !/^\d{6}$/.test(code)) {
      return response.status(400).json({ message: "Enter a valid email and 6-digit code." });
    }

    const record = await verifications.findOne({ email });
    if (!record || record.expiresAt <= new Date()) {
      return response.status(400).json({ message: "That code has expired. Request a new one." });
    }
    if (record.attempts >= maxOtpAttempts) {
      await verifications.deleteOne({ _id: record._id });
      return response.status(429).json({ message: "Too many incorrect attempts. Request a new code." });
    }

    const storedCodeHash = toBuffer(record.codeHash);
    const submittedCodeHash = hashCode(code);
    if (
      storedCodeHash.length !== submittedCodeHash.length ||
      !timingSafeEqual(storedCodeHash, submittedCodeHash)
    ) {
      const attempts = record.attempts + 1;
      await verifications.updateOne({ _id: record._id }, { $set: { attempts } });
      return response.status(attempts >= maxOtpAttempts ? 429 : 400).json({
        message: attempts >= maxOtpAttempts
          ? "Too many incorrect attempts. Request a new code."
          : "The verification code is incorrect.",
      });
    }

    await verifications.deleteOne({ _id: record._id });
    const verificationToken = jwt.sign(
      { email, name: record.name, purpose: "signup-email-otp" },
      process.env.JWT_SECRET,
      { expiresIn: "10m" },
    );
    return response.json({ verificationToken });
  } catch (error) {
    console.error("Signup code verification failed", error);
    return response.status(500).json({ message: "Unable to verify your code right now." });
  }
});

app.post("/api/auth/signup/complete", async (request, response) => {
  try {
    const idToken = request.headers.authorization?.replace(/^Bearer\s+/i, "");
    if (!idToken) return response.status(401).json({ message: "Sign in to complete account setup." });

    const decodedIdToken = await firebaseAuth.verifyIdToken(idToken);
    const verification = jwt.verify(request.body.verificationToken || "", process.env.JWT_SECRET);
    if (
      verification.purpose !== "signup-email-otp" ||
      verification.email !== decodedIdToken.email ||
      decodedIdToken.email_verified
    ) {
      return response.status(403).json({ message: "The verification proof does not match this account." });
    }

    const user = await firebaseAuth.updateUser(decodedIdToken.uid, {
      displayName: verification.name,
      emailVerified: true,
    });
    await firebaseAuth.setCustomUserClaims(user.uid, {
      ...(user.customClaims || {}),
      emailOtpVerified: true,
    });
    return response.json({ message: "Your email is verified and your account is ready." });
  } catch (error) {
    console.error("Signup completion failed", error);
    const badToken = error.name === "JsonWebTokenError" || error.name === "TokenExpiredError";
    const firebaseError = isFirebaseCredentialError(error);
    const permissionError = isFirebasePermissionError(error);
    const firebaseAuthConfigurationError = isFirebaseConfigurationError(error);
    return response.status(
      firebaseError || permissionError || firebaseAuthConfigurationError ? 503 : badToken ? 403 : 500,
    ).json({
      message: permissionError
        ? firebasePermissionMessage
        : firebaseAuthConfigurationError
          ? firebaseConfigurationMessage
          : firebaseError
          ? firebaseCredentialMessage
          : badToken
            ? "Your verification session expired. Request and verify a new code."
            : "Unable to complete your account setup.",
    });
  }
});

const start = async () => {
  await mongoClient.connect();
  await verifications.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
  await verifications.createIndex({ email: 1 }, { unique: true });
  app.listen(port, () => console.log(`PharmaCare authentication API listening on port ${port}`));
};

start().catch((error) => {
  console.error("Server startup failed", error);
  process.exit(1);
});
