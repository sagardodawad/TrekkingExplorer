import express from "express";
import dotenv from "dotenv";
import mongoose from "mongoose";
import cors from "cors";
import cookieParser from "cookie-parser";
import tourRoute from "./routes/tour.js";
import userRoute from "./routes/user.js";
import authRoute from "./routes/auth.js";
import reviewRoute from "./routes/review.js";
import bookingRoute from "./routes/booking.js";
import Joi from "joi";
import crypto from "crypto";
import bcrypt from "bcrypt";
import nodemailer from "nodemailer";


// Change this line in your index.js file
import
 { Token } from "./models/token.js";
 import User from "./models/User.js";


dotenv.config();

const app = express();
const port = process.env.PORT || 8000;
const corsOptions = {
  origin: true,
  credentials: true,
};

// database connection
mongoose.set("strictQuery", false);
const connect = async () => {
  try {
    await mongoose.connect(process.env.MONGO_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("MongoDB database connected");
  } catch (err) {
    console.log("MongoDB database not connected");
  }
};

app.use(express.json());
app.use(cors(corsOptions));
app.use(cookieParser());
app.use("/api/v1/auth", authRoute);
app.use("/api/v1/tours", tourRoute);
app.use("/api/v1/users", userRoute);
app.use("/api/v1/reviews", reviewRoute);
app.use("/api/v1/booking", bookingRoute);

const hashPassword = async (password) => {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
};

app.post("/forgot-password", async (req, res) => {
  try {
    const emailSchema = Joi.object({
      email: Joi.string().email().required().label("Email"),
    });
    const { error } = emailSchema.validate(req.body);
    if (error) {
      return res.status(400).send({ message: error.details[0].message });
    }
    
    let user = await User.findOne({ email: req.body.email });

    // console.log(user);
    if (!user) {
      return res.status(409).send({ message: "User with given email does not exist!" });
    }
    
    let token = await Token.findOne({ userId: user._id });
    if (!token) {
      token = await new Token({
        userId: user._id,
        token: crypto.randomBytes(32).toString("hex"),
      }).save();
    }

    const url = `${process.env.BASE_URL}password-reset/${user._id}/${token.token}/`;
    const emailSent = await sendEmail(user.email, "Password Reset", url);

    if (emailSent) {
      return res.status(200).send({ message: "Password reset link sent to your email account" });
    } else {
      return res.status(500).send({ message: "Internal Server Error" });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).send({ message: "Internal Server Error" });
  }
});

const sendEmail = async (email, subject, text) => {
  try {
    const transporter = nodemailer.createTransport({
      host: process.env.HOST,
      service: process.env.SERVICE,
      port: process.env.SMTP_PORT,
      auth: {
        user: process.env.USER,
        pass: process.env.PASS,
      },
    });

    transporter.sendMail({
      from: process.env.USER,
      to: email,
      subject: subject,
      text: text,
    });
    return true;
  } catch (error) {
    console.log(error);
    return false;
  }
};

app.post("/password-reset/:userId/:token", async (req, res) => {
  

  try {
    const { userId, token } = req.params;
    const { password } = req.body;
    const validToken = await Token.findOne({ userId, token });
    if (!validToken) {
      return res.status(400).send({ message: "Invalid or expired token" });
    }

    const hashedPassword = await hashPassword(password);
    await User.findByIdAndUpdate(userId, { password: hashedPassword });

    return res.status(200).send({ message: "Password reset successful" });
  } catch (error) {
    console.error(error);
    return res.status(500).send({ message: "Internal Server Error" });
  }
});

app.listen(port, () => {
  connect();
  console.log("Server listing on port", port);
});
