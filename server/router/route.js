// // const express = require("express");
// // const router = express.Router();

// import { Router } from "express";
// const router = Router();

// // /** import all controllers */
// import * as controller from '../controllers/appController.js';
// import { registerMail } from '../controllers/mailer.js'
// import Auth, { localVariables } from '../middleware/auth.js';
// /** important all controllers */ 
// // const controller = require('../controllers/appController.js');

// // /** POST Methods */
// router.route('/register').post(controller.register); // register user
// router.route('/registerMail').post(registerMail); // send the email
// router.route('/authenticate').post(controller.verifyUser, (req, res) => res.end()); // authenticate user
// router.route('/login').post(controller.verifyUser,controller.login); // login in app

// // /** GET Methods */
// router.route('/user/:username').get(controller.getUser) // user with username
// router.route('/generateOTP').get(controller.verifyUser, localVariables, controller.generateOTP) // generate random OTP
// router.route('/verifyOTP').get(controller.verifyUser, controller.verifyOTP) // verify generated OTP
// router.route('/createResetSession').get(controller.createResetSession) // reset all the variables
// router.get('/api/register', (req, res) => {
//     res.send('This is the register page.');
//   });
// // /** PUT Methods */
// router.route('/updateuser').put(Auth, controller.updateUser); // is use to update the user profile
// router.route('/resetPassword').put(controller.verifyUser, controller.resetPassword); // use to reset password

// // module.exports = router;



import jwt from 'jsonwebtoken';
import config from '../router/Config.js';
// import {UserSchema, FormSchema } from '../model/User.model.js';
import { Router } from "express";
const router = Router();
/** import all controllers */
import * as controller from '../controllers/appController.js';
import { registerMail } from '../controllers/mailer.js'
// import  { verifyToken } from '../middleware/auth.js';
// import UserModel from "../model/User.model.js";
import bcrypt from "bcrypt";

import { User, Form } from '../model/User.model.js';

import pkg from 'node-sessionstorage';
const { sessionStorage } = pkg;
import generateToken from "../middleware/auth.js"
import { token } from 'morgan';

/** POST Methods */
// router.post('/register', async (req, res) => {
//     const { username, password, email, firstName, lastName, phoneNumber, address } = req.body;

//     // Check if user with the same username or email already exists
//     const existingUser = await UserModel.findOne({ $or: [{ username }, { email }] });
//     if (existingUser) {
//       return res.status(400).send({ message: 'User already exists' });
//     }

//     // Save the new user to the database
//     const newUser = new UserModel({ username, password, email, firstName, lastName, phoneNumber, address });
//     await newUser.save();

//     // Send a response back to the client
//     res.send({ message: 'User registered successfully' });
//   });
const jwt_Secret = config.JWT_SECRET;

// Define a function to check if all required fields are present in the request body
// const checkRequiredFields = (body, requiredFields) => {
//   for (const field of requiredFields) {
//     if (!body[field]) {
//       return false;
//     }
//   }
//   return true;
// };

// // // Define an API to register a new user
// router.post('/register', async (req, res) => {
//   const { username, password, email, firstName, lastName, phoneNumber, address } = req.body;

//   // Check if all required fields are present in the request body
//   const requiredFields = ['username', 'password', 'email', 'firstName', 'lastName', 'phoneNumber', 'address'];
//   if (!checkRequiredFields(req.body, requiredFields)) {
//     return res.status(400).send({ message: 'Please fill in all required fields' });
//   }

//   // Check if user with the same username or email already exists
//   const existingUser = await User.findOne({ $or: [{ username }, { email }] });
// if (existingUser) {
//     return res.status(400).send({ message: 'User already exists' });
//   }

//   // Save the new user to the database
//   const newUser = new User({ username, password, email, firstName, lastName, phoneNumber, address });
//   await newUser.save();

//   // Generate a JWT token and send it back to the client
//   const token = jwt.sign({ email }, jwt_Secret
//                          );
//   res.send({ message: 'User registered successfully', token });
// });

// // Define an API to update user data
// router.post('/form', async (req, res) => {
//   try {
//     // Verify JWT token from request header
//     const authorizationHeader = req.headers.authorization;
//     if (!authorizationHeader) {
//       throw new Error('Authorization header is missing');
//     }
//     const token = authorizationHeader.split(' ')[1];
//     const tokenData = jwt.verify(token, jwt_Secret);
//     const userEmail = tokenData.email;

//     // Update user data with form data (if user exists)
//     const user = await Form.findOne({ userEmail });
// if (!user) {
//       throw new Error('User not found');
//     }
//     const { address, bankAccount, ifscCode } = req.body;
//     if (!checkRequiredFields(req.body, ['address', 'bankAccount', 'ifscCode'])) {
//       throw new Error('Address, bank account, and IFSC code are required');
//     }
//     user.address = address;
//     user.bankAccount = bankAccount;
//     user.ifscCode = ifscCode;
//     await user.save();

//     // Send a response back to the client
//     res.send({ message: 'User data updated successfully' });
//   } catch (err) {
//     console.log(err.message);
//     res.status(400).send({ message: err.message });
//   }
// });
// const localStorage = {
//   getItem: function(key) {
//     return window.localStorage.getItem(key);
//   },
//   setItem: function(key, value) {
//     window.localStorage.setItem(key, value);
//   },
//   removeItem: function(key) {
//     window.localStorage.removeItem(key);
//   }
// };

// const encryptPassword = async (password) => {
//   const salt = await bcrypt.genSalt(10);
//   const hashedPassword = await bcrypt.hash(password, salt);
//   return hashedPassword;
// };

// const comparePassword = async (password, hashedPassword) => {
//   const isMatch = await bcrypt.compare(password, hashedPassword);
//   return isMatch;
// };

// const checkRequiredFields = (body, requiredFields) => {
//   for (const field of requiredFields) {
//     if (!body[field]) {
//       return false;
//     }
//   }
//   return true;
// };

// router.post('/register', async (req, res) => {
//   const { username, password, email, firstName, lastName, phoneNumber, address } = req.body;

//   const requiredFields = ['username', 'password', 'email', 'firstName', 'lastName', 'phoneNumber', 'address'];
//   if (!checkRequiredFields(req.body, requiredFields)) {
//     return res.status(400).send({ message: 'Please fill in all required fields' });
//   }

//   const existingUser = await User.findOne({ $or: [{ username }, { email }] });

//   if (existingUser) {
//     return res.status(400).send({ message: 'User already exists' });
//   }

//   const hashedPassword = await encryptPassword(password);
//   const newUser = new User({ username, password: hashedPassword, email, firstName, lastName, phoneNumber, address });
//   await newUser.save();

//   const token = jwt.sign({ email }, jwt_Secret);

//   // Set token and email in session storage

//   res.send({ message: 'User registered successfully', token });
// });

// router.post('/form', async (req, res) => {
//   try {


//     if (!token || !email) {
//       throw new Error('Token not found in localStorage');
//     }

//     const tokenData = jwt.verify(token, jwt_Secret);
//     const userEmail = tokenData.email;

//     const user = await Form.findOne({ userEmail });

//     if (!user) {
//       throw new Error('User not found');
//     }

//     const { address, bankAccount, ifscCode } = req.body;
//     if (!checkRequiredFields(req.body, ['address', 'bankAccount', 'ifscCode'])) {
//       throw new Error('Address, bank account, and IFSC code are required');
//     }

//     user.address = address;
//     user.bankAccount = bankAccount;
//     user.ifscCode = ifscCode;

//     await user.save();

//     res.send({ message: 'User data updated successfully' });
//   } catch (err) {
//     console.log(err.message);
//     res.status(400).send({ message: err.message });
//   }
// });





// const verifyToken = (req, res, next) => {
//   const token = req.headers.authorization?.split(' ')[1];
//   if (!token) {
//     return res.status(401).json({ message: 'Token not found.' });
//   }

//   jwt.verify(token, process.env.JWT_SECRET, (err, decodedToken) => {
//     if (err) {
//       return res.status(401).json({ message: 'Invalid token.' });
//     }

//     req.user = decodedToken.user;
//     next();
//   });
// };

// // Update user data
// router.post('/form', verifyToken, async (req, res) => {
//   try {
//     const { address, bankAccount, ifscCode } = req.body;

//     // Find and update user data by ID
//     const updatedUser = await User.findByIdAndUpdate(
//       req.user.id,
//       { address, bankAccount, ifscCode },
//       { new: true } // return updated document
//     );

//     res.json({ success: true, updatedUser });
//   } catch (error) {
//     console.error(error);
//     res.status(500).json({ message: 'Server error.' });
//   }
// });






// router.post('/register', async (req, res) => {
//   const { username, password, email, firstName, lastName, phoneNumber, address } = req.body;

//   // Check if user with the same username or email already exists
//   const existingUser = await UserModel.findOne({ $or: [{ username }, { email }] });
//   if (existingUser) {
//     return res.status(400).send({ message: 'User already exists' });
//   }

//   // Encrypt the password
//   const salt = await bcrypt.genSalt(10);
//   const hashedPassword = await bcrypt.hash(password, salt);

//   // Save the new user to the database
//   const newUser = new UserModel({ username, password: hashedPassword, email, firstName, lastName, phoneNumber, address });
//   await newUser.save();

//   // Send a response back to the client
//   res.send({ message: 'User registered successfully' });
// });



router.route('/registerMail').post(registerMail); // send the email
router.route('/authenticate').post(controller.verifyUser, (req, res) => res.end()); // authenticate user
// router.route('/login').post(controller.login); // login in app
router.route('/procted').post(generateToken);
/** GET Methods */
router.route('/user/:username').get(controller.getUser) // user with username
// router.route('/generateOTP').get(controller.verifyUser, localVariables, controller.generateOTP) // generate random OTP
router.route('/verifyOTP').get(controller.verifyUser, controller.verifyOTP) // verify generated OTP
router.route('/createResetSession').get(controller.createResetSession) // reset all the variables
router.route('/register').get(controller.getCollectionData); // register user
// router.route('/auth').post(loginUser,verifyToken,(req, res,next) => {
//   res.status(200).json({ message: "Authentication successful!" });
// });
// router.post('/login', async (req, res) => {
//   const { username, password } = req.body;

//   // Check if user with the given username exists
//   const user = await UserModel.findOne({ username });
//   if (!user) {
//     return res.status(400).send({ message: 'User not found' });
//   }

//   // Check if the password is correct
//   const isPasswordCorrect = await bcrypt.compare(password, user.password);
//   if (!isPasswordCorrect) {
//     return res.status(400).send({ message: 'Invalid password' });
//   }

//   // Generate a token and send it to the client
//   const token = generateToken(user);
//   res.send({ token });
// });


const secretKey = config.jwtSecretKey;

// // Update
// router.post('/update', async (req, res) => {
//   const { username, email, newData } = req.body;

//   // Verify the JWT token
//   const token = req.headers.authorization?.split(' ')[1];
//   if (!token) {
//     return res.status(401).send({ message: 'Missing authorization token' });
//   }

//   try {
//     const decodedToken = jwt.verify(token, secretKey);
//     const userId = decodedToken.userId;

//     // Find the user by ID and validate the username or email
//     const user = await UserModel.findOne({ _id: userId, $or: [{ username }, { email }] });
//     if (!user) {
//       return res.status(404).send({ message: 'User not found' });
//     }

//     // Update the user data
//     user.data.push(newData);

//     // Save the updated user to the database
//     await user.save();

//     // Send a response back to the client
//     res.send({ message: 'User data updated successfully' });
//   } catch (error) {
//     return res.status(401).send({ message: 'Invalid authorization token' });
//   }
// });

router.get('/user-data', async (req, res) => {
  try {
    // Get the JWT token from the client's local storage
    const token = req.headers.authorization.split(' ')[1] || localStorage.getItem('token');
    if (!token) {
      return res.status(401).send({ message: 'Invalid or missing JWT token' });
    }

    // Verify the JWT token and get the user's ID
    const decodedToken = jwt.verify(token, process.env.JWT_SECRET);
    const userId = decodedToken.userId;

    // Get the user's username from the database
    const user = await UserModel.findById(userId).select('username');
    if (!user) {
      return res.status(404).send({ message: 'User not found' });
    }

    // Send the user's username back to the client
    res.send({ username: user.username });
  } catch (error) {
    res.status(401).send({ message: 'Invalid or missing JWT token' });
  }
});

router.get('/protected', (req, res) => {
  try {
    // Get JWT token from request headers
    const token = req.headers.authorization.split(' ')[1];

    // Verify JWT token with secret key
    const decodedToken = jwt.verify(token, 'jwt_Secret');

    // Get user ID from decoded token
    const userId = decodedToken.userId;

    // Send response with user ID
    res.send(`User ID: ${userId}`);
  } catch (error) {
    // Send error response if token is invalid or missing
    res.status(401).send('Invalid or missing JWT token');
  }
});

/** PUT Methods */
// router.route('/updateuser').put(Auth, controller.updateUser); // is use to update the user profile
router.route('/resetPassword').put(controller.verifyUser, controller.resetPassword); // use to reset password







// Register endpoint
router.post('/register', async (req, res) => {
  console.log("New user registration request received");

  // Check required fields
  if (!req.body.username || !req.body.password || !req.body.email) {
      console.log("Required fields missing");
      return res.status(400).send("Username, password, and email are required fields");
  }

  // Check if user already exists
  const existingUser = await User.findOne({ username: req.body.username });
  if (existingUser) {
      console.log("Username already exists");
      return res.status(409).send("Username already exists");
  }

  // Encrypt password using bcrypt
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.password, salt);

  // Create new user object with form data
  const newUser = new User({
      username: req.body.username,
      password: hashedPassword,
      email: req.body.email,
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      phoneNumber: req.body.phoneNumber,
      address: req.body.address
  });

  // Save new user object to database
  try {
      const savedUser = await newUser.save();
      console.log("New user saved to database");

      // Generate JWT token
      const token = jwt.sign({ _id: savedUser._id }, config.JWT_SECRET);
      console.log("JWT token generated for user:", savedUser.username);

      // Store token in cookie
      res.cookie('auth-token', token, {
        maxAge: 86400000, // 24 hours
        httpOnly: true,
        secure: true,
        sameSite: 'strict'
      });

      res.send({ message: 'Registration successful' });
  } catch (err) {
      console.log("Error saving user to database:", err.message);
      res.status(500).send("Error saving user to database");
  }
});

// // Login endpoint
// router.post('/login', async (req, res) => {
//   console.log("User login request received");

//   // Check required fields
//   if (!req.body.username || !req.body.password) {
//       console.log("Required fields missing");
//       return res.status(400).send("Username and password are required fields");
//   }

//   // Check if user exists
//   const user = await User.findOne({ username: req.body.username });
//   if (!user) {
//       console.log("User not found");
//       return res.status(400).send("Invalid username or password");
//   }

//   // Check if password is correct
//   const validPassword = await bcrypt.compare(req.body.password, user.password);
//   if (!validPassword) {
//       console.log("Invalid password");
//       return res.status(400).send("Invalid username or password");
//   }

//   // Generate JWT token
//   const token = jwt.sign({ _id: user._id }, config.JWT_SECRET);
//   console.log("JWT token generated for user:", user.username);

//   // Store token in cookie
//   res.cookie('auth-token', token, {
//     maxAge: 86400000, // 24 hours
//     httpOnly: true,
//     secure: true,
//     sameSite: 'strict'
//   });

//   res.send({ message: 'Login successful' });
// });




// /*** */
// const getToken = (req) => {
//   // Check if cookies is present and has token
//   const cookies = req.cookies;
//   if (cookies && cookies.token) {
//       console.log("Token found in cookies");
//       return cookies.token;
//   }

//   // Check if token is present in auth header
//   const authHeader = req.header('Authorization');
//   if (authHeader && authHeader.startsWith('Bearer ')) {
//       const bearerToken = authHeader.substring(7);
//       console.log("Token found in auth header");
//       return bearerToken;
//   }

//   console.log("No token found in cookies or auth header");
//   return null;
// };

// function getTokenFromCookies(req) {
//   let token = req.headers['authorization'] || req.cookies['token'];
//   if (!token) {
//     console.log("No token found in cookies");
//     return null;
//   }

//   try {
//     // Remove "Bearer " prefix if present
//     if (token.startsWith("Bearer ")) {
//       token = token.slice(7, token.length);
//     }
//     const decodedToken = jwt.verify(token, config.JWT_SECRET);
//     console.log("Decoded token:", decodedToken);

//     // Check if decoded token contains required fields (e.g. user ID)
//     if (!decodedToken._id || !decodedToken.email || !decodedToken.password) {
//       console.log("Invalid token. Missing required fields");
//       return null;
//     }

//     return decodedToken._id; // Return user ID
//   } catch (err) {
//     console.log("Error decoding token:", err.message);
//     return null;
//   }
// }

// // Add middleware to check if user is authorized with valid token
// const authorize = (req, res, next) => {
//   const authToken = getTokenFromCookies(req); // Use authToken to decode
//   if (!authToken) {
//       console.log("No authorization token provided");
//       return res.status(401).send("Access denied. No token provided");
//   }

//   try {
//       const decodedToken = jwt.verify(authToken, config.JWT_SECRET);
//       req.user = {
//         id: decodedToken.id,
//         email: decodedToken.email,
//         password: decodedToken.password,
//         username: decodedToken.username
//       };
//       next();
//   } catch (err) {
//       console.log("Invalid authorization token provided");
//       res.status(400).send("Invalid token provided");
//   }
// }


// // Add user data
// // Add or update user data
// // Add or update user data
// // Add or update user data using Form schema
// // Add or update user data
// router.post('/addData', async (req, res) => {
//   console.log("User data add request received");

//   // Get user ID from token
//   const userId = getTokenFromCookies(req);
//   if (!userId) {
//     return res.status(401).send("Unauthorized");
//   }

//   try {
//     // Find the existing user object in database
//     let user = await Form.findById(userId);
//     if (!user) {
//       console.log("User not found");
//       return res.status(404).json({ error: "User not found" });
//     }

//     // Update the user object with new form data
//     if (!user.form) {
//       user.form = {}; // Create a new form object if it doesn't exist
//     }
//     if (req.body.bankAcc) user.form.bankAcc = req.body.bankAcc;
//     if (req.body.ifsc) user.form.ifsc = req.body.ifsc;
//     if (req.body.adharNumber) user.form.adharNumber = req.body.adharNumber;
//     if (req.body.panNumber) user.form.panNumber = req.body.panNumber;
//     if (req.body.address) user.form.address = req.body.address;

//     // Save the updated user object to the database
//     user = await user.save();

//     console.log("User data added/updated successfully. User ID:", userId, "Form data:", user.form);
//     res.send(user);
//   } catch (err) {
//     console.log("Error adding/updating user data:", err.message);
//     res.status(500).send("Error adding/updating user data");
//   }
// });


function getTokenFromCookies(req) {
  let token = req.headers['authorization'] || req.cookies['token'];
  if (!token) {
    console.log("No token found in cookies");
    return null;
  }

  try {
    // Remove "Bearer " prefix if present
    if (token.startsWith("Bearer ")) {
      token = token.slice(7, token.length);
    }
    const decodedToken = jwt.verify(token, config.JWT_SECRET);
    console.log("Decoded token:", decodedToken);

    // Check if decoded token contains required fields (e.g. user ID)
    if (!decodedToken.userId || !decodedToken.email) {
      console.log("Invalid token. Missing required fields");
      return null;
    }

    return decodedToken; // Return decoded token object
  } catch (err) {
    console.log("Error decoding token:", err.message);
    return null;
  }
}

const authorize = (req, res, next) => {
  const authToken = getTokenFromCookies(req); // Use authToken to decode
  if (!authToken) {
    console.log("No authorization token provided");
    return res.status(401).send("Access denied. No token provided");
  }

  try {
    req.user = {
      id: authToken.userId,
      email: authToken.email,
    };
    next();
  } catch (err) {
    console.log("Invalid authorization token provided");
    res.status(400).send("Invalid token provided");
  }
};

router.post('/addData', authorize, async (req, res) => {
  console.log("User data add request received");

  // Get user ID from token
  const userId = req.user.id;
  if (!userId) {
    return res.status(401).send("Unauthorized");
  }

  try {
    // Find the existing user object in database
    let user = await User.findById(userId);
    if (!user) {
      console.log("User not found");
      return res.status(404).json({ error: "User not found" });
    }

    // Update the user object with new form data
    if (!user.form) {
      user.form = {}; // Create a new form object if it doesn't exist
    }
    if (req.body.bankAcc) user.form.bankAcc = req.body.bankAcc;
    if (req.body.ifsc) user.form.ifsc = req.body.ifsc;
    if (req.body.adharNumber) user.form.adharNumber = req.body.adharNumber;
    if (req.body.panNumber) user.form.panNumber = req.body.panNumber;
    if (req.body.address) user.form.address = req.body.address;

    // Save the updated user object to the database
    user = await user.save();
    console.log("User data added/updated successfully. User ID:", userId, "Form data:", user.form);
    res.send(user);
  } catch (err) {
    console.log("Error adding/updating user data:", err.message);
    res.status(500).json({ error: "Error adding/updating user data" });
  }
});



export default router;