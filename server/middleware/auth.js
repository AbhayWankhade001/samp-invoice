// import jwt from 'jsonwebtoken';
// import bcrypt from 'bcrypt';
// import User from '../model/User.model.js';
// import ENV from '../router/Config.js';


// /** auth middleware */
// export default async function Auth(req, res, next){
//     try {
//         // access authorize header to validate request
//         const token = req.headers.authorization.split(" ")[1];

//         // retrieve the user details for the logged in user
//         const decodedToken = await jwt.verify(token, ENV.JWT_SECRET);

//         req.user = decodedToken;

//         next();

//     } catch (error) {
//         res.status(401).json({ error : "Authentication Failed!"})
//     }
// }


// export function localVariables(req, res, next){
//     req.app.locals = {
//         OTP : null,
//         resetSession : false,
//         currentUser: req.user
//     };
//     next();
// }



// /** auth middleware */
// // Generate token for user login and store it to database


// export const generateToken = async (req, res, next) => {
//   try {
//     const { username, password } = req.body;

//     // check if user exists in the database
//     const user = await User.findOne({ username });
//     if (!user) {
//       return res.status(401).json({ error: 'Authentication Failed!' });
//     }

//     // check if the password is correct
//     const isPasswordCorrect = await bcrypt.compare(password, user.password);
//     if (!isPasswordCorrect) {
//       return res.status(401).json({ error: 'Authentication Failed!' });
//     }

//     // generate and sign JWT token
//     const token = jwt.sign(
//       {
//         username: user.username,
//         userId: user._id,
//       },
//       ENV.JWT_SECRET,
//       {
//         expiresIn: '1h',
//       }
//     );

//     // store token in cookie
//     res.cookie('token', token, { httpOnly: true });

//     next();
//   } catch (error) {
//     console.log('error', error);
//     res.status(500).json({ error: error.message });
//   }
// };


// /** account route middleware */
// export async function account(req, res, next){
//     try {
//         const token = req.cookies.token;
//         const decodedToken = jwt.verify(token, ENV.JWT_SECRET);
//         const userId = decodedToken.userId;

//         // retrieve the user details for the logged in user
//         const user = await User.findById(userId);

//         res.status(200).json({
//             message: "Welcome to your account!",
//             user: {
//                 email: user.email,
//                 name: user.name
//             }
//         });

//     } catch (error) {
//         res.status(401).json({ error: "Authentication Failed!" });
//     }
// }

import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import User from "../model/User.model.js";
import config from "../router/config.js";

export default async function loginUser(req, res, next) {
  const { email, password } = req.body;
  try {
    // check if user exists in database
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // check if password is correct
    const isPasswordMatch = await bcrypt.compare(password, user.password);
    if (!isPasswordMatch) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // generate token
    const token = generateToken(user);

    // save token in database
    user.tokens = user.tokens.concat({ token });
    await user.save();

    // send response with token and user data
    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        email: user.email,
        name: user.name,
      },
    });
  } catch (err) {
    next(err);
  }
}

function generateToken(user) {
  const token = jwt.sign(
    {
      userId: user._id,
      username: user.username,
      email: user.email,
    },
    config.JWT_SECRET,
    {
      expiresIn: "1h",
    }
  );
  return token;
}

export async function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ error: "Authorization header missing" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decodedToken = jwt.verify(token, config.JWT_SECRET);

    // find user by token and token's user ID
    const user = await User.findOne({ _id: decodedToken.userId, "tokens.token": token });
    if (!user) {
      throw new Error();
    }

    req.user = user;
    req.token = token;
    next();
  } catch (err) {
    res.status(401).json({ error: "Authentication failed" });
  }
}
