// const express = require('express');
// const cors = require('cors');
// const mongoose = require('mongoose');
// const bcrypt = require('bcryptjs');
// const jwt = require('jsonwebtoken');
// const morgan = require('morgan')
// const app = express();
// const port = process.env.PORT || 5000;

// app.use(cors());
// app.use(express.json());

// mongoose.connect('mongodb+srv://abhaywankhade2004:9529370446%40aw@cluster0.kljekbq.mongodb.net/test', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true
// });

// const userSchema = new mongoose.Schema({
//   email: String,
//   password: String
// });

// const User = mongoose.model('User', userSchema);

// app.post('/api/register', async (req, res) => {
//   const { email, password } = req.body;

//   const user = await User.findOne({ email });

//   if (user) {
//     return res.status(400).json({ message: 'User already exists' });
//   }

//   const hashedPassword = await bcrypt.hash(password, 10);

//   const newUser = new User({
//     email,
//     password: hashedPassword
//   });

//   await newUser.save();

//   res.json({ message: 'User created' });
// });

// app.post('/api/login', async (req, res) => {
//   const { email, password } = req.body;

//   const user = await User.findOne({ email });

//   if (!user) {
//     return res.status(400).json({ message: 'User not found' });
//   }

//   const isMatch = await bcrypt.compare(password, user.password);

//   if (!isMatch) {
//     return res.status(400).json({ message: 'Incorrect password' });
//   }

//   const token = jwt.sign({ id: user._id }, 'secret', { expiresIn: '1h' });

//   res.json({ token });
// });

// app.listen(port, () => {
//   console.log(`Server running on port ${port}`);
// });
// import express from 'express';
// import cors from 'cors';
// import morgan from 'morgan';
// const express = require('express');
// const cors = require('cors');
// const morgan = require('morgan');
// const mongoose = require('mongoose');
// const multer = require('multer');
// const connect = require('./database/conn')
// const router = require('./router/route')
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import connect from './database/conn.js';
import router from './router/route.js';
import bodyParser from 'body-parser'; 
import router2 from './router/router2.js';
const app = express();

/** middlewares */
app.use(express.json());
app.use(cors());
app.use(morgan('tiny'));
app.disable('x-powered-by'); // less hackers know about our stack

router.use(bodyParser.json());
const port = process.env.PORT || 8080;

/** Https get req */

app.get('/', (req,res)=>{
  res.status(201).json("home get request")
})





/** api routes */
app.use('/api' , router )
app.use("/api", router2);

/** start server */


connect().then(()=>{
  try {
    app.listen(port, () =>{
      console.log(`server connected to https://localhost:${port}`);
    });
  } catch (error) {
    console.log('cannot connect to the server')
  }
}).catch(error => {
  console.log("invalid database connection.... !")
})




