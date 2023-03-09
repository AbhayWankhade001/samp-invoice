// import bcrypt from "bcrypt";

// import mongoose from "mongoose";

// export const UserSchema = new mongoose.Schema({
//   username: {
//     type: String,
//     required: [true, "Please provide a unique username"],
//     unique: [true, "Username already exists"],
//   },
//   password: {
//     type: String,
//     required: [true, "Please provide a password"],
//   },
//   email: {
//     type: String,
//     required: [true, "Please provide a unique email"],
//     unique: [true, "Email already exists"],
//   },
//   firstName: {
//     type: String,
//     required: [true, "Please provide your first name"],
//   },
//   lastName: {
//     type: String,
//     required: [true, "Please provide your last name"],
//   },
//   phoneNumber: {
//     type: String,
//     required: [true, "Please provide a valid phone number"],
//   },
//   address: {
//     type: String,
//     required: [true, "Please provide your address"],
//   },
//   profileImageUrl: {
//     type: String,
//     default: "",
//   },
// });

// // comparePassword method for user schema
// UserSchema.methods.comparePassword = async function (enteredPassword) {
//   return await bcrypt.compare(enteredPassword, this.password);
// };




// export default mongoose.model("User", UserSchema);
import bcrypt from "bcrypt";
import mongoose from "mongoose";

const { Schema } = mongoose;

export const UserSchema = new Schema({
  username: {
    type: String,
    required: [true, "Please provide a unique username"],
    unique: [true, "Username already exists"],
  },
  password: {
    type: String,
    required: [true, "Please provide a password"],
  },
  email: {
    type: String,
    required: [true, "Please provide a unique email"],
    unique: [true, "Email already exists"],
  },
  firstName: {
    type: String,
    required: [true, "Please provide your first name"],
  },
  lastName: {
    type: String,
    required: [true, "Please provide your last name"],
  },
  phoneNumber: {
    type: String,
    required: [true, "Please provide a valid phone number"],
  },
  address: {
    type: String,
    required: [true, "Please provide your address"],
  },
  profileImageUrl: {
    type: String,
    default: "",
  },
});

// comparePassword method for user schema
UserSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

export default mongoose.model("User", UserSchema);

