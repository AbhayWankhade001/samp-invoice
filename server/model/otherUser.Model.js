import mongoose from "mongoose";

export const FormSchema = new mongoose.Schema({
  bankAccount: {
    type: String,
    required: true
  },
  ifscCode: {
    type: String,
    required: true
  },
  // add any additional fields you need for the /form API
});


export default mongoose.model( 'Form',FormSchema);
