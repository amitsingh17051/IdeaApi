require('dotenv').config()
const express = require("express");
const path = require("path");
var bodyParser = require('body-parser')
const mongoose = require('mongoose');
mongoose.set('strictQuery', false);
const app = express();
const port = process.env.PORT || "8000";



const cors = require('cors');
app.use(cors({
  origin: '*'
}));

mongoose.connect('mongodb+srv://root:root@cluster0.iagif.mongodb.net/?retryWrites=true&w=majority');
mongoose.Promise = global.Promise;

app.use(bodyParser.urlencoded({ extended: true }))
// parse application/json
app.use(bodyParser.json())


app.use(express.static('public'));
app.use(express.json());
app.use('/api',require('./router/api'));




app.listen(port, () => {
  console.log(`Listening to requests on http://localhost:${port}`);
});