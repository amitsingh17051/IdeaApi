const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// create student schema & model
const IdeaSchema = new Schema({
    name: {
        type: String,
    },
    userId: {
        type:String,
    },
    description: {
        type: String,
    },
    featuredImageKey: {
        type: String,
    }
});


const Idea = mongoose.model('idea',IdeaSchema);

module.exports = Idea;