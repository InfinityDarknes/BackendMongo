const { default: mongoose } = require("mongoose");

const tareaSchema = mongoose.Schema({
    user:{
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        ref: 'User'
    },
    descripcion: {
    type: String,
    required: [true,'Por favor teclea una descripcion']
    },
}, {
    timestamps: true
})

module.exports = mongoose.model('Tarea', tareaSchema)