const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const asyncHandler = require('express-async-handler')
const User = require('../models/usersModel')

const crearUser = asyncHandler( async (req, res) =>{
    //Desestructuramos el body
    const { name , email , password } = req.body
    
    if(!name || !email || !password) {
        res.status(400)
        throw new Error('Faltan datos')
    }
    //Verificar si ya existe el usuario
    const userExiste = await User.findOne({email})
    if(userExiste) {
        res.status(400)
        throw new Error('Este Usuario ya existe en la base de datos')
    }

    //Hacemos el HASH al password
    const salt = await bcrypt.genSalt(10)
    const hashedPassword = await bcrypt.hash(password, salt)

    //Crear el usuario
    const user = await User.create({
        name,
        email,
        password: hashedPassword
    })
    if (user) {
        res.status(201).json({
            _id: user.id,
            name: user.name,
            email: user.email
        })
    } else{
        res.status(400)
            throw new Error('no se pudieron guardar los datos')
        
    }
    res.status(201).json({ message: 'Crear Usuario'})
})

const loginUser = asyncHandler( async (req, res) =>{
    const {email, password} = req.body

    // verificar que exista un usario con ese email
    const user = await User.findOne({email})

    //Si el usurio existe verificamos el password
    if (user && (await bcrypt.compare(password, user.password))) {
        res.status(200).json({
            _id: user.id,
            name: user.name,
            email: user.email,
            token: generarToken(user.id)
        })        
    }
    else{
        res.status(400)
        throw new Error('Credenciales incorrectas')
    }

    res.status(200).json({ message: 'Login Usuario'})
})

const datosUser = asyncHandler( async (req, res) =>{
    res.status(200).json(req.user)
})

//Funcion para generar el token
const generarToken = (id_usuario) => {
    return jwt.sign({ id_usuario }, process.env.JWT_SECRET, {
        expiresIn: '30d'
    })
}

module.exports = {
    crearUser,
    loginUser,
    datosUser
}