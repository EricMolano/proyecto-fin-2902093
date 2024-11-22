import mongoose from "mongoose"
import User from "../entities/user.entity.js"
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export const userRegister = async(req , res)=> {

    const { firstName,
            lastName,
            email,
            password,
            isAdmin
    } = req.body 

    const vUser = await User.findOne({email: req.body.email})
        if (vUser) { 
            res.status(400).json({
                                    message: "Ya exite el usuario"
                                })
        }else {  

            const sal = await bcrypt.genSalt(10)
            const bcPassword = await bcrypt.hash(password, sal)

            const newUser = await User.create({firstName,
                                                lastName,
                                                email,
                                                password : bcPassword,
                                                isAdmin})
                res.status(201).json(newUser)
    }}



export const loginUser = async(req , res)=> {
    const {email , password} = req.body  

    // encontrar al user por email
    const user= await User.findOne({email})
    // si el user existe, comparar los hash
    //hash(request, mongo)
    if(user) {
        if(await bcrypt.compare(password, user.password)) {
            res.status(200).json({
                username: user.email,
                id: user._id,
                token: generarToken(user._id),
            });
        }else{
            res.status(404).json({
                message: "Usuario no encontrado"})
        }
    }
}

// crear una funcion que retorne el token
const generarToken = (id) => {
    return jwt.sign({id}, process.env.JWT_SECRET,
    {
        expiresIn: '30d'
    } )
}
    