import pkg from 'colors';
const { colors} = pkg;
import dotenv from 'dotenv';
import express from 'express';
import pruebaRouter from './routes/pruebaRoutes.js';
import authRouter from './routes/authRouter.js';
import connectDB from './config/db.js'


dotenv.config()

connectDB()

//crear el objeto 
//aplicacion de expresion 
const app =express()

app.use(express.json())


const PORT =process.env.PORT


app.use('/api/prueba/' , pruebaRouter)
app.use('/api/auth', authRouter)

//crear servidor express
app.listen( PORT , () => {
    console.log(`Servidor ejecutando:${ PORT }`.bgGreen.red.bold)
})


