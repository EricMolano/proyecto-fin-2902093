import express from 'express'
import { userRegister , loginUser } from '../controllers/authController.js'

const authRouter = express.Router()

authRouter.post('/register' , userRegister)

authRouter.post('/login'  ,  loginUser)



export default authRouter