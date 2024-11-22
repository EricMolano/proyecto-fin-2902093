import mongoose from "mongoose";


const UserSchema = mongoose.Schema({
    firstName:{type: String, require:[true , "Nombre requerido"]},
    lastName:{type: String, require:[true , "Apellido requerido"]},
    email:{type: String,    require:[true , "UserName requerido"] ,
                            unique : [true , "UserName no debe ser repetido"]},
    password:{type: String, require:[true , "Contraseña requerido"]},
    isAdmin:{type: Boolean, require:[true , "isAdmin requerido"] , default : false },

},
{
    timestamps: true 
}
)



const   User =  mongoose.model("User" , UserSchema) 

export default User 