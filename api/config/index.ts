require('dotenv').config();

export default{
	port: process.env.PORT,
	pepper: process.env.PEPPER,
	jwt_secret: process.env.JWT_SECRET
}
