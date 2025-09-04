"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
require('dotenv').config();
exports.default = {
    port: process.env.PORT,
    pepper: process.env.PEPPER,
    jwt_secret: process.env.JWT_SECRET
};
