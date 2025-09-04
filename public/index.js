"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const client_1 = require("@prisma/client");
const crypto_1 = require("crypto");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const config_1 = __importDefault(require("./config"));
const app = (0, express_1.default)();
const PORT = 3000;
const prisma = new client_1.PrismaClient();
app.use(express_1.default.json());
app.listen(PORT, () => {
    console.log("Server is running on PORT:", PORT);
});
// 以下を追加
app.get("/scores", VerifyToken, async (req, res) => {
    const scores = await prisma.score.findMany({
        orderBy: [
            {
                score: 'desc'
            }
        ],
        include: { user: true },
        take: 5,
    });
    res.json(scores);
});
// 以下を追加
app.post("/scores", VerifyToken, async (req, res) => {
    const { score } = req.body;
    const user = await GetUser(req);
    const result = await prisma.score.create({
        data: {
            userId: user.id,
            score: score
        },
    });
    if (result != null) {
        return res.json({ status_code: 200 });
    }
    else {
        return res.json({ status_code: 500 });
    }
});
//
app.post("/users/new", async (req, res) => {
    const name = req.body.name;
    const salt = (0, crypto_1.randomBytes)(8).toString('hex');
    const password = (0, crypto_1.createHash)('sha256').update(req.body.password + salt + config_1.default.pepper, 'utf8').digest('hex');
    const result = await prisma.user.create({
        data: {
            name,
            password,
            salt
        },
    });
    res.json(result);
});
//
app.post("/users/login", async (req, res) => {
    const name = req.body.name;
    const saltres = await prisma.user.findFirst({
        where: {
            name: name
        }
    });
    if (saltres != null) {
        const salt = saltres.salt;
        const password = (0, crypto_1.createHash)('sha256').update(req.body.password + salt + config_1.default.pepper, 'utf8').digest('hex');
        const result = await prisma.user.findFirst({
            where: {
                name: name,
                password: password
            }
        });
        if (result != null) {
            const token = jsonwebtoken_1.default.sign({ name: name }, config_1.default.jwt_secret || "", { expiresIn: '1h' });
            res.json({ login_status: "success", token: token });
        }
        else {
            res.json({ login_status: "faild" });
        }
    }
    else {
        res.json({ login_status: "No User found." });
    }
});
async function VerifyToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    if (authHeader !== undefined) {
        if (authHeader.split(" ")[0] === "Bearer") {
            try {
                const token = jsonwebtoken_1.default.verify(authHeader.split(" ")[1], config_1.default.jwt_secret || "");
                const result = await prisma.user.findFirst({
                    where: {
                        name: token.name,
                    }
                });
                if (result != null && token.exp && Date.now() < token.exp * 1000) {
                    console.log(token);
                    next();
                }
                else {
                    res.json({ error: "auth error" });
                }
            }
            catch (e) {
                //tokenエラー
                console.log(e.message);
                res.json({ error: e.message });
            }
        }
        else {
            res.json({ error: "header format error" });
        }
    }
    else {
        res.json({ error: "header error" });
    }
}
async function GetUser(req) {
    const authHeader = req.headers["authorization"];
    if (authHeader !== undefined) {
        if (authHeader.split(" ")[0] === "Bearer") {
            try {
                const token = jsonwebtoken_1.default.verify(authHeader.split(" ")[1], config_1.default.jwt_secret || "");
                const result = await prisma.user.findFirst({
                    where: {
                        name: token.name,
                    }
                });
                if (result != null && token.exp && Date.now() < token.exp * 1000) {
                    return result;
                }
            }
            catch (e) {
                console.log(e.message);
            }
        }
    }
    return {};
}
exports.default = app;
