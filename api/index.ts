import * as dotenv from 'dotenv';
dotenv.config(); // .envファイルから環境変数を読み込む

import express, { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import cors from 'cors';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

const app = express();
const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const PEPPER = process.env.PEPPER;
const JWT_SECRET = process.env.JWT_SECRET;

// サーバー起動時に必須の環境変数が設定されているか確認
if (!PEPPER || !JWT_SECRET) {
    throw new Error("PEPPER and JWT_SECRET must be defined in .env");
}

app.use(express.json());
app.use(cors());

// --- トークン検証のためのミドルウェア ---
// Request型を拡張して、認証済みのユーザー情報を格納できるようにする
interface AuthRequest extends Request {
    user?: jwt.JwtPayload & { id: number; name: string };
}

// トークンを検証する関数
function VerifyToken(req: AuthRequest, res: Response, next: NextFunction) {
    const authHeader = req.headers["authorization"];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: "Access denied. No token provided." });
    }

    const token = authHeader.split(" ")[1];
    try {
        // トークンが正しい秘密鍵で署名されているか、有効期限は切れていないか検証
        const decoded = jwt.verify(token, JWT_SECRET!) as jwt.JwtPayload & { id: number; name: string };
        // 検証に成功したら、デコードされたユーザー情報をリクエストオブジェクトに追加
        req.user = decoded;
        next(); // 次の処理へ進む
    } catch (error) {
        return res.status(400).json({ message: "Invalid token." });
    }
}


// --- ユーザー関連のルート ---

// POST /users/new - 新規ユーザー登録
app.post("/users/new", async (req: Request, res: Response): Promise<void> => {
    try {
        const { name, password } = req.body;
        if (!name || !password) {
            res.status(400).json({ message: "Username and password are required." });
            return;
        }

        // 同じ名前のユーザーが既に存在するかチェック
        const existingUser = await prisma.user.findFirst({ where: { name } });
        if (existingUser) {
            res.status(409).json({ message: "User already exists." });
            return;
        }

        // パスワードをハッシュ化
        const salt = crypto.randomBytes(16).toString('hex');
        const hashedPassword = crypto.createHash('sha256').update(password + salt + PEPPER).digest('hex');

        const newUser = await prisma.user.create({
            data: { name, password: hashedPassword, salt },
        });

        res.status(201).json({ id: newUser.id, name: newUser.name, message: "User created successfully." });

    } catch (error) {
        console.error("User Registration Error:", error);
        res.status(500).json({ message: "User registration failed due to a server error." });
    }
});

// POST /users/login - ユーザーログイン
app.post("/users/login", async (req: Request, res: Response): Promise<void> => {
    try {
        const { name, password } = req.body;
        if (!name || !password) {
            res.status(400).json({ message: "Username and password are required." });
            return;
        }

        const user = await prisma.user.findFirst({ where: { name } });
        if (!user) {
            res.status(401).json({ message: "Invalid credentials." });
            return;
        }

        // 入力されたパスワードを、DBに保存されているsaltを使ってハッシュ化
        const hashedPassword = crypto.createHash('sha256').update(password + user.salt + PEPPER).digest('hex');

        // ハッシュ値が一致するかどうかで認証
        if (hashedPassword !== user.password) {
            res.status(401).json({ message: "Invalid credentials." });
            return;
        }
        
        // 認証成功後、ユーザー情報を含むJWTを生成
        const token = jwt.sign(
            { id: user.id, name: user.name }, // トークンに含める情報
            JWT_SECRET!,
            { expiresIn: '1h' } // 有効期限は1時間
        );

        res.status(200).json({ login_status: "success", token: token });

    } catch (error) {
        console.error("Login Error:", error);
        res.status(500).json({ message: "Login failed due to a server error." });
    }
});


// --- スコア関連のルート（要認証） ---

// GET /scores - ランキング上位5件をユーザー名付きで取得
app.get("/scores", VerifyToken, async (req: Request, res: Response): Promise<void> => {
    try {
        const scores = await prisma.score.findMany({
            orderBy: { score: 'desc' },
            take: 5,
            include: { // 投稿者の情報も一緒に取得
                author: {
                    select: {
                        name: true, // ユーザー名だけを選択
                    },
                },
            },
        });
        res.status(200).json(scores);
    } catch (error) {
        console.error("Get Scores Error:", error);
        res.status(500).json({ message: "Failed to retrieve scores." });
    }
});

// POST /scores - 新しいスコアを投稿し、ユーザーと紐付ける
app.post("/scores", VerifyToken, async (req: AuthRequest, res: Response): Promise<void> => {
    try {
        const { score } = req.body;
        if (typeof score !== 'number') {
            res.status(400).json({ message: "Score must be a number." });
            return;
        }

        // 検証済みトークンからユーザーIDを取得
        const userId = req.user?.id;
        if (!userId) {
            res.status(403).json({ message: "User ID not found in token." });
            return;
        }
        
        const newScore = await prisma.score.create({
            data: { 
                score: Math.floor(score),
                authorId: userId, // スコアとユーザーを紐付ける
            },
        });

        res.status(201).json(newScore);

    } catch (error) {
        console.error("Post Score Error:", error);
        res.status(500).json({ message: "Failed to save score." });
    }
});

// ★★★ ここから追加 ★★★
// GET / - ルートURLへのアクセスに対する応答
app.get("/", (req: Request, res: Response) => {
    res.status(200).json({ 
        message: "Welcome to the Stopwatch Game API!",
        endpoints: {
            register: "POST /users/new",
            login: "POST /users/login",
            getScores: "GET /scores (Auth Required)",
            postScore: "POST /scores (Auth Required)"
        }
     });
});
// ★★★ ここまで追加 ★★★


// サーバーを起動
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

