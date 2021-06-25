import express from 'express';
import mongodb from 'mongodb';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();
const PORT = process.env.PORT || 3000;
const DBURL = process.env.DBURL;
const SECRET_ACCSES = process.env.SECRET_ACCSES;
const SECRET_REFRESH = process.env.SECRET_REFRESH;
const app = express();
app.use(express.json());
const MongoClient = mongodb.MongoClient;


async function saveToken(user, refreshToken,accsessToken) {
    const collectionAuthorization = app.locals.collection.authorization;
    const tokenData = await collectionAuthorization.findOne({ user })
    if (tokenData) {
        collectionAuthorization.findOneAndUpdate({ user }, { $set: { refreshToken,accsessToken } });
        return
    }
    collectionAuthorization.insertOne({ user, refreshToken,accsessToken });
}



const generateToken = (user) => {
    const payload = { user };
    const TTL = Math.round(30 + Math.random() * 30);

    const accsessToken = jwt.sign(payload, SECRET_ACCSES, { expiresIn: '29d'})
    const refreshToken = jwt.sign(payload, SECRET_REFRESH, { expiresIn: '30d' })
    saveToken(user, refreshToken, accsessToken);
    return {
        accsessToken,
        acssesTTL: `${TTL}s`,
        refreshToken,
        refreshTTL: '30d'
    }
}


app.post('/sign_up', async (req, res) => {
    try {
        if (!req.body.email && !req.body.password) return res.status(400).json({ message: "Enter email and password" });
        if (!req.body.email) return res.status(400).json({ message: "Enter email" });
        if (!req.body.password) return res.status(400).json({ message: "Enter password" });

        const { email, password } = req.body;
        const collection = app.locals.collection;

        const chekUser = await collection.findOne({ email: email });
        if (chekUser) return res.json({ message: "email is not unique" });

        const heshPassword = bcrypt.hashSync(password, 7);
        const user = { email: email, password: heshPassword };
        collection.insertOne(user, (err, result) => {
            if (err) {
                console.log(err);
                res.sendStatus(400).json({ message: 'Registration error2' })
            }
            res.status(200).json({ message: "user created successfully" });
        });

    } catch (error) {
        console.log(error);
        res.status(400).json({ message: 'Registration error' })
    }
})

app.post('/login', async (req, res) => {
    try {
        const collectionUser = app.locals.collection.user;
        const { email, password } = req.query;
        const user = await collectionUser.findOne({ email: email })
        if (!user) {
            return res.status(400).json({ message: 'User not found' })
        }
        const validPassword = bcrypt.compareSync(password, user.password)
        if (!validPassword) {
            return res.status(400).json({ message: 'Invalid password' })
        }
        const token = generateToken(user.email);
        return res.status(200).json(token);

    } catch (error) {
        console.log(error);
        res.status(400).json({ message: 'Login error' })
    }

})



app.post('/refresh', async (req, res) => {
    try {
        const collectionAuthorization = app.locals.collection.authorization;
        const refreshToken = req.headers.authorization.split(' ')[1];
        if (!refreshToken) {
            return res.status(400).json({ message: 'specify the refresh token' })
        }

       const decodedData = jwt.verify(refreshToken, SECRET_REFRESH);    
       const tokenData =  await collectionAuthorization.findOne({ user:decodedData.user })
       console.log(tokenData.refreshToken === refreshToken );
       if (tokenData.refreshToken !== refreshToken ) return res.status(401).json({ message: 'Unauthorised' })

        const token = generateToken(decodedData.user);
        return res.status(200).json(token);

    } catch (error) {
        console.log(error);
        res.status(400).json({ message: 'Login error' })
    }

})



app.get('/me[0-9]', async function (req, res) {

    try {
        const collectionAuthorization = app.locals.collection.authorization;
        const num = +req.path.substr(-1, 1);
        const accsesToken = req.headers.authorization.split(' ')[1];
        if (!accsesToken) {
            return res.status(400).json({ message: 'specify the access token' })
        }

        const decodedData = jwt.verify(accsesToken, SECRET_ACCSES);    
        const tokenData = await collectionAuthorization.findOne({ user:decodedData.user });
        if (tokenData.accsessToken !== accsesToken ) return res.status(401).json({ message: 'Unauthorised' });
        
        const message = {
            "request_num": num,
            "data": {
                "username": decodedData.user
            }
        }
        res.status(200).json(message);
    } catch (error) {
        res.status(401).json({ message: 'Unauthorised' })
    }
});


const start = () => {
    try {
        MongoClient.connect(DBURL, { useUnifiedTopology: true }, (err, client) => {
            if (err) {
                return (console.log(err));
            }
            app.locals.collection = {
                user: client.db("JWT").collection("Users"),
                authorization: client.db("JWT").collection("Authorization")
            }
        }
        )
        app.listen(PORT, () => console.log('server started on port 3000 '));
    } catch (error) {
        console.log(error);
    }
}

start()
