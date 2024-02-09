const jwt = require('jsonwebtoken');
require('dotenv').config();
const secretKey = process.env.SECRET_KEY; 

function createToken(username) {
    return jwt.sign({ username }, secretKey, { expiresIn: '8h' });
}

const verifyToken = (req, res, next) => {
    let token = req.headers['authorization'];
    token = token.replace("Bearer ", "");
    if (!token) {
        return res.status(403).json({ message: 'Token is not provided' });
    }
    
    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized' });
        }
        req.decoded = decoded;
        next();
    });
};

module.exports = {verifyToken, createToken}