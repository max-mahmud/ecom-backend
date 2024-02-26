
const jwt = require('jsonwebtoken');

module.exports.authMiddleware = async (req, res, next) => {
    // Get the authorization header
    const authHeader = req.headers['authorization'];

    if (!authHeader) {
        return res.status(401).json({ error: 'Authorization header is missing' });
    }

    // Split the header to get the token part
    const tokenParts = authHeader.split(' ');

    if (tokenParts.length !== 2 || tokenParts[0] !== 'Bearer') {
        return res.status(401).json({ error: 'Invalid authorization header format' });
    }

    const accessToken = tokenParts[1];

    try {
        const decodedToken = await jwt.verify(accessToken, process.env.SECRET);
        req.role = decodedToken.role;
        req.id = decodedToken.id;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
}