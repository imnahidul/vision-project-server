
import jwt from "jsonwebtoken";
import User from "../models/User.js";

const authMiddleware = async (req , res, next) =>{

    try{
        const token = req.headers.authorization?.split(" ")[1];
        if (!token){
            return res.status(401).json({success: false, message: "No token provided"});
        }
        const decoded =jwt.verify(token, process.env.JWT_SECRET);
        if (!decoded){
            return res.status(401).json({success: false, message: "Invalid token"});
        }

        const user = await User.findById({_id: decoded.id});
        if(!user){
            return res.status(401).json({success: false, message:"User not found"});
        }
        req.user = user;
        next();
    }catch(error){
        console.error("Enter in authMiddleware:", error);
        return res.status(500).json({success: false, message: "Internal server error in middleware"});
    }

}

export default authMiddleware;

// ...existing code...
// import jwt from "jsonwebtoken";
// import User from "../models/User.js";

// const authMiddleware = async (req , res, next) =>{

//     try{
//         // allow preflight through
//         if (req.method === 'OPTIONS') return next();

//         // robust token extraction: "Bearer <token>", raw token, cookie or query
//         let token = null;
//         const authHeader = req.headers.authorization || req.headers.Authorization;
//         if (authHeader) {
//             const parts = authHeader.split(' ').filter(Boolean);
//             if (parts.length === 2 && /bearer/i.test(parts[0])) token = parts[1];
//             else token = parts.join(' ');
//         }

//         if (!token && req.cookies) token = req.cookies.token;
//         if (!token && req.query) token = req.query.token;

//         if (!token){
//             return res.status(401).json({success: false, message: "No token provided"});
//         }

//         let decoded;
//         try {
//             decoded = jwt.verify(token, process.env.JWT_SECRET);
//         } catch (err) {
//             console.error("JWT verify error:", err);
//             return res.status(401).json({success: false, message: "Invalid or expired token"});
//         }

//         const user = await User.findById(decoded.id);
//         if(!user){
//             return res.status(401).json({success: false, message:"User not found"});
//         }
//         req.user = user;
//         next();
//     }catch(error){
//         console.error("Enter in authMiddleware:", error);
//         return res.status(500).json({success: false, message: "Internal server error in middleware"});
//     }

// }

// export default authMiddleware;
// // ...existing code...