
/**
 * WedPlan Authentication & Authorization Middleware
 *
 * Features:
 * 1. Better Auth session cookies (primary)
 * 2. Better Auth Bearer JWT (fallback)
 * 3. Latest user data from MongoDB
 * 4. Role-based authorization
 * 5. Vendor approval protection
 * 6. Blocked user protection
 */

import { fromNodeHeaders } from "better-auth/node";
import {
  createRemoteJWKSet,
  jwtVerify,
} from "jose";
import { ObjectId } from "mongodb";

import { getAuth } from "./auth.js";
import { getDB } from "../config/db.js";
import { sanitizeUser } from "../utils/helpers.js";

let jwks = null;

/* =====================================================
   ID HELPERS
===================================================== */

const normalizeUserId = (id) => {
  if (!id) return null;

  if (id instanceof ObjectId) {
    return id.toHexString();
  }

  return String(id);
};

const buildUserIdQuery = (userId) => {
  const normalizedId = normalizeUserId(userId);

  if (!normalizedId) {
    throw new Error("Invalid user ID.");
  }

  const conditions = [
    { id: normalizedId },
  ];

  if (ObjectId.isValid(normalizedId)) {
    conditions.push({
      _id: new ObjectId(normalizedId),
    });
  }

  return { $or: conditions };
};

/* =====================================================
   JWT CONFIGURATION
===================================================== */

const getJWKSet = () => {
  if (!jwks) {
    const baseURL = process.env.BETTER_AUTH_URL;

    if (!baseURL) {
      throw new Error("BETTER_AUTH_URL is missing.");
    }

    const jwksURL = new URL(
      "/api/auth/jwks",
      baseURL,
    );

    jwks = createRemoteJWKSet(jwksURL);
  }

  return jwks;
};

/* =====================================================
   VERIFY BEARER TOKEN
===================================================== */

const verifyBearerToken = async (token) => {
  const baseURL = process.env.BETTER_AUTH_URL;

  if (!baseURL) {
    throw new Error("BETTER_AUTH_URL is missing.");
  }

  const issuer = baseURL.replace(/\/+$/, "");

  const { payload } = await jwtVerify(
    token,
    getJWKSet(),
    {
      issuer,
      audience: issuer,
    },
  );

  return payload;
};

/* =====================================================
   CHECK BLOCKED USER
===================================================== */

const isUserBlocked = (user) => {
  if (user?.banned !== true) {
    return false;
  }

  if (!user.banExpires) {
    return true;
  }

  const expiresAt = new Date(
    user.banExpires,
  ).getTime();

  if (Number.isNaN(expiresAt)) {
    return true;
  }

  return expiresAt > Date.now();
};

/* =====================================================
   AUTHENTICATE USER
===================================================== */

const authenticateUser = async (req, res, next) => {
  try {
    const auth = getAuth();

    let userId = null;
    let authenticationMethod = null;

    /* -------------------------------------
       1. BETTER AUTH SESSION
    ------------------------------------- */

    try {
      const session = await auth.api.getSession({
        headers: fromNodeHeaders(req.headers),
      });

      if (session?.user?.id) {
        userId = normalizeUserId(
          session.user.id,
        );

        authenticationMethod = "session";
      }
    } catch (error) {
      console.error(
        "Better Auth session error:",
        error.message,
      );
    }

    /* -------------------------------------
       2. BEARER JWT FALLBACK
    ------------------------------------- */

    if (!userId) {
      const authHeader =
        req.headers.authorization || "";

      if (authHeader.startsWith("Bearer ")) {
        const token = authHeader
          .slice(7)
          .trim();

        if (token) {
          try {
            const payload =
              await verifyBearerToken(token);

            if (payload.sub) {
              userId = normalizeUserId(
                payload.sub,
              );

              authenticationMethod = "bearer";
            }
          } catch (error) {
            console.error(
              "Bearer JWT verification failed:",
              error.message,
            );
          }
        }
      }
    }

    /* -------------------------------------
       3. CHECK AUTHENTICATION
    ------------------------------------- */

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: "Unauthorized. Please log in first.",
      });
    }

    /* -------------------------------------
       4. LOAD LATEST USER FROM DATABASE
    ------------------------------------- */

    const db = getDB();

    const dbUser = await db
      .collection("user")
      .findOne(buildUserIdQuery(userId));

    console.log("AUTH DEBUG:", {
      authenticationMethod,
      userId,
      dbUserFound: Boolean(dbUser),
      role: dbUser?.role,
      vendorApproved: dbUser?.vendorApproved,
    });

    if (!dbUser) {
      return res.status(401).json({
        success: false,
        message: "User account not found.",
      });
    }

    /* -------------------------------------
       5. CHECK BLOCKED ACCOUNT
    ------------------------------------- */

    if (isUserBlocked(dbUser)) {
      return res.status(403).json({
        success: false,
        blocked: true,
        message:
          "Your account has been blocked by the administrator. Please contact support.",
      });
    }

    /* -------------------------------------
       6. NORMALIZE USER
    ------------------------------------- */

    const id = normalizeUserId(
      dbUser.id || dbUser._id,
    );

    req.user = {
      ...dbUser,
      id,
    };

    next();

  } catch (error) {
    console.error(
      "Authentication middleware error:",
      error,
    );

    next(error);
  }
};

/* =====================================================
   ROLE AUTHORIZATION
===================================================== */

const requireRole = (...roles) => {
  return (req, res, next) => {
    const userRole = req.user?.role || "customer";

    if (!roles.includes(userRole)) {
      return res.status(403).json({
        success: false,
        message:
          `Access denied. Required role: ${roles.join(" or ")}.`,
      });
    }

    next();
  };
};

/* =====================================================
   VENDOR APPROVAL
===================================================== */

const requireVendorApproved = (req, res, next) => {
  console.log("VENDOR APPROVAL DEBUG:", {
    userId: req.user?.id,
    role: req.user?.role,
    vendorApproved: req.user?.vendorApproved,
  });

  if (req.user?.vendorApproved !== true) {
    return res.status(403).json({
      success: false,
      message:
        "Your vendor account has not been approved by an admin yet.",
    });
  }

  next();
};

/* =====================================================
   REUSABLE MIDDLEWARE
===================================================== */

const requireAuth = [
  authenticateUser,
];

const requireCustomer = [
  authenticateUser,
  requireRole("customer"),
];

const requireVendor = [
  authenticateUser,
  requireRole("vendor"),
  requireVendorApproved,
];

const requireAdmin = [
  authenticateUser,
  requireRole("admin"),
];

/* =====================================================
   EXPORTS
===================================================== */

export {
  isUserBlocked,
  authenticateUser,
  requireRole,
  requireVendorApproved,
  requireAuth,
  requireCustomer,
  requireVendor,
  requireAdmin,
  sanitizeUser,
};
