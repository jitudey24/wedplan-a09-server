
/**
 * Better Auth configuration for WedPlan.
 * Authentication is handled only by Express Backend.
 */

import { betterAuth } from "better-auth";
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import { admin, jwt } from "better-auth/plugins";

const ROLES = ["customer", "vendor", "admin"];

let auth = null;

const isProd = process.env.NODE_ENV === "production";

// ---------------------------------------
// Helpers
// ---------------------------------------

const cleanUrl = (url) =>
  url?.trim().replace(/\/+$/, "") || undefined;

const getAllowedOrigins = () => {
  const origins = [
    process.env.CLIENT_URL,
    process.env.FRONTEND_URL,
    process.env.VERCEL_CLIENT_URL,

    "https://wedplan-a09-client.vercel.app",

    "http://localhost:3000",
    "http://127.0.0.1:3000",
  ]
    .filter(Boolean)
    .map(cleanUrl);

  return [...new Set(origins)];
};

// ---------------------------------------
// Environment validation
// ---------------------------------------

const validateEnv = () => {
  const required = [
    "BETTER_AUTH_SECRET",
    "BETTER_AUTH_URL",
    "CLIENT_URL",
  ];

  const missing = required.filter(
    (key) => !process.env[key]?.trim()
  );

  if (missing.length) {
    throw new Error(
      `Missing environment variables: ${missing.join(", ")}`
    );
  }

  if (process.env.BETTER_AUTH_SECRET.length < 32) {
    throw new Error(
      "BETTER_AUTH_SECRET must be at least 32 characters."
    );
  }

  if (
    process.env.GOOGLE_CLIENT_SECRET &&
    process.env.BETTER_AUTH_SECRET ===
      process.env.GOOGLE_CLIENT_SECRET
  ) {
    throw new Error(
      "Auth secret and Google secret must be different."
    );
  }
};

// ---------------------------------------
// Initialize Better Auth
// ---------------------------------------

const initAuth = (db, client) => {
  if (auth) return auth;

  if (!db || !client) {
    throw new Error(
      "MongoDB database/client missing during Better Auth initialization."
    );
  }

  validateEnv();

  const trustedOrigins = getAllowedOrigins();

  const hasGoogle =
    Boolean(process.env.GOOGLE_CLIENT_ID) &&
    Boolean(process.env.GOOGLE_CLIENT_SECRET);

  auth = betterAuth({
    database: mongodbAdapter(db, {
      client,
      transaction: false,
    }),

    // Important: public FRONTEND URL.
    // OAuth callback will pass through Next.js rewrites.
    baseURL: cleanUrl(process.env.BETTER_AUTH_URL),

    secret: process.env.BETTER_AUTH_SECRET,

    trustedOrigins,

    advanced: {
      useSecureCookies: isProd,

      defaultCookieAttributes: {
        sameSite: "lax",
        secure: isProd,
        httpOnly: true,
      },
    },

    emailAndPassword: {
      enabled: true,
      minPasswordLength: 8,
    },

    session: {
      expiresIn: 60 * 60 * 24 * 7,
      updateAge: 60 * 60 * 24,
    },

    user: {
      additionalFields: {
        vendorApproved: {
          type: "boolean",
          required: false,
          defaultValue: false,
          input: false,
        },

        vendorReviewStatus: {
          type: "string",
          required: false,
          input: false,
        },

        businessName: {
          type: "string",
          required: false,
          input: false,
        },

        studioName: {
          type: "string",
          required: false,
          input: false,
        },

        phone: {
          type: "string",
          required: false,
          input: false,
        },

        location: {
          type: "string",
          required: false,
          input: false,
        },

        bio: {
          type: "string",
          required: false,
          input: false,
        },

        website: {
          type: "string",
          required: false,
          input: false,
        },
      },
    },

    ...(hasGoogle
      ? {
          socialProviders: {
            google: {
              clientId: process.env.GOOGLE_CLIENT_ID,
              clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            },
          },
        }
      : {}),

    plugins: [
      admin({
        defaultRole: "customer",
        adminRoles: ["admin"],
      }),

      jwt(),
    ],
  });

  return auth;
};

// ---------------------------------------
// Get Auth
// ---------------------------------------

const getAuth = () => {
  if (!auth) {
    throw new Error(
      "Better Auth is not initialized. Call initAuth() first."
    );
  }

  return auth;
};

export {
  initAuth,
  getAuth,
  getAllowedOrigins,
  ROLES,
};
