/**
 * Better Auth configuration for WedPlan.
 *
 * Uses the existing MongoDB connection.
 * Authentication is handled ONLY by Express Backend.
 *
 * Roles: customer | vendor | admin
 */

import { betterAuth } from "better-auth";
import { mongodbAdapter } from "@better-auth/mongo-adapter";
import { admin, jwt } from "better-auth/plugins";

const ROLES = ["customer", "vendor", "admin"];

let auth = null;

const isProd = process.env.NODE_ENV === "production";

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

// Remove trailing slash so "https://x.app/" matches "https://x.app"
const cleanUrl = (url) => (url ? url.trim().replace(/\/+$/, "") : url);

// Exported so Express CORS can use the exact same list.
const getAllowedOrigins = () => {
  const origins = [
    process.env.CLIENT_URL,
    process.env.FRONTEND_URL,
    process.env.VERCEL_CLIENT_URL,
    process.env.BETTER_AUTH_URL, // backend itself (same-origin / rewrite setups)

    // Known deployments
    "https://wedplan-a09-client.vercel.app",
    "https://wedplan-client-rho.vercel.app",

    // Local development
    "http://localhost:3000",
    "http://127.0.0.1:3000",
  ]
    .filter(Boolean)
    .map(cleanUrl);

  return [...new Set(origins)];
};

// ─────────────────────────────────────────────
// Environment Validation
// ─────────────────────────────────────────────

const validateEnv = () => {
  const required = ["BETTER_AUTH_SECRET", "BETTER_AUTH_URL", "CLIENT_URL"];

  const missing = required.filter((key) => !process.env[key]);

  if (missing.length) {
    throw new Error(`Missing environment variables: ${missing.join(", ")}`);
  }

  // Only compare when Google secret actually exists
  // (undefined === undefined used to throw here).
  if (
    process.env.GOOGLE_CLIENT_SECRET &&
    process.env.BETTER_AUTH_SECRET === process.env.GOOGLE_CLIENT_SECRET
  ) {
    throw new Error(
      "BETTER_AUTH_SECRET and GOOGLE_CLIENT_SECRET must be different.",
    );
  }
};

// ─────────────────────────────────────────────
// Initialize Auth
// ─────────────────────────────────────────────

const initAuth = (db, client) => {
  if (auth) return auth;

  if (!db || !client) {
    throw new Error(
      "MongoDB database/client missing during Better Auth initialization.",
    );
  }

  validateEnv();

  const trustedOrigins = getAllowedOrigins();

  const hasGoogle =
    process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET;

  auth = betterAuth({
    database: mongodbAdapter(db, {
      client,
      transaction: false,
    }),

    baseURL: cleanUrl(process.env.BETTER_AUTH_URL),
    secret: process.env.BETTER_AUTH_SECRET,

    trustedOrigins,

    advanced: {
      // Cross-domain cookies (frontend and backend on different Vercel domains)
      useSecureCookies: isProd,
      defaultCookieAttributes: {
        sameSite: isProd ? "none" : "lax",
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

        // Admin review decision: "pending" | "approved" | "rejected".
        vendorReviewStatus: {
          type: "string",
          required: false,
          input: false,
        },

        businessName: { type: "string", required: false, input: false },
        studioName: { type: "string", required: false, input: false },
        phone: { type: "string", required: false, input: false },
        location: { type: "string", required: false, input: false },
        bio: { type: "string", required: false, input: false },
        website: { type: "string", required: false, input: false },
      },
    },

    // Enable Google only if credentials exist
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

// ─────────────────────────────────────────────
// Get Auth
// ─────────────────────────────────────────────

const getAuth = () => {
  if (!auth) {
    throw new Error("Better Auth is not initialized. Call initAuth() first.");
  }

  return auth;
};

// ─────────────────────────────────────────────
// EXPORTS
// ─────────────────────────────────────────────

export { initAuth, getAuth, getAllowedOrigins, ROLES };
