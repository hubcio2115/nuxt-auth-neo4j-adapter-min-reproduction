import { createEnv } from "@t3-oss/env-nuxt";
import { z } from "zod";

export const env = createEnv({
  server: {
    // DATABASE_URL: z.string().url(),
    /**
     * You can generate one with `openssl rand -base64 32`
     */
    NUXTAUTH_SECRET: z.string(),

    DB_USERNAME: z.string(),
    DB_PASSWORD: z.string(),

    GOOGLE_CLIENT_ID: z.string(),
    GOOGLE_CLIENT_SECRET: z.string(),
  },
  client: {
    /**
     * The URL of your deployed app (used for origin Check in production)
     */
    NUXT_PUBLIC_NUXTAUTH_URL: z.string().url().optional(),
  },
});
