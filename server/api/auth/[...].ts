import Credentials from "@auth/core/providers/credentials";
import Google from "@auth/core/providers/google";
import type { AuthConfig } from "@auth/core/types";
import { NuxtAuthHandler } from "#auth";
import neo4j from "neo4j-driver";
import { verify } from "argon2";
import { env } from "~/env.mjs";
import { Neo4jAdapter } from "@auth/neo4j-adapter";

const driver = neo4j.driver(
  "bolt://localhost",
  neo4j.auth.basic(env.DB_USERNAME, env.DB_PASSWORD),
);

export const neo4jSession = driver.session();

const runtimeConfig = useRuntimeConfig();

export const authOptions: AuthConfig = {
  secret: env.NUXTAUTH_SECRET,
  adapter: Neo4jAdapter(neo4jSession),
  trustHost: true,

  providers: [
    Google({
      clientId: env.GOOGLE_CLIENT_ID,
      clientSecret: env.GOOGLE_CLIENT_SECRET,
    }),
    Credentials({
      name: "credentials",
      credentials: {
        name: {},
        password: {},
      },

      async authorize(credentials) {
        const { name, password } = credentials;

        if (typeof name !== "string" || typeof password !== "string")
          throw new Error("Provided credentials couldn't be parsed.");

        const query = await neo4jSession.run(
          "MATCH (u:User { username: $username }) RETURN u.id, u.username, u.email, u.password",
          { username: name },
        );

        if (!query.records[0]?.toObject()) throw new Error("User not found.");

        const userPassword = query.records[0].get("u.password");
        const arePasswordSame = await verify(userPassword, password);
        if (!arePasswordSame) throw new Error("Wrong password.");

        /** @type {import("~/lib/validators/user").User} */
        const user = {
          id: query.records[0]?.get("u.id"),
          name: query.records[0]?.get("u.username"),
          email: query.records[0]?.get("u.email"),
        };

        return user;
      },
    }),
  ],
};

export default NuxtAuthHandler(authOptions, runtimeConfig);
