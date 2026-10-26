/** Plattform-Administrator ernennen: pnpm tsx scripts/grant-admin.ts admin@cybersafe24.de */
import "../worker/load-env";
import { createServiceClient } from "../worker/deps";

const email = process.argv[2];
if (!email) throw new Error("E-Mail angeben");
const db = createServiceClient(process.env as Record<string, string | undefined>);
const { data } = await db.auth.admin.listUsers({ perPage: 1000 });
const user = data.users.find((u) => u.email === email.toLowerCase());
if (!user) throw new Error("Nutzer nicht gefunden");
await db.from("platform_admins").upsert({ user_id: user.id });
await db.from("audit_logs").insert({ actor_type: "system", action: "admin.granted", target_type: "user", target_id: user.id });
console.log(`Admin-Rechte vergeben an ${email}`);
