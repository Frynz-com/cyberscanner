// Lokale Entwicklung: .env.local / .env laden (in Produktion kommen Variablen aus der Laufzeitumgebung)
import { config } from "dotenv";

if (process.env.NODE_ENV !== "production") {
  config({ path: ".env.local", quiet: true });
  config({ path: ".env", quiet: true });
}
