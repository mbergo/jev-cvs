import { config as loadDotenv } from "dotenv";

/**
 * Loads TYPESAFE_API_KEY into process.env and returns it ("" when there is none).
 *
 * dotenv never overrides a variable that already exists, so a TYPESAFE_API_KEY exported
 * as empty in the launching shell would silently hide the one in .env. When the variable
 * is empty after the normal load, .env is read again with override.
 */
export function loadTypeSafeKey(envPath = ".env"): string {
  loadDotenv({ path: envPath, quiet: true });
  if (!process.env.TYPESAFE_API_KEY?.trim()) {
    loadDotenv({ path: envPath, override: true, quiet: true });
  }
  return process.env.TYPESAFE_API_KEY?.trim() ?? "";
}
