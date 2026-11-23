import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadTypeSafeKey } from "./typesafeKey";

function envFile(contents: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "typesafe-key-"));
  const file = path.join(dir, ".env");
  fs.writeFileSync(file, contents);
  return file;
}

test("reads the key from .env", () => {
  delete process.env.TYPESAFE_API_KEY;
  assert.equal(loadTypeSafeKey(envFile('TYPESAFE_API_KEY="from-file"\n')), "from-file");
});

test("an exported but empty key does not hide the one in .env", () => {
  process.env.TYPESAFE_API_KEY = "";
  assert.equal(loadTypeSafeKey(envFile('TYPESAFE_API_KEY="from-file"\n')), "from-file");
});

test("a key already set in the environment wins over .env", () => {
  process.env.TYPESAFE_API_KEY = "from-env";
  assert.equal(loadTypeSafeKey(envFile('TYPESAFE_API_KEY="from-file"\n')), "from-env");
});

test("no key anywhere returns empty", () => {
  delete process.env.TYPESAFE_API_KEY;
  assert.equal(loadTypeSafeKey(envFile("OTHER=1\n")), "");
});
