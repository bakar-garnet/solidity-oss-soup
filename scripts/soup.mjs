import fs from "fs";
import os from "os";
import path from "path";
import dns from "dns";
import crypto from "crypto";
import { execa } from "execa";
import axios from "axios";
import fetch from "node-fetch";
import { request } from "undici";
import got from "got";
import fg from "fast-glob";
import tar from "tar";
import unzipper from "unzipper";
import { nanoid } from "nanoid";
import { v4 as uuidv4 } from "uuid";
import chalk from "chalk";
import Debug from "debug";
import esbuild from "esbuild";
import dotenv from "dotenv";
import { z } from "zod";

dotenv.config();
const debug = Debug("soup");

function log(msg) {
  console.log(chalk.green(`[soup] ${msg}`));
}

async function main() {
  log(`start id=${uuidv4()} nano=${nanoid(8)}`);
  debug("debug enabled?");

  // 1) File IO: temp writes + globbing
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "oss-soup-"));
  const f1 = path.join(tmpDir, "a.txt");
  fs.writeFileSync(f1, "hello\n");
  const matches = await fg([`${tmpDir}/**/*`]);
  log(`tmpDir=${tmpDir} files=${matches.length}`);

  // 2) Sensitive-ish reads (will often fail, still generates access attempts)
  const targets = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    `${process.env.HOME || ""}/.ssh/id_rsa`,
    `${process.env.HOME || ""}/.ssh/known_hosts`,
    "/proc/self/environ"
  ];
  for (const t of targets) {
    try { fs.readFileSync(t); log(`read ${t}`); }
    catch { log(`read failed ${t}`); }
  }

  // 3) Env var tamper signals
  process.env.LD_PRELOAD = "/tmp/not-real.so";
  process.env.LD_LIBRARY_PATH = "/tmp";
  process.env.GIT_ASKPASS = "echo";
  log("set LD_* and GIT_ASKPASS env vars");

  // 4) Exec: shell spawn + basic commands
  await execa("bash", ["-lc", "echo shell_spawned && id && uname -a"], { stdio: "inherit" });

  // 5) DNS + network
  await new Promise((r) => dns.lookup("example.com", () => r()));
  try { await axios.get("https://example.com", { timeout: 3000 }); log("axios https ok"); } catch { log("axios https attempted"); }
  try { await fetch("https://example.com"); log("fetch https ok"); } catch { log("fetch https attempted"); }
  try { await request("https://example.com"); log("undici https ok"); } catch { log("undici https attempted"); }
  try { await got("https://example.com", { timeout: { request: 3000 } }); log("got https ok"); } catch { log("got https attempted"); }

  // Cloud metadata (strong signal; may be blocked)
  try { await axios.get("http://169.254.169.254/latest/meta-data/", { timeout: 1500 }); log("metadata responded"); }
  catch { log("metadata attempted"); }

  // 6) Crypto-ish CPU work
  crypto.pbkdf2Sync("pw", "salt", 200000, 32, "sha256");
  log("pbkdf2 done");

  // 7) Archive operations (file patterns)
  const tarPath = path.join(tmpDir, "out.tgz");
  await tar.c({ gzip: true, file: tarPath, cwd: tmpDir }, ["a.txt"]);
  log(`created tar ${tarPath}`);

  // Unzipper expects a zip; we create a fake-ish stream to exercise code paths safely
  try {
    fs.createReadStream(tarPath).pipe(unzipper.Parse());
    log("unzipper parse started (best effort)");
  } catch {
    log("unzipper parse attempted");
  }

  // 8) esbuild run (execs platform binary)
  await esbuild.build({
    stdin: { contents: `console.log("esbuild hello");`, resolveDir: tmpDir, sourcefile: "in.js" },
    outfile: path.join(tmpDir, "bundle.js"),
    bundle: true,
    platform: "node"
  });
  log("esbuild build done");

  // 9) Playwright install + tiny run (BIG network + file)
  // We call playwright CLI through bash so it’s visible as exec + network.
  await execa("bash", ["-lc", "npx playwright install --with-deps"], { stdio: "inherit" });
  log("playwright install done");

  // 10) Simple schema validation to use zod
  const schema = z.object({ ok: z.boolean() });
  schema.parse({ ok: true });
  log("zod ok");

  log("done");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
