// Browser-mode end-to-end run of the real app, which also takes the doc screenshots.
// Run through e2e/run.sh, which starts the app and sets the environment below.
const { chromium } = require("playwright");
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");

const WORK = process.env.E2E_DIR;
const SHOTS = process.env.SHOTS || path.join(WORK, "shots");
const VAULTS = process.env.VAULTS;
const PY = process.env.PYTHON || "python";
const BACKEND = path.resolve(__dirname, "..", "backend");
const PASSWORD = "Tr0ub4dor & 3 horses";
const NEW_PASSWORD = "an even longer passphrase 2026";
const DEMO_PASSWORD = "demo-password-1234";
const results = [];

function ok(name, cond, detail = "") {
  results.push({ name, ok: !!cond, detail });
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${detail ? " - " + detail : ""}`);
  if (!cond) throw new Error(`failed: ${name}`);
}
const cli = (...args) =>
  execFileSync(PY, ["-c", "import sys; from app.localclient import LocalClient; import json; c = LocalClient.from_runtime(); " + args[0]], {
    cwd: BACKEND, env: process.env, encoding: "utf8",
  });

(async () => {
  fs.mkdirSync(SHOTS, { recursive: true });
  const browser = await chromium.launch();
  const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, acceptDownloads: true });
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("response", (r) => r.status() >= 400 && errors.push(`${r.status()} ${r.request().method()} ${r.url()}`));
  const shot = async (name, opts = {}) => {
    // Let notifications from earlier steps fade, so they don't end up in the docs.
    await page.locator(".toast").first().waitFor({ state: "detached", timeout: 10000 }).catch(() => {});
    await page.screenshot({ path: path.join(SHOTS, `${name}.png`), ...opts });
  };

  try {
    // ---- launch: one-time link -> cookie -> welcome
    await page.goto(process.env.LAUNCH_URL);
    await page.getByText("Create vault").waitFor();
    ok("launch link opens the app", page.url().endsWith("/"));
    const reuse = await (await context.newPage()).goto(process.env.LAUNCH_URL);
    ok("launch link is single use", reuse.status() === 403);
    await shot("01-welcome");

    // ---- create a vault
    await page.getByRole("button", { name: "Create vault" }).click();
    await page.getByLabel("Vault name").fill("ACME-2026");
    await page.getByLabel("Location").fill(VAULTS);
    await page.getByLabel("Password", { exact: true }).fill(PASSWORD);
    await page.getByLabel("Confirm password").fill(PASSWORD);
    await shot("02-create-vault");
    await page.locator("form.gate-form").getByRole("button", { name: "Create vault" }).click();
    const keyBox = page.getByLabel("Recovery key");
    await keyBox.waitFor({ timeout: 30000 });
    const recoveryKey = (await keyBox.innerText()).replace(/\s+/g, "-").replace(/-+/g, "-");
    ok("recovery key shown once after create", /^OHRK-/.test(recoveryKey), recoveryKey.slice(0, 11) + "...");
    await shot("03-recovery-key");
    // Recovery kit download (browser mode: a plain same-origin download).
    const [kitDl] = await Promise.all([page.waitForEvent("download"), page.getByText("Save the recovery kit").click()]);
    const kit = JSON.parse(fs.readFileSync(await kitDl.path(), "utf8"));
    ok("recovery kit downloads", kit.format === "offsechub-recovery-kit" && !JSON.stringify(kit).includes(recoveryKey.slice(5, 15)),
       kitDl.suggestedFilename());
    await page.getByLabel("I have stored it somewhere safe").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("link", { name: "Dashboard" }).waitFor();
    ok("vault unlocked after create", true);
    ok("vault files are ciphertext", !fs.readFileSync(path.join(VAULTS, "ACME-2026.ohvault", "db.enc")).includes("sqlite"));

    // ---- lock, wrong password, recovery-key unlock -> forced new password + new key
    await page.getByRole("button", { name: "Lock", exact: true }).click();
    await page.getByRole("button", { name: "Unlock" }).waitFor();
    await page.getByLabel("Password").fill("not the password at all");
    await page.getByRole("button", { name: "Unlock" }).click();
    await page.locator(".alert-error").waitFor();
    ok("wrong password refused", true, await page.locator(".alert-error").innerText());
    await page.getByText("Forgot the password? Use recovery key").click();
    await page.getByLabel("Recovery key").fill(recoveryKey.toLowerCase().replace(/-/g, " "));
    await page.getByRole("button", { name: "Unlock" }).click();
    await page.getByText("Set a new password").first().waitFor({ timeout: 30000 });
    await page.getByLabel("New password", { exact: true }).fill(NEW_PASSWORD);
    await page.getByLabel("Confirm new password").fill(NEW_PASSWORD);
    await shot("04-set-password");
    await page.getByRole("button", { name: "Set password" }).click();
    await page.getByLabel("Recovery key").waitFor({ timeout: 30000 });
    const rotated = (await page.getByLabel("Recovery key").innerText()).replace(/\s+/g, "-");
    ok("recovery key rotated after use", rotated !== recoveryKey);
    await page.getByLabel("I have stored it somewhere safe").check();
    await page.getByRole("button", { name: "Continue" }).click();
    await page.getByRole("link", { name: "Dashboard" }).waitFor();

    // ---- close it and open the demo vault (created by `offsechub demo`)
    await page.getByRole("link", { name: /Settings/ }).click();
    await page.getByRole("button", { name: "Close vault" }).click();
    await page.getByText("Recent vaults", { exact: false }).waitFor();
    const demo = page.locator(".recent-list li, li").filter({ hasText: "Demo" }).first();
    await demo.getByRole("button", { name: "Open" }).click();
    await page.getByLabel("Password").fill(DEMO_PASSWORD);
    await page.getByRole("button", { name: "Unlock" }).click();
    await page.getByRole("link", { name: "Dashboard" }).waitFor({ timeout: 30000 });
    await page.getByText("Riley Chen").first().waitFor();
    ok("a newly opened vault starts on its dashboard", new URL(page.url()).pathname === "/", page.url());
    await page.waitForTimeout(800);
    await shot("05-dashboard");

    // ---- domain pages (expected failures so far: the wrong-password attempt)
    ok("only the wrong password failed so far", errors.length === 1 && errors[0].includes("/api/vault/unlock"), errors.join(" | "));
    errors.length = 0;
    await page.getByRole("link", { name: "Engagements" }).click();
    await page.getByText("External Penetration Test 2026").first().click();
    await page.getByRole("link", { name: "Overview" }).waitFor();
    const base = page.url().replace(/\/$/, "");
    const tabs = ["Overview", "Scope", "Targets", "Recon", "Testing", "Findings", "Evidence", "Op log", "Report", "Activity"];
    for (const [i, tab] of tabs.entries()) {
      await page.getByRole("main").getByRole("link", { name: tab, exact: true }).click();
      await page.waitForLoadState("networkidle");
      await page.waitForTimeout(500);
      await shot(`${String(10 + i).padStart(2, "0")}-${tab.toLowerCase().replace(/ /g, "-")}`);
    }
    ok("all engagement tabs render", errors.length === 0, errors.join(" | "));

    // Finding editor
    await page.getByRole("main").getByRole("link", { name: "Findings", exact: true }).click();
    await page.getByText("Exposed Git Repository").first().click();
    await page.waitForLoadState("networkidle");
    await page.waitForTimeout(500);
    await shot("20-finding-editor");

    // Evidence upload as a raw body, then download it back
    await page.getByRole("main").getByRole("link", { name: "Evidence", exact: true }).click();
    await page.getByText(/Evidence locker/).waitFor();
    const sample = path.join(WORK, "e2e-upload.txt");
    fs.writeFileSync(sample, "uid=0(root) gid=0(root)\n");
    await page.locator('input[type="file"]').first().setInputFiles(sample);
    await page.getByRole("link", { name: "e2e-upload.txt" }).first().waitFor({ timeout: 15000 });
    const [evDl] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: "e2e-upload.txt" }).first().click()]);
    ok("evidence round-trips through the vault", fs.readFileSync(await evDl.path(), "utf8") === "uid=0(root) gid=0(root)\n");

    // Report export
    await page.getByRole("main").getByRole("link", { name: "Report", exact: true }).click();
    const [mdDl] = await Promise.all([page.waitForEvent("download"), page.getByRole("link", { name: "Markdown" }).click()]);
    const md = fs.readFileSync(await mdDl.path(), "utf8");
    ok("markdown report exports", md.includes("Exposed Git Repository"), mdDl.suggestedFilename());

    // Settings and library
    await page.getByRole("link", { name: "Finding library" }).click();
    await page.waitForTimeout(600);
    await shot("21-library");
    await page.getByRole("link", { name: /Settings/ }).click();
    await page.getByRole("button", { name: "Verify evidence" }).click();
    await page.getByText(/verified/i).first().waitFor({ timeout: 20000 });
    await page.waitForTimeout(300);
    await shot("22-settings", { fullPage: true });
    ok("evidence verification passes", true, (await page.getByText(/verified/i).first().innerText()).slice(0, 80));

    // ---- lock from outside (CLI/idle): the UI drops everything and explains
    await page.getByRole("link", { name: "Dashboard" }).click();
    cli("c.json('POST', '/api/vault/lock')");
    await page.getByRole("link", { name: "Engagements" }).click();
    await page.getByRole("button", { name: "Unlock" }).waitFor({ timeout: 15000 });
    await page.getByText("The vault was locked.").waitFor();
    ok("external lock returns the UI to the unlock screen and says why", true);
    await shot("23-locked");

    // ---- the API refuses a request without the session
    const anon = await browser.newContext();
    const r = await (await anon.newPage()).goto(page.url().replace(/\/[^/]*$/, "/api/vault/status"));
    ok("API requires the session cookie", r.status() === 401);
  } catch (e) {
    console.log("ERROR", e.message);
    await shot("99-error").catch(() => {});
    process.exitCode = 1;
  } finally {
    fs.writeFileSync(path.join(WORK, "browser-results.json"), JSON.stringify({ results, errors }, null, 2));
    await browser.close();
  }
})();
