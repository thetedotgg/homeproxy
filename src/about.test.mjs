import assert from "node:assert/strict";
import test from "node:test";

import { aboutVersions, PROJECT_SOURCE, PROJECT_WEBSITE } from "../target/ui-tests/about.js";
import { createTranslator } from "../target/ui-tests/i18n.js";

test("about shows the service version only for the separate Linux service", () => {
  assert.deepEqual(aboutVersions("1.2.8", "1.2.8", true), { app: "1.2.8", service: "1.2.8", mismatch: false });
  assert.deepEqual(aboutVersions("1.2.8", "1.2.7", true), { app: "1.2.8", service: "1.2.7", mismatch: true });
  assert.deepEqual(aboutVersions("1.2.8", undefined, true), { app: "1.2.8", service: null, mismatch: false });
  assert.deepEqual(aboutVersions("1.2.8", "  ", true), { app: "1.2.8", service: null, mismatch: false });
  assert.deepEqual(aboutVersions("1.2.8", "1.2.7", false), { app: "1.2.8", service: null, mismatch: false });
});

test("about copy exists in both languages and names the public project links", () => {
  for (const locale of ["cs", "en"]) {
    const t = createTranslator(locale);
    for (const key of ["aboutTitle", "aboutCopy", "aboutAppVersion", "aboutServiceVersion", "aboutVersionMismatch", "aboutWebsite", "aboutSource"]) {
      assert.ok(t(key).trim().length > 0, `${locale}:${key}`);
    }
    assert.match(t("aboutVersionMismatch", { app: "1.2.8", service: "1.2.7" }), /1\.2\.8.*1\.2\.7/);
  }
  assert.equal(PROJECT_WEBSITE, "homeproxy.thetasigma.io");
  assert.equal(PROJECT_SOURCE, "github.com/thetedotgg/homeproxy");
});
