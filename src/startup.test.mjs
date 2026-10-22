import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  APP_STATE_INITIALIZING,
  isSnapshotStateInitializing,
  loadSnapshotWhenReady,
} from "../target/ui-tests/snapshot.js";

// The embedded (Windows) runtime lives in embedded.rs since the Linux client split.
const backendSource = await readFile(
  new URL("../src-tauri/src/embedded.rs", import.meta.url),
  "utf8",
);
const frontendSource = await readFile(new URL("./main.ts", import.meta.url), "utf8");

test("registers AppState on the builder before setup can create the webview", () => {
  const managed = backendSource.indexOf(".manage(AppState::default())");
  const setup = backendSource.indexOf(".setup(");

  assert.notEqual(managed, -1, "AppState is not managed on the builder");
  assert.ok(managed < setup, "AppState must be managed before setup");
  assert.ok(
    !backendSource.includes("app.manage(AppState"),
    "setup must not register AppState after the frontend has started",
  );
});

test("the initial snapshot load uses the state-aware retry path", () => {
  assert.match(frontendSource, /loadSnapshotWhenReady/);
  assert.match(frontendSource, /refreshing/);
});

test("CZ and EN startup silently retry the live unmanaged-state error within one second", async () => {
  const unmanagedStateError =
    "state not managed for field 'state' on command 'get_snapshot'. You must call '.manage()' before using this command";

  for (const locale of ["cs", "en"]) {
    let attempts = 0;
    const startedAt = performance.now();
    const snapshot = await loadSnapshotWhenReady(async () => {
      attempts += 1;
      if (attempts === 1) throw unmanagedStateError;
      if (attempts === 2) throw APP_STATE_INITIALIZING;
      return { locale, running: true };
    });

    assert.deepEqual(snapshot, { locale, running: true });
    assert.equal(attempts, 3);
    assert.ok(performance.now() - startedAt < 1_000, `${locale} snapshot exceeded one second`);
  }
});

test("snapshot retry recognizes only initialization failures", async () => {
  assert.equal(isSnapshotStateInitializing(APP_STATE_INITIALIZING), true);
  assert.equal(
    isSnapshotStateInitializing(
      new Error("state not managed for field 'state' on command 'get_snapshot'"),
    ),
    true,
  );
  assert.equal(isSnapshotStateInitializing("proxy failed to start"), false);

  let attempts = 0;
  await assert.rejects(
    loadSnapshotWhenReady(async () => {
      attempts += 1;
      throw new Error("proxy failed to start");
    }),
    /proxy failed to start/,
  );
  assert.equal(attempts, 1);
});
