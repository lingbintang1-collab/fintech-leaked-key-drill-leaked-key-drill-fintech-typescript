import assert from "node:assert/strict";
import test from "node:test";
import { InfraiClient } from "../src/infrai_client.js";
import { assessPaymentRisk, runLeakedKeyDrill } from "../src/leaked_key_drill.js";

test("a captured payment on the leaked key triggers high-risk rotation", () => {
  const decision = assessPaymentRisk(false, [
    {
      eventId: "pay-100",
      kind: "capture",
      amountMinor: 12500,
      currency: "USD",
      occurredAt: "2026-09-27T08:00:00Z",
      linkedToDrillKey: true,
    },
    {
      eventId: "pay-101",
      kind: "refund",
      amountMinor: 900,
      currency: "USD",
      occurredAt: "2026-09-27T08:04:00Z",
      linkedToDrillKey: false,
    },
  ]);

  assert.deepEqual(decision, {
    level: "high",
    affectedPaymentCount: 1,
    affectedAmountMinor: 12500,
    shouldRotate: true,
  });
});

const drillInput = {
  incidentId: "incident-test",
  detectedAt: "2026-09-27T08:00:00Z",
  confirmedLeak: true,
  graceHours: 1,
  paymentEvents: [],
};

test("the temporary key is revoked after a successful drill", async () => {
  const calls: string[] = [];
  const client = {
    async createKey() { calls.push("create"); return { key_id: "key-1" }; },
    async reportSuspectedCompromise() { calls.push("report"); return {}; },
    async searchLogs() { calls.push("search"); return []; },
    async rotateKey() { calls.push("rotate"); return { key_id: "ifr_redacted...", key: "ifr_full-secret-abcd" }; },
    async revokeKey(id: string) { calls.push(`revoke:${id}`); },
  } as unknown as InfraiClient;

  const result = await runLeakedKeyDrill(client, drillInput);

  assert.deepEqual(calls, ["create", "report", "search", "rotate", "revoke:key-1", "revoke:ifr_...abcd"]);
  assert.equal(result.steps.at(-1), "temporary_key_revoked");
});

test("the temporary key is revoked when a downstream operation fails", async () => {
  const calls: string[] = [];
  const client = {
    async createKey() { calls.push("create"); return { key_id: "key-2" }; },
    async reportSuspectedCompromise() { calls.push("report"); throw new Error("report failed"); },
    async revokeKey() { calls.push("revoke"); },
  } as unknown as InfraiClient;

  await assert.rejects(runLeakedKeyDrill(client, drillInput), /report failed/);
  assert.deepEqual(calls, ["create", "report", "revoke"]);
});
