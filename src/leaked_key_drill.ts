import { createHash } from "node:crypto";
import { z } from "zod";
import { InfraiClient } from "./infrai_client.js";

export const drillRequestSchema = z.object({
  incidentId: z.string().min(1).max(80),
  detectedAt: z.string().datetime({ offset: true }),
  confirmedLeak: z.boolean(),
  graceHours: z.number().int().min(0).max(24).default(1),
  paymentEvents: z.array(z.object({
    eventId: z.string().min(1),
    kind: z.enum(["authorization", "capture", "refund"]),
    amountMinor: z.number().int().positive(),
    currency: z.string().regex(/^[A-Z]{3}$/),
    occurredAt: z.string().datetime({ offset: true }),
    linkedToDrillKey: z.boolean(),
  })).max(500).default([]),
});

export type DrillRequest = z.infer<typeof drillRequestSchema>;
type PaymentEvent = DrillRequest["paymentEvents"][number];

export type RiskDecision = {
  level: "low" | "high";
  affectedPaymentCount: number;
  affectedAmountMinor: number;
  shouldRotate: boolean;
};

export type DrillResult = {
  incidentId: string;
  decision: RiskDecision;
  notification: {
    category: "security.key_compromise";
    summary: string;
    evidenceDigest: string;
    recordedAt: string;
  };
  steps: Array<"temporary_key_created" | "compromise_reported" | "logs_searched" | "temporary_key_rotated" | "temporary_key_revoked">;
  logEvidenceAvailable: boolean;
};

export function assessPaymentRisk(
  confirmedLeak: boolean,
  events: PaymentEvent[],
): RiskDecision {
  const affected = events.filter((event) => event.linkedToDrillKey);
  return {
    level: confirmedLeak || affected.some((event) => event.kind === "capture") ? "high" : "low",
    affectedPaymentCount: affected.length,
    affectedAmountMinor: affected.reduce((sum, event) => sum + event.amountMinor, 0),
    shouldRotate: confirmedLeak || affected.length > 0,
  };
}

export async function runLeakedKeyDrill(
  client: InfraiClient,
  input: DrillRequest,
  now: () => Date = () => new Date(),
): Promise<DrillResult> {
  const decision = assessPaymentRisk(input.confirmedLeak, input.paymentEvents);
  const idempotencyPrefix = `${input.incidentId}-drill`;

  const temporaryKey = await client.createKey({
    name: `isolated-drill-${input.incidentId}`,
    scopes: ["account.keys.suspected_compromise", "account.keys.rotate", "logs.search"],
    idempotency_key: `${idempotencyPrefix}-create`,
  });
  const steps: DrillResult["steps"] = ["temporary_key_created"];
  const temporaryKeyIds = new Set([temporaryKey.key_id]);
  let logEvidence: unknown;

  try {
    const compromise = await client.reportSuspectedCompromise(temporaryKey.key_id, {
      confirmed_leak: input.confirmedLeak,
      auto_rotate: false,
    });
    if (compromise.key_id !== undefined) temporaryKeyIds.add(compromise.key_id);
    steps.push("compromise_reported");

    logEvidence = await client.searchLogs();
    steps.push("logs_searched");

    if (decision.shouldRotate) {
      const rotation = await client.rotateKey(temporaryKey.key_id, {
        grace_hours: input.graceHours,
        idempotency_key: `${idempotencyPrefix}-rotate`,
      });
      if (rotation.key !== undefined) {
        temporaryKeyIds.add(`ifr_...${rotation.key.slice(-4)}`);
      } else if (rotation.key_id !== undefined) {
        temporaryKeyIds.add(rotation.key_id);
      }
      steps.push("temporary_key_rotated");
    }
  } finally {
    for (const keyId of temporaryKeyIds) await client.revokeKey(keyId);
    steps.push("temporary_key_revoked");
  }

  const evidenceDigest = createHash("sha256")
    .update(JSON.stringify({ events: input.paymentEvents, logEvidence }))
    .digest("hex");

  return {
    incidentId: input.incidentId,
    decision,
    notification: {
      category: "security.key_compromise",
      summary: `${decision.affectedPaymentCount} payment events matched the drill key`,
      evidenceDigest,
      recordedAt: now().toISOString(),
    },
    steps,
    logEvidenceAvailable: logEvidence !== undefined && logEvidence !== null,
  };
}
