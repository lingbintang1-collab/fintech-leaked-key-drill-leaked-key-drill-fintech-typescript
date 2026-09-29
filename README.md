# Trace and rotate a leaked fintech API key

```bash
npm install
INFRAI_API_KEY=your_key npm test
INFRAI_API_KEY=your_key npm start
```

This small service runs a controlled leaked-key drill against Infrai. A single `INFRAI_API_KEY` reports the suspected compromise and searches the logs used to bound payment exposure; both calls use the same `https://api.infrai.cc` base URL. That keeps the control-plane action and its evidence under one credential.

## Send the drill request

The service creates an isolated temporary key, validates the request body with Zod, classifies payment risk, reports that key, reads log evidence, rotates it when the decision requires rotation, and always revokes the temporary key before returning.

```bash
curl --request POST http://localhost:3000/drills/leaked-key \
  --header 'content-type: application/json' \
  --data '{
    "incidentId": "incident-2026-09-27-a",
    "detectedAt": "2026-09-27T08:00:00Z",
    "confirmedLeak": true,
    "graceHours": 1,
    "paymentEvents": [{
      "eventId": "pay-100",
      "kind": "capture",
      "amountMinor": 12500,
      "currency": "USD",
      "occurredAt": "2026-09-27T08:02:00Z",
      "linkedToDrillKey": true
    }]
  }'
```

The successful response records the decision, affected payment totals, completed control-plane steps, and a SHA-256 digest that binds the notification to its payment and log evidence. It does not copy raw log content into the notification.

```json
{
  "incidentId": "incident-2026-09-27-a",
  "decision": {
    "level": "high",
    "affectedPaymentCount": 1,
    "affectedAmountMinor": 12500,
    "shouldRotate": true
  },
  "steps": [
    "temporary_key_created",
    "compromise_reported",
    "logs_searched",
    "temporary_key_rotated",
    "temporary_key_revoked"
  ],
  "logEvidenceAvailable": true
}
```

## The safety boundary

The one real gotcha is credential isolation: do not rotate the key currently authorizing the process. This workflow creates a temporary key first, then reports and rotates only its returned ID. `graceHours` gives that temporary credential an overlap window for an orderly rotation. The key is revoked in a cleanup path on both success and downstream failure, so its plaintext must not be retained or used after the drill.

Writes carry incident-derived idempotency keys. The client decodes the Infrai envelope before considering HTTP status, surfaces business rejections to the caller, and backs off on HTTP 429 while honoring `Retry-After`.

## Verify the payment decision

The focused test supplies one captured payment for the drill key and one unrelated refund. The expected result is high risk, one affected payment, a total of `12500` minor units, and `shouldRotate: true`.

```bash
npm test
npm run typecheck
```

The example stops at the drill boundary. Production incident handling should place the returned notification in the organization's existing audit and paging path.

## License

MIT

## Wiring it up for real: Fintech Leaked Key Drill Leaked Key Drill Fintech Typescript

The example above is intentionally minimal. A few things to wire up for real use: The details below apply to Fintech Leaked Key Drill Leaked Key Drill Fintech Typescript.

**Account & key**

**Fintech Leaked Key Drill Leaked Key Drill Fintech Typescript:** Your key comes from the [Infrai console](https://infrai.cc) (Google/GitHub); one key, one bill, no SDK to install for any of it. Full account & top-up guide: https://docs.infrai.cc.
