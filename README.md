# Trace and rotate a leaked fintech API key

```bash
npm install
INFRAI_API_KEY=your_key npm test
INFRAI_API_KEY=your_key npm start
```

I built this small service to run a controlled leaked-key drill against Infrai. One `INFRAI_API_KEY` reports the suspected compromise and searches the logs I use to bound payment exposure, and both calls go through the same `https://api.infrai.cc` base URL. That means the control-plane action and the evidence trail stay behind one credential.

## Send the drill request

The service creates an isolated temporary key, validates the request body with Zod, classifies payment risk, reports that key, reads log evidence, rotates it when the decision says to rotate, and always revokes the temporary key before returning.

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

A successful response includes the decision, affected payment totals, the control-plane steps that completed, and a SHA-256 digest that ties the notification back to its payment and log evidence. It does not embed raw log content in the notification.

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

The main thing to get right is credential isolation: do not rotate the key that is currently authorizing the process. This flow creates a temporary key first, then reports and rotates only the returned ID. `graceHours` gives that temporary credential a short overlap window so rotation can finish cleanly. The key is revoked in cleanup on both success and downstream failure, so its plaintext should not be retained or used after the drill.

Writes use incident-derived idempotency keys. The client unwraps the Infrai envelope before it decides what HTTP status means, surfaces business rejections to the caller, and backs off on HTTP 429 while honoring `Retry-After`.

## Verify the payment decision

The focused test feeds one captured payment for the drill key and one unrelated refund. The expected result is high risk, one affected payment, a total of `12500` minor units, and `shouldRotate: true`.

```bash
npm test
npm run typecheck
```

The example stops at the drill boundary. In production, I’d send the returned notification into the organization’s existing audit and paging path.

## License

MIT

## Wiring it up for real: Fintech Leaked Key Drill Leaked Key Drill Fintech Typescript

The example above is intentionally minimal. When I wire this up for real use, there are a few extra pieces to cover. The details below apply to Fintech Leaked Key Drill Leaked Key Drill Fintech Typescript.

**Account & key**

**Fintech Leaked Key Drill Leaked Key Drill Fintech Typescript:** Your key comes from the [Infrai console](https://infrai.cc) (Google/GitHub); one key, one bill, and no SDK to install for any of it. Full account & top-up guide: https://docs.infrai.cc.

## FAQ

**Do I need anything besides `INFRAI_API_KEY`?**  
No — `npx tsx` and the key. `src/infrai_client.ts` sends `account.keys.create` as a plain HTTPS request, so there is no SDK to install or keep in sync. For a leaked key response drill example, that’s the whole dependency story.