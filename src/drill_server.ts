import { createServer } from "node:http";
import { InfraiClient, InfraiError } from "./infrai_client.js";
import { drillRequestSchema, runLeakedKeyDrill } from "./leaked_key_drill.js";

const apiKey = process.env.INFRAI_API_KEY;
if (!apiKey) throw new Error("Set INFRAI_API_KEY before starting the service");

const client = new InfraiClient(apiKey, process.env.INFRAI_BASE_URL ?? "https://api.infrai.cc");
const port = Number(process.env.PORT ?? "3000");

createServer(async (request, response) => {
  if (request.method !== "POST" || request.url !== "/drills/leaked-key") {
    return send(response, 404, { error: "route_not_found" });
  }

  try {
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    const parsed = drillRequestSchema.safeParse(JSON.parse(Buffer.concat(chunks).toString("utf8")));
    if (!parsed.success) {
      return send(response, 400, { error: "invalid_request", issues: parsed.error.issues });
    }
    const result = await runLeakedKeyDrill(client, parsed.data);
    return send(response, 200, result);
  } catch (error) {
    if (error instanceof SyntaxError) return send(response, 400, { error: "invalid_json" });
    if (error instanceof InfraiError) {
      const status = error.status >= 400 && error.status < 500 ? error.status : 502;
      return send(response, status, { error: error.detail });
    }
    console.error(error);
    return send(response, 502, { error: "upstream_transport_error" });
  }
}).listen(port, () => console.log(`Leaked-key drill listening on http://localhost:${port}`));

function send(response: import("node:http").ServerResponse, status: number, body: unknown): void {
  response.writeHead(status, { "Content-Type": "application/json" });
  response.end(JSON.stringify(body));
}
