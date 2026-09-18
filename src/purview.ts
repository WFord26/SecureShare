/** Policy discovery only: never submits file contents or authorizes a download. */
export interface PurviewStatus {
  state: "checked" | "unavailable";
  message: string;
  checkedAt: string;
  text?: "inline" | "audit" | "none";
  files?: "inline" | "audit" | "none";
}

export function summarizeScopes(body: unknown): Pick<PurviewStatus, "text" | "files"> {
  const value = (body as { value?: unknown } | null)?.value;
  if (!Array.isArray(value)) throw new Error("Invalid protection scopes response");
  const result = { text: "none", files: "none" } as const;
  const summary: Pick<PurviewStatus, "text" | "files"> = { ...result };
  for (const scope of value) {
    if (!scope || typeof scope.activities !== "string" ||
        !["evaluateInline", "evaluateOffline"].includes(scope.executionMode)) {
      throw new Error("Unknown protection scope");
    }
    const activities = scope.activities.split(",").map((s: string) => s.trim());
    for (const [key, activity] of [["text", "uploadText"], ["files", "uploadFile"]] as const) {
      if (!activities.includes(activity)) continue;
      if (scope.executionMode === "evaluateInline") summary[key] = "inline";
      else if (summary[key] !== "inline") summary[key] = "audit";
    }
  }
  return summary;
}

export async function checkPurview(accessToken: string, clientId: string, request: typeof fetch = fetch): Promise<PurviewStatus> {
  const checkedAt = new Date().toISOString();
  try {
    const response = await request("https://graph.microsoft.com/v1.0/me/dataSecurityAndGovernance/protectionScopes/compute", {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ activities: "uploadText,uploadFile", locations: [
        { "@odata.type": "microsoft.graph.policyLocationApplication", value: clientId },
      ] }),
      signal: AbortSignal.timeout(10000),
      redirect: "error",
    });
    if (!response.ok) {
      return { state: "unavailable", checkedAt, message: response.status === 403
        ? "Purview denied the status check. Ask an administrator to verify permissions and tenant setup."
        : response.status === 401 ? "Purview authorization expired. Check again to reconnect."
        : "Purview could not complete the status check. Try again later." };
    }
    return { state: "checked", checkedAt, message: "Policy status checked for your account.", ...summarizeScopes(await response.json()) };
  } catch {
    // Do not expose Graph errors, tokens, or user data to the browser or logs.
    return { state: "unavailable", checkedAt, message: "Purview could not complete the status check. Try again later." };
  }
}
