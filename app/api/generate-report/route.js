export async function POST(request) {
  const apiKey = process.env.AMAZIN_CYBER_REPORT
  if (!apiKey) {
    return Response.json({ error: "API key not configured" }, { status: 500 })
  }

  let body
  try {
    body = await request.json()
  } catch {
    return Response.json({ error: "Invalid request body" }, { status: 400 })
  }

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify(body),
  })

  const data = await res.json()

  if (!res.ok) {
    return Response.json({ error: data?.error?.message || "Anthropic API error" }, { status: res.status })
  }

  return Response.json(data)
}
