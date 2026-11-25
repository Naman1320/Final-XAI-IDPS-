import { streamNdjson } from "../api/client";

function chunkedResponse(chunks: Uint8Array[]): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      chunks.forEach((c) => controller.enqueue(c));
      controller.close();
    },
  });
  return new Response(body, { status: 200 });
}

describe("streamNdjson", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("reassembles lines and multi-byte characters split across chunks", async () => {
    const bytes = new TextEncoder().encode('{"type":"text","text":"héllo"}\n{"type":"done"}');
    // split inside the two-byte "é" and leave the last line without a newline
    const cut = bytes.indexOf(0xc3) + 1;
    vi.stubGlobal("fetch", vi.fn(async () => chunkedResponse([bytes.slice(0, cut), bytes.slice(cut)])));
    const events: Record<string, unknown>[] = [];
    await streamNdjson("/assistant/chat", { message: "x" }, (e) => events.push(e));
    expect(events).toEqual([{ type: "text", text: "héllo" }, { type: "done" }]);
  });

  it("raises the API's error message", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ detail: "busy" }), { status: 409 })));
    await expect(streamNdjson("/assistant/chat", {}, () => {})).rejects.toThrow("busy");
  });
});
