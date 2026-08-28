const request = JSON.parse(await new Promise((resolve, reject) => {
  let body = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => {
    body += chunk;
  });
  process.stdin.on("end", () => resolve(body));
  process.stdin.on("error", reject);
}));
const { component: encoded, context_json: contextJson, checkpoint_json: checkpointJson } = request;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function writeString(memory, offset, value) {
  const bytes = textEncoder.encode(value);
  const view = new Uint8Array(memory.buffer);
  if (offset + bytes.length > view.length) {
    throw new Error("component input exceeds guest memory");
  }
  view.set(bytes, offset);
  return bytes.length;
}

function readReturnedString(memory, encodedPointerLength) {
  const value = BigInt(encodedPointerLength);
  const pointer = Number(value >> 32n);
  const length = Number(value & 0xffffffffn);
  const view = new Uint8Array(memory.buffer);
  if (!Number.isSafeInteger(pointer) || !Number.isSafeInteger(length) || pointer < 0 || length < 0 || pointer + length > view.length) {
    throw new Error("component returned an invalid pointer/length pair");
  }
  return textDecoder.decode(view.subarray(pointer, pointer + length));
}

try {
  const bytes = Buffer.from(encoded, "base64");
  const module = new WebAssembly.Module(bytes);
  const imports = WebAssembly.Module.imports(module);
  if (imports.length !== 0) {
    throw new Error("components with ambient imports are forbidden");
  }
  const instance = new WebAssembly.Instance(module, {});
  if (!(instance.exports.memory instanceof WebAssembly.Memory)) {
    throw new Error("component must export memory");
  }
  if (typeof instance.exports.resume !== "function") {
    throw new Error("component must export resume(context-json, checkpoint-json)");
  }

  const memory = instance.exports.memory;
  const contextPointer = 1024;
  const contextLength = writeString(memory, contextPointer, contextJson);
  const checkpointPointer = contextPointer + contextLength + 16;
  const checkpointLength = writeString(memory, checkpointPointer, checkpointJson);
  const result = instance.exports.resume(contextPointer, contextLength, checkpointPointer, checkpointLength);
  process.stdout.write(readReturnedString(memory, result));
} catch (error) {
  process.stderr.write(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
