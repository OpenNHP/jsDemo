export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

export function stringToBytes(str) {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}

export function bytesToString(bytes) {
  const decoder = new TextDecoder();
  return decoder.decode(bytes);
}

export function bytesToBase64(bytes) {
    let bin = "";
    bytes.forEach(b => bin += String.fromCharCode(b));
    return btoa(bin);
}

export function base64ToBytes(base64) {
    const bin = atob(base64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
    }
    return bytes;
}

export function getUnixNano() {
  const ms = Date.now(); // milliseconds since Unix epoch
  const subMs = performance.now() % 1; // fractional milliseconds
  return BigInt(ms) * 1_000_000n + BigInt(Math.floor(subMs * 1_000_000));
}

export async function zlibCompress(data) {
  // Create a compression stream using 'deflate' (ZLIB format)
  const cs = new CompressionStream('deflate');
  const writer = cs.writable.getWriter();
  writer.write(data);
  writer.close();

  // Read the compressed chunks into an array
  const response = new Response(cs.readable);
  const compressedBuffer = await response.arrayBuffer();
  return new Uint8Array(compressedBuffer);
}

export async function zlibDecompress(compressedData) {
  // Create a stream from the compressed Uint8Array
  const ds = new DecompressionStream("deflate");
  const writer = ds.writable.getWriter();
  writer.write(compressedData);
  writer.close();

  // Read the decompressed data
  const response = new Response(ds.readable);
  const arrayBuffer = await response.arrayBuffer();
  return new Uint8Array(arrayBuffer);
}
