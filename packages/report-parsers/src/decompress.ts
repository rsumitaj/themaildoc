/**
 * Getting XML out of whatever the mailbox delivered.
 *
 * Reports arrive as `.xml`, `.xml.gz` or `.zip` depending on the receiver, and
 * the extension is not reliable — Yahoo has shipped gzip named `.zip` before.
 * So the format is decided by the first bytes, never by the filename.
 *
 * Decompression uses the platform's own `DecompressionStream`, which every
 * current browser and Node 20+ provides. No library, no upload, no server.
 */

export interface ReportFile {
  name: string;
  xml: string;
}

export class DecompressError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DecompressError';
  }
}

/** A zip bomb is 40KB on the wire and gigabytes in a browser tab. */
const MAX_UNPACKED = 64 * 1024 * 1024;

const GZIP = [0x1f, 0x8b];
const ZIP = [0x50, 0x4b, 0x03, 0x04];

export type Format = 'xml' | 'gzip' | 'zip' | 'unknown';

export function sniff(bytes: Uint8Array): Format {
  if (starts(bytes, GZIP)) return 'gzip';
  if (starts(bytes, ZIP)) return 'zip';

  for (let index = 0; index < Math.min(bytes.length, 512); index += 1) {
    const byte = bytes[index] as number;
    if (byte === 0x3c) return 'xml'; // '<'
    if (byte > 0x20) return 'unknown';
  }
  return 'unknown';
}

function starts(bytes: Uint8Array, magic: readonly number[]): boolean {
  return magic.every((byte, index) => bytes[index] === byte);
}

/**
 * Every XML document inside one dropped file. A zip holding six reports gives
 * six results; anything else gives one.
 */
export async function readReportBytes(name: string, bytes: Uint8Array): Promise<ReportFile[]> {
  switch (sniff(bytes)) {
    case 'xml':
      return [{ name, xml: decode(bytes) }];
    case 'gzip':
      return [{ name: stripExtension(name), xml: decode(await inflate(bytes, 'gzip')) }];
    case 'zip':
      return unzip(name, bytes);
    default:
      throw new DecompressError(
        `${name} is not XML, gzip or zip. Drop the report exactly as it arrived, do not open it first.`,
      );
  }
}

/** Convenience wrapper for a browser `File`. */
export async function readReportFile(file: {
  name: string;
  arrayBuffer(): Promise<ArrayBuffer>;
}): Promise<ReportFile[]> {
  return readReportBytes(file.name, new Uint8Array(await file.arrayBuffer()));
}

function decode(bytes: Uint8Array): string {
  return new TextDecoder('utf-8').decode(bytes);
}

function stripExtension(name: string): string {
  return name.replace(/\.(gz|zip)$/i, '');
}

/**
 * The shape of a decompression stream, spelled out here because the DOM and
 * Node type libraries describe this exact API with chunk types that disagree.
 * Both runtimes take a Uint8Array in and hand a Uint8Array back.
 */
interface ByteTransform {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
}

async function inflate(bytes: Uint8Array, format: 'gzip' | 'deflate-raw'): Promise<Uint8Array> {
  const Stream = (globalThis as { DecompressionStream?: typeof DecompressionStream })
    .DecompressionStream;

  if (!Stream) {
    throw new DecompressError(
      'This browser cannot decompress files. Unzip the report yourself and drop the .xml in.',
    );
  }

  // Built from a stream rather than a Blob so this file needs no DOM types
  // beyond the compression API itself.
  const source = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });

  const transform = new Stream(format) as unknown as ByteTransform;
  const reader = (source.pipeThrough(transform) as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.length;
      if (total > MAX_UNPACKED) {
        await reader.cancel();
        throw new DecompressError('That file unpacks to more than 64MB. It is not a DMARC report.');
      }
      chunks.push(value);
    }
  }

  const out = new Uint8Array(total);
  let at = 0;
  for (const chunk of chunks) {
    out.set(chunk, at);
    at += chunk.length;
  }
  return out;
}

/* Zip ---------------------------------------------------------------------- */

const EOCD_SIGNATURE = 0x0605_4b50;
const CENTRAL_SIGNATURE = 0x0201_4b50;
const LOCAL_SIGNATURE = 0x0403_4b50;

async function unzip(name: string, bytes: Uint8Array): Promise<ReportFile[]> {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const eocd = findEocd(view);
  if (eocd === -1) throw new DecompressError(`${name} is not a readable zip archive.`);

  const entries = view.getUint16(eocd + 10, true);
  const directory = view.getUint32(eocd + 16, true);

  if (directory === 0xffff_ffff || entries === 0xffff) {
    throw new DecompressError(
      `${name} uses the zip64 format, which we do not read. Unzip it and drop the .xml in.`,
    );
  }

  const files: ReportFile[] = [];
  let at = directory;

  for (let index = 0; index < entries && at + 46 <= bytes.length; index += 1) {
    if (view.getUint32(at, true) !== CENTRAL_SIGNATURE) break;

    const method = view.getUint16(at + 10, true);
    const compressed = view.getUint32(at + 20, true);
    const nameLength = view.getUint16(at + 28, true);
    const extraLength = view.getUint16(at + 30, true);
    const commentLength = view.getUint16(at + 32, true);
    const localOffset = view.getUint32(at + 42, true);
    const entryName = decode(bytes.subarray(at + 46, at + 46 + nameLength));

    at += 46 + nameLength + extraLength + commentLength;
    if (entryName.endsWith('/') || entryName.startsWith('__MACOSX/')) continue;

    if (view.getUint32(localOffset, true) !== LOCAL_SIGNATURE) continue;
    const localName = view.getUint16(localOffset + 26, true);
    const localExtra = view.getUint16(localOffset + 28, true);
    const start = localOffset + 30 + localName + localExtra;
    const body = bytes.subarray(start, start + compressed);

    if (method === 0) {
      files.push({ name: entryName, xml: decode(body) });
    } else if (method === 8) {
      files.push({ name: entryName, xml: decode(await inflate(body, 'deflate-raw')) });
    } else {
      throw new DecompressError(
        `${entryName} uses an unsupported compression method. Unzip it and drop the .xml in.`,
      );
    }
  }

  if (files.length === 0) throw new DecompressError(`${name} contains no readable files.`);
  return files;
}

/** The end-of-central-directory record, searched from the back as the spec requires. */
function findEocd(view: DataView): number {
  const limit = Math.max(0, view.byteLength - 22 - 0xffff);
  for (let at = view.byteLength - 22; at >= limit; at -= 1) {
    if (view.getUint32(at, true) === EOCD_SIGNATURE) return at;
  }
  return -1;
}
