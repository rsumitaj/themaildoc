import { describe, expect, it } from 'vitest';
import { DecompressError, readReportBytes, sniff } from '../src/decompress.js';
import { SAMPLE } from './fixtures.js';

const encoder = new TextEncoder();

async function gzip(text: string): Promise<Uint8Array> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** A minimal, stored (uncompressed) zip — enough to prove the reader walks it. */
function storedZip(name: string, body: string): Uint8Array {
  const nameBytes = encoder.encode(name);
  const bodyBytes = encoder.encode(body);
  const local = 30 + nameBytes.length + bodyBytes.length;
  const central = 46 + nameBytes.length;
  const out = new Uint8Array(local + central + 22);
  const view = new DataView(out.buffer);

  view.setUint32(0, 0x0403_4b50, true);
  view.setUint16(8, 0, true); // stored
  view.setUint32(18, bodyBytes.length, true);
  view.setUint32(22, bodyBytes.length, true);
  view.setUint16(26, nameBytes.length, true);
  out.set(nameBytes, 30);
  out.set(bodyBytes, 30 + nameBytes.length);

  view.setUint32(local, 0x0201_4b50, true);
  view.setUint16(local + 10, 0, true);
  view.setUint32(local + 20, bodyBytes.length, true);
  view.setUint32(local + 24, bodyBytes.length, true);
  view.setUint16(local + 28, nameBytes.length, true);
  view.setUint32(local + 42, 0, true);
  out.set(nameBytes, local + 46);

  const eocd = local + central;
  view.setUint32(eocd, 0x0605_4b50, true);
  view.setUint16(eocd + 8, 1, true);
  view.setUint16(eocd + 10, 1, true);
  view.setUint32(eocd + 12, central, true);
  view.setUint32(eocd + 16, local, true);

  return out;
}

describe('sniff', () => {
  it('decides by the bytes, never by the name', () => {
    expect(sniff(encoder.encode('<?xml version="1.0"?><feedback/>'))).toBe('xml');
    expect(sniff(new Uint8Array([0x1f, 0x8b, 0x08]))).toBe('gzip');
    expect(sniff(new Uint8Array([0x50, 0x4b, 0x03, 0x04]))).toBe('zip');
    expect(sniff(encoder.encode('not a report'))).toBe('unknown');
  });
});

describe('readReportBytes', () => {
  it('reads plain XML', async () => {
    const files = await readReportBytes('report.xml', encoder.encode(SAMPLE));
    expect(files).toHaveLength(1);
    expect(files[0]?.xml).toContain('<feedback>');
  });

  it('reads a gzipped report and drops the .gz from its name', async () => {
    const files = await readReportBytes(
      'google.com!example.com!1706745600!1706832000.xml.gz',
      await gzip(SAMPLE),
    );
    expect(files[0]?.name).toBe('google.com!example.com!1706745600!1706832000.xml');
    expect(files[0]?.xml).toContain('209.85.220.41');
  });

  it('reads a gzipped report that was misnamed .zip', async () => {
    // Receivers have shipped this. The extension is a suggestion.
    const files = await readReportBytes('report.zip', await gzip(SAMPLE));
    expect(files[0]?.xml).toContain('<feedback>');
  });

  it('reads every entry out of a zip', async () => {
    const files = await readReportBytes('reports.zip', storedZip('inner.xml', SAMPLE));
    expect(files).toHaveLength(1);
    expect(files[0]?.name).toBe('inner.xml');
    expect(files[0]?.xml).toContain('<feedback>');
  });

  it('explains a file it cannot open instead of failing silently', async () => {
    await expect(readReportBytes('holiday.jpg', new Uint8Array([0xff, 0xd8, 0xff]))).rejects.toThrow(
      DecompressError,
    );
    await expect(readReportBytes('holiday.jpg', new Uint8Array([0xff, 0xd8, 0xff]))).rejects.toThrow(
      /exactly as it arrived/,
    );
  });
});
