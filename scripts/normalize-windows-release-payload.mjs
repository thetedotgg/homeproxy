#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";

const MARKER_PREFIX = Buffer.from("__TAURI_BUNDLE_TYPE_VAR_", "ascii");
const MARKER_STANDALONE = Buffer.from("__TAURI_BUNDLE_TYPE_VAR_UNK", "ascii");
const MARKER_NSIS = Buffer.from("__TAURI_BUNDLE_TYPE_VAR_NSS", "ascii");
const MARKER_NORMALIZED = Buffer.from("__TAURI_BUNDLE_TYPE_VAR_CMP", "ascii");

function fail(message) {
  console.error(`Windows PE normalization failed: ${message}`);
  process.exit(1);
}

function requireRange(buffer, offset, length, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > buffer.length) {
    fail(`${label} is outside the file.`);
  }
}

function findAll(buffer, needle) {
  const offsets = [];
  let offset = 0;
  while (offset <= buffer.length - needle.length) {
    const found = buffer.indexOf(needle, offset);
    if (found === -1) break;
    offsets.push(found);
    offset = found + 1;
  }
  return offsets;
}

function normalizePe(path, expectedMarker, label) {
  const input = readFileSync(path);
  requireRange(input, 0, 64, `${label} DOS header`);
  if (input.toString("ascii", 0, 2) !== "MZ") fail(`${label} has no MZ header.`);

  const peOffset = input.readUInt32LE(0x3c);
  requireRange(input, peOffset, 24, `${label} PE header`);
  if (!input.subarray(peOffset, peOffset + 4).equals(Buffer.from("PE\0\0", "binary"))) {
    fail(`${label} has no PE signature.`);
  }

  const optionalHeaderSize = input.readUInt16LE(peOffset + 20);
  const optionalHeaderOffset = peOffset + 24;
  requireRange(input, optionalHeaderOffset, optionalHeaderSize, `${label} optional header`);

  const optionalMagic = input.readUInt16LE(optionalHeaderOffset);
  let numberOfDirectoriesOffset;
  let dataDirectoriesOffset;
  if (optionalMagic === 0x10b) {
    numberOfDirectoriesOffset = optionalHeaderOffset + 92;
    dataDirectoriesOffset = optionalHeaderOffset + 96;
  } else if (optionalMagic === 0x20b) {
    numberOfDirectoriesOffset = optionalHeaderOffset + 108;
    dataDirectoriesOffset = optionalHeaderOffset + 112;
  } else {
    fail(`${label} has unsupported PE optional-header magic 0x${optionalMagic.toString(16)}.`);
  }

  const checksumOffset = optionalHeaderOffset + 64;
  const securityDirectoryOffset = dataDirectoriesOffset + 4 * 8;
  requireRange(input, checksumOffset, 4, `${label} PE checksum`);
  requireRange(input, numberOfDirectoriesOffset, 4, `${label} data-directory count`);
  if (input.readUInt32LE(numberOfDirectoriesOffset) < 5) {
    fail(`${label} has no certificate-table data-directory entry.`);
  }
  if (securityDirectoryOffset + 8 > optionalHeaderOffset + optionalHeaderSize) {
    fail(`${label} certificate-table entry exceeds the optional header.`);
  }

  const certificateOffset = input.readUInt32LE(securityDirectoryOffset);
  const certificateSize = input.readUInt32LE(securityDirectoryOffset + 4);
  if ((certificateOffset === 0) !== (certificateSize === 0)) {
    fail(`${label} has an incomplete certificate-table entry.`);
  }
  if (certificateSize !== 0) {
    if (certificateOffset % 8 !== 0) fail(`${label} certificate table is not 8-byte aligned.`);
    requireRange(input, certificateOffset, certificateSize, `${label} certificate table`);
    if (certificateOffset + certificateSize !== input.length) {
      fail(`${label} certificate table is not terminal.`);
    }
  }

  const markerOffsets = findAll(input, MARKER_PREFIX);
  if (markerOffsets.length !== 2 || markerOffsets[1] !== markerOffsets[0] + MARKER_NSIS.length) {
    fail(`${label} must contain exactly one contiguous Tauri bundle marker pair; found ${markerOffsets.length} marker prefixes.`);
  }
  if (!input.subarray(markerOffsets[0], markerOffsets[0] + MARKER_NSIS.length).equals(MARKER_NSIS)) {
    fail(`${label} contains an unexpected Tauri bundle-type sentinel.`);
  }
  const markerOffset = markerOffsets[1];
  requireRange(input, markerOffset, expectedMarker.length, `${label} Tauri bundle marker`);
  if (!input.subarray(markerOffset, markerOffset + expectedMarker.length).equals(expectedMarker)) {
    fail(`${label} contains an unexpected Tauri bundle marker.`);
  }

  const normalizedLength = certificateSize === 0 ? input.length : certificateOffset;
  if (markerOffset + MARKER_NORMALIZED.length > normalizedLength) {
    fail(`${label} Tauri bundle marker overlaps the certificate table.`);
  }
  const normalized = Buffer.from(input.subarray(0, normalizedLength));
  normalized.fill(0, checksumOffset, checksumOffset + 4);
  normalized.fill(0, securityDirectoryOffset, securityDirectoryOffset + 8);
  MARKER_NORMALIZED.copy(normalized, markerOffset);
  return normalized;
}

if (process.argv.length !== 6) {
  fail("usage: normalize-windows-release-payload.mjs <standalone.exe> <nsis-payload.exe> <normalized-standalone.exe> <normalized-payload.exe>");
}

const [, , standalonePath, payloadPath, normalizedStandalonePath, normalizedPayloadPath] = process.argv;
writeFileSync(normalizedStandalonePath, normalizePe(standalonePath, MARKER_STANDALONE, "standalone application"), { flag: "wx", mode: 0o600 });
writeFileSync(normalizedPayloadPath, normalizePe(payloadPath, MARKER_NSIS, "NSIS application payload"), { flag: "wx", mode: 0o600 });
