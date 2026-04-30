import { describe, expect, test } from "bun:test";
import { AAGUID_MAP, resolveAAGUID } from "./aaguid";

describe("AAGUID_MAP", () => {
	test("contains known Apple entry", () => {
		expect(AAGUID_MAP["fbfc3007-154e-4ecc-8c0b-6e020557d7bd"]).toBe(
			"iCloud Keychain",
		);
	});

	test("contains known YubiKey entry", () => {
		expect(AAGUID_MAP["2fc0579f-8113-47ea-b116-bb5a8db9202a"]).toBe(
			"YubiKey 5 Series (USB-A, NFC)",
		);
	});

	test("returns undefined for unknown AAGUID", () => {
		expect(AAGUID_MAP["00000000-0000-0000-0000-000000000000"]).toBeUndefined();
	});
});

describe("resolveAAGUID", () => {
	test("resolves known AAGUID", () => {
		expect(resolveAAGUID("fbfc3007-154e-4ecc-8c0b-6e020557d7bd")).toBe(
			"iCloud Keychain",
		);
	});

	test("resolves case-insensitively", () => {
		expect(resolveAAGUID("FBFC3007-154E-4ECC-8C0B-6E020557D7BD")).toBe(
			"iCloud Keychain",
		);
	});

	test("returns null for unknown AAGUID", () => {
		expect(resolveAAGUID("00000000-0000-0000-0000-000000000000")).toBeNull();
	});

	test("resolves 1Password entry", () => {
		expect(resolveAAGUID("bada5566-a7aa-401f-bd96-45619a55120d")).toBe(
			"1Password",
		);
	});

	test("resolves Windows Hello entry", () => {
		expect(resolveAAGUID("6028b017-b1d4-4c02-b4b3-afcdafc96bb2")).toBe(
			"Windows Hello",
		);
	});
});
