/**
 * FIDO Alliance MDS AAGUID -> device name mapping.
 * Used to resolve human-friendly names for passkey authenticators.
 *
 * Source: https://github.com/nickspatties/passkeys-aaguid
 * Updated periodically. Falls back to "Unknown" for unrecognized AAGUIDs.
 */
export const AAGUID_MAP: Record<string, string> = {
	// Apple
	"fbfc3007-154e-4ecc-8c0b-6e020557d7bd": "iCloud Keychain",
	"dd4ec289-e01d-41c9-bb89-70fa845d4bf2": "iCloud Keychain (Managed)",

	// Google
	"adce0002-35bc-c60a-648b-0b25f1f05503": "Chrome on Mac",
	"ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": "Google Password Manager",
	"b5397571-f314-4571-9173-2155a0baf341": "Google Password Manager",

	// Microsoft
	"6028b017-b1d4-4c02-b4b3-afcdafc96bb2": "Windows Hello",
	"9ddd1817-af5a-4672-a2b9-3e3dd95000a9": "Windows Hello",
	"08987058-cadc-4b81-b6e1-30de50dcbe96": "Windows Hello",

	// YubiKey
	"2fc0579f-8113-47ea-b116-bb5a8db9202a": "YubiKey 5 Series (USB-A, NFC)",
	"73bb0cd4-e502-49b8-9c6f-b59445bf720b": "YubiKey 5 FIPS Series",
	"c5ef55ff-ad9a-4b9f-b580-adebafe026d0": "YubiKey 5Ci FIPS",
	"85203421-48f9-4355-9bc8-8a53846e5083": "YubiKey 5Ci",
	"d8522d9f-575b-4866-88a9-ba99fa02f35b": "YubiKey Bio Series (USB-A)",
	"ee882879-721c-4913-9775-3dfcee97617a": "YubiKey Bio Series (USB-C)",
	"fa2b99dc-9e39-4257-8f92-4a30d23c4118": "YubiKey 5 Series (USB-C, NFC)",
	"cb69481e-8ff7-4039-93ec-0a2729a154a8": "YubiKey 5 Series (USB-C)",
	"c1f9a0bc-1dd2-404a-b27f-8e29047a43fd":
		"YubiKey 5 Series (USB-A, NFC, FIDO2)",
	"f8a011f3-8c0a-4d15-8006-17111f9edc7d": "Security Key by Yubico (USB-A, NFC)",
	"b92c3f9a-c014-4056-887f-140a2501163b": "Security Key by Yubico (USB-C, NFC)",
	"6d44ba9b-f6ec-2e49-b930-0c8fe920cb73": "Security Key by Yubico (USB-C)",
	"149a2021-8ef6-4133-96b8-81f8d5b7f1f5":
		"Security Key by Yubico (USB-A, FIDO2)",

	// 1Password
	"bada5566-a7aa-401f-bd96-45619a55120d": "1Password",
	"b84e4048-15dc-4dd0-8640-f4f60813c8af": "1Password",

	// Bitwarden
	"d548826e-79b4-db40-a3d8-11116f7e8349": "Bitwarden",

	// Dashlane
	"531126d6-e717-415c-9320-3d9aa6981239": "Dashlane",

	// Samsung
	"53414d53-554e-4700-0000-000000000000": "Samsung Pass",

	// Thales
	"b267239b-954f-4041-a01b-ee4f33c145b7": "Thales IDPrime FIDO Bio",

	// KeePass
	"fdb141b2-5d84-443e-8a35-4698c205a502": "KeePassXC",
};

/** Resolve an AAGUID to a human-friendly device name */
export function resolveAAGUID(aaguid: string): string | null {
	return AAGUID_MAP[aaguid.toLowerCase()] ?? null;
}
