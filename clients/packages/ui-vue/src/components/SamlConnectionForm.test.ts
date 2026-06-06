import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { type YAuthContext, YAuthKey } from "../provider";
import SamlConnectionForm from "./SamlConnectionForm.vue";

const VALID_CERT = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUExampleFakeCertForTestingOnlyXX=
-----END CERTIFICATE-----`;

function createMockContext(
	overrides: Partial<YAuthContext> = {},
): YAuthContext {
	return {
		client: {
			organizations: {
				listSsoConnections: vi.fn().mockResolvedValue({ sso_connections: [] }),
				createSsoConnection: vi.fn().mockResolvedValue({
					id: "conn-1",
					organization_id: "org-1",
					name: "Acme Okta SAML",
					kind: "saml_sp",
					status: "draft",
					oidc: null,
					saml: {
						idp_entity_id: "urn:idp:acme:saml",
						idp_sso_url: "https://acme.okta.com/sso/saml",
						idp_x509_cert: "********",
						sp_entity_id: "https://app/sso/saml/metadata/conn-1",
						sp_acs_url: "https://app/sso/saml/acs",
						sp_private_key: null,
						idp_initiated_sso_allowed: false,
						assertion_signed_required: true,
						response_signed_required: true,
						want_encrypted_assertions: false,
						idp_slo_url: null,
						attribute_mappings: {
							email:
								"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
							display_name: null,
							external_id: "NameID",
							groups: null,
							group_to_role: {},
						},
					},
					jit_provisioning_enabled: true,
					default_role_on_jit: "member",
					created_at: "2026-05-17T00:00:00",
					updated_at: "2026-05-17T00:00:00",
				}),
			},
		} as never,
		user: { value: null } as never,
		loading: { value: false } as never,
		mustChangePassword: { value: false } as never,
		flagMustChangePassword: vi.fn(),
		refetch: vi.fn().mockResolvedValue(null),
		...overrides,
	};
}

describe("SamlConnectionForm", () => {
	it("renders the IdP entity / SSO / cert inputs", () => {
		const ctx = createMockContext();
		const wrapper = mount(SamlConnectionForm, {
			props: { organizationId: "org-1" },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		expect(wrapper.text()).toContain("IdP Entity ID");
		expect(wrapper.text()).toContain("IdP Single Sign-On URL");
		expect(wrapper.text()).toContain("IdP X.509 Signing Certificate (PEM)");
		expect(wrapper.find("textarea").exists()).toBe(true);
	});

	it("keeps submit disabled until required fields are valid", async () => {
		const ctx = createMockContext();
		const wrapper = mount(SamlConnectionForm, {
			props: { organizationId: "org-1" },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		const submitBtn = wrapper.find("button[type='submit']");
		expect(submitBtn.attributes("disabled")).toBeDefined();

		const inputs = wrapper.findAll("input");
		await inputs[0]!.setValue("Acme Okta SAML"); // name
		await inputs[1]!.setValue("urn:idp:acme:saml"); // idp_entity_id
		await inputs[2]!.setValue("https://acme.okta.com/sso/saml"); // idp_sso_url

		// Still disabled — cert is empty
		expect(submitBtn.attributes("disabled")).toBeDefined();

		// First textarea is the cert
		await wrapper.findAll("textarea")[0]!.setValue(VALID_CERT);

		expect(submitBtn.attributes("disabled")).toBeUndefined();
	});

	it("calls createSsoConnection with kind=saml_sp on submit", async () => {
		const createMock = vi.fn().mockResolvedValue({
			id: "conn-1",
			organization_id: "org-1",
			name: "Acme Okta SAML",
			kind: "saml_sp",
			status: "draft",
			oidc: null,
			saml: {
				idp_entity_id: "urn:idp:acme:saml",
				idp_sso_url: "https://acme.okta.com/sso/saml",
				idp_x509_cert: "********",
				sp_entity_id: "https://app/sso/saml/metadata/conn-1",
				sp_acs_url: "https://app/sso/saml/acs",
				sp_private_key: null,
				idp_initiated_sso_allowed: false,
				assertion_signed_required: true,
				response_signed_required: true,
				want_encrypted_assertions: false,
				idp_slo_url: null,
				attribute_mappings: {
					email: "x",
					display_name: null,
					external_id: "NameID",
					groups: null,
					group_to_role: {},
				},
			},
			jit_provisioning_enabled: true,
			default_role_on_jit: "member",
			created_at: "2026-05-17T00:00:00",
			updated_at: "2026-05-17T00:00:00",
		});
		const onSuccess = vi.fn();
		const ctx = createMockContext({
			client: {
				organizations: {
					listSsoConnections: vi.fn().mockResolvedValue({ sso_connections: [] }),
					createSsoConnection: createMock,
				},
			} as never,
		});

		const wrapper = mount(SamlConnectionForm, {
			props: { organizationId: "org-1", onSuccess },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		const inputs = wrapper.findAll("input");
		await inputs[0]!.setValue("Acme Okta SAML");
		await inputs[1]!.setValue("urn:idp:acme:saml");
		await inputs[2]!.setValue("https://acme.okta.com/sso/saml");
		await wrapper.findAll("textarea")[0]!.setValue(VALID_CERT);
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(createMock).toHaveBeenCalledTimes(1);
		});
		const call = createMock.mock.calls[0]!;
		expect(call[0]).toBe("org-1");
		expect(call[1].kind).toBe("saml_sp");
		expect(call[1].saml.idp_entity_id).toBe("urn:idp:acme:saml");
		expect(call[1].saml.idp_sso_url).toBe("https://acme.okta.com/sso/saml");
		expect(call[1].saml.assertion_signed_required).toBe(true);
		expect(call[1].saml.response_signed_required).toBe(true);
		expect(call[1].saml.idp_initiated_sso_allowed).toBe(false);
		expect(onSuccess).toHaveBeenCalled();
	});

	it("surfaces an alert when the create call fails", async () => {
		const createMock = vi
			.fn()
			.mockRejectedValue(new Error("idp_sso_url must be HTTPS"));
		const onError = vi.fn();
		const ctx = createMockContext({
			client: {
				organizations: {
					listSsoConnections: vi.fn().mockResolvedValue({ sso_connections: [] }),
					createSsoConnection: createMock,
				},
			} as never,
		});

		const wrapper = mount(SamlConnectionForm, {
			props: { organizationId: "org-1", onError },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		const inputs = wrapper.findAll("input");
		await inputs[0]!.setValue("Acme Okta SAML");
		await inputs[1]!.setValue("urn:idp:acme:saml");
		await inputs[2]!.setValue("https://acme.okta.com/sso/saml");
		await wrapper.findAll("textarea")[0]!.setValue(VALID_CERT);
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(wrapper.text()).toContain("idp_sso_url must be HTTPS");
			expect(onError).toHaveBeenCalled();
		});
	});
});
