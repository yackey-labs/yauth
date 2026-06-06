import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { type YAuthContext, YAuthKey } from "../provider";
import SsoConnectionList from "./SsoConnectionList.vue";

const samlConnection = {
	id: "conn-saml-1",
	organization_id: "org-1",
	name: "Acme Okta SAML",
	kind: "saml_sp",
	status: "active",
	oidc: null,
	saml: {
		idp_entity_id: "urn:idp:acme:saml",
		idp_sso_url: "https://acme.okta.com/sso/saml",
		idp_x509_cert: "********",
		sp_entity_id: "https://app/sso/saml/metadata/conn-saml-1",
		sp_acs_url: "https://app/sso/saml/acs",
		sp_private_key: null,
		idp_initiated_sso_allowed: false,
		assertion_signed_required: true,
		response_signed_required: true,
		want_encrypted_assertions: false,
		idp_slo_url: null,
		attribute_mappings: {
			email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
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
};

function createMockContext(): YAuthContext {
	return {
		client: {
			sso: {
				loginUrl: vi.fn(),
				samlLoginUrl: vi.fn(),
				samlMetadataUrl: vi.fn(
					(id: string) => `/api/auth/sso/saml/metadata/${id}`,
				),
			},
			organizations: {
				listSsoConnections: vi
					.fn()
					.mockResolvedValue({ sso_connections: [samlConnection] }),
				updateSsoConnection: vi.fn(),
				deleteSsoConnection: vi.fn(),
				testSsoConnection: vi.fn(),
			},
		} as never,
		user: { value: null } as never,
		loading: { value: false } as never,
		mustChangePassword: { value: false } as never,
		flagMustChangePassword: vi.fn(),
		refetch: vi.fn().mockResolvedValue(null),
	};
}

describe("SsoConnectionList (SAML)", () => {
	it("renders the SAML connection's IdP and SP entity IDs", async () => {
		const ctx = createMockContext();
		const wrapper = mount(SsoConnectionList, {
			props: { organizationId: "org-1" },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		await vi.waitFor(() => {
			expect(wrapper.text()).toContain("Acme Okta SAML");
		});
		expect(wrapper.text()).toContain("urn:idp:acme:saml");
		expect(wrapper.text()).toContain("https://app/sso/saml/metadata/conn-saml-1");
	});

	it("exposes a SAML SP metadata download link", async () => {
		const ctx = createMockContext();
		const wrapper = mount(SsoConnectionList, {
			props: { organizationId: "org-1" },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		await vi.waitFor(() => {
			expect(wrapper.find("[data-testid='saml-metadata-download']").exists()).toBe(
				true,
			);
		});
		const link = wrapper.find("[data-testid='saml-metadata-download']");
		expect(link.attributes("href")).toBe(
			"/api/auth/sso/saml/metadata/conn-saml-1",
		);
		expect(link.attributes("download")).toBe("sp-metadata-conn-saml-1.xml");
	});

	it("summarises signing requirements", async () => {
		const ctx = createMockContext();
		const wrapper = mount(SsoConnectionList, {
			props: { organizationId: "org-1" },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		await vi.waitFor(() => {
			expect(wrapper.text()).toContain("assertion signed");
		});
		expect(wrapper.text()).toContain("response signed");
	});
});
