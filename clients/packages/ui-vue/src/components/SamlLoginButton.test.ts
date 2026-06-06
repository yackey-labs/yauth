import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { type YAuthContext, YAuthKey } from "../provider";
import SamlLoginButton from "./SamlLoginButton.vue";

function createMockContext(): YAuthContext {
	return {
		client: {
			sso: {
				loginUrl: vi.fn(),
				samlLoginUrl: vi.fn(
					(opts: { org?: string; domain?: string; redirectTo?: string }) => {
						const params = new URLSearchParams();
						if (opts.org) params.set("org", opts.org);
						if (opts.domain) params.set("domain", opts.domain);
						if (opts.redirectTo) params.set("redirect_to", opts.redirectTo);
						return `/api/auth/sso/saml/login?${params.toString()}`;
					},
				),
				samlMetadataUrl: vi.fn((id: string) => `/api/auth/sso/saml/metadata/${id}`),
			},
		} as never,
		user: { value: null } as never,
		loading: { value: false } as never,
		mustChangePassword: { value: false } as never,
		flagMustChangePassword: vi.fn(),
		refetch: vi.fn().mockResolvedValue(null),
	};
}

describe("SamlLoginButton", () => {
	it("renders nothing when neither orgSlug nor domain is provided", () => {
		const ctx = createMockContext();
		const wrapper = mount(SamlLoginButton, {
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});
		expect(wrapper.find("a").exists()).toBe(false);
	});

	it("builds the correct /sso/saml/login URL for an orgSlug", () => {
		const ctx = createMockContext();
		const wrapper = mount(SamlLoginButton, {
			props: { orgSlug: "acme", redirectTo: "/dashboard" },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});
		const a = wrapper.find("a");
		expect(a.exists()).toBe(true);
		const href = a.attributes("href") ?? "";
		expect(href).toContain("/sso/saml/login");
		expect(href).toContain("org=acme");
		expect(href).toContain("redirect_to=%2Fdashboard");
	});

	it("supports the domain HRD path", () => {
		const ctx = createMockContext();
		const wrapper = mount(SamlLoginButton, {
			props: { domain: "acme.com" },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});
		const href = wrapper.find("a").attributes("href") ?? "";
		expect(href).toContain("domain=acme.com");
	});

	it("uses the label override when provided", () => {
		const ctx = createMockContext();
		const wrapper = mount(SamlLoginButton, {
			props: { orgSlug: "acme", label: "Sign in with Okta SAML" },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});
		expect(wrapper.text()).toContain("Sign in with Okta SAML");
	});

	it("falls back to a default label", () => {
		const ctx = createMockContext();
		const wrapper = mount(SamlLoginButton, {
			props: { orgSlug: "acme" },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});
		expect(wrapper.text()).toContain("Sign in via SAML");
	});
});
