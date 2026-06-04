import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import { type YAuthContext, YAuthKey } from "../provider";
import OrganizationCreate from "./OrganizationCreate.vue";

function createMockContext(
	overrides: Partial<YAuthContext> = {},
): YAuthContext {
	return {
		client: {
			organizations: {
				list: vi.fn().mockResolvedValue([]),
				create: vi.fn().mockResolvedValue({
					id: "org-1",
					name: "Acme",
					slug: "acme",
					display_name: null,
					avatar_url: null,
					created_at: "2026-05-17T00:00:00",
					updated_at: "2026-05-17T00:00:00",
				}),
			},
		} as never,
		user: { value: null } as never,
		loading: { value: false } as never,
		refetch: vi.fn().mockResolvedValue(null),
		...overrides,
	};
}

describe("OrganizationCreate", () => {
	it("renders name + slug + display name inputs", () => {
		const ctx = createMockContext();
		const wrapper = mount(OrganizationCreate, {
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});
		expect(wrapper.find("#yauth-org-create-name").exists()).toBe(true);
		expect(wrapper.find("#yauth-org-create-slug").exists()).toBe(true);
		expect(wrapper.find("#yauth-org-create-display-name").exists()).toBe(true);
	});

	it("auto-derives slug from name until edited", async () => {
		const ctx = createMockContext();
		const wrapper = mount(OrganizationCreate, {
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		await wrapper.find("#yauth-org-create-name").setValue("Acme  Corp! 2026");
		const slug = wrapper.find<HTMLInputElement>("#yauth-org-create-slug")
			.element.value;
		expect(slug).toBe("acme-corp-2026");
	});

	it("calls client.organizations.create on submit", async () => {
		const createMock = vi.fn().mockResolvedValue({
			id: "org-1",
			name: "Acme",
			slug: "acme",
			display_name: null,
			avatar_url: null,
			created_at: "2026-05-17T00:00:00",
			updated_at: "2026-05-17T00:00:00",
		});
		const onSuccess = vi.fn();
		const ctx = createMockContext({
			client: {
				organizations: {
					list: vi.fn().mockResolvedValue([]),
					create: createMock,
				},
			} as never,
		});

		const wrapper = mount(OrganizationCreate, {
			props: { onSuccess },
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});

		await wrapper.find("#yauth-org-create-name").setValue("Acme");
		await wrapper.find("form").trigger("submit");

		await vi.waitFor(() => {
			expect(createMock).toHaveBeenCalledWith({
				name: "Acme",
				slug: "acme",
				display_name: undefined,
			});
		});
	});

	it("has proper accessibility attributes", () => {
		const ctx = createMockContext();
		const wrapper = mount(OrganizationCreate, {
			global: { provide: { [YAuthKey as symbol]: ctx } },
		});
		const nameInput = wrapper.find("#yauth-org-create-name");
		expect(nameInput.attributes("required")).toBeDefined();
		expect(
			wrapper.find("label[for='yauth-org-create-name']").exists(),
		).toBe(true);
		expect(
			wrapper.find("label[for='yauth-org-create-slug']").exists(),
		).toBe(true);
	});
});
