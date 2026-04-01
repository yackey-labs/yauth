/// <reference types="vite/client" />
declare module "*.vue" {
	import type { DefineComponent } from "vue";
	// biome-ignore lint/complexity/noBannedTypes: standard Vue module declaration
	const component: DefineComponent<{}, {}, any>;
	export default component;
}
