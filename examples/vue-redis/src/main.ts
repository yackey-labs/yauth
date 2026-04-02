import { YAuthPlugin } from "@yackey-labs/yauth-ui-vue";
import { createApp } from "vue";
import App from "./App.vue";
import { router } from "./router";

createApp(App)
	.use(YAuthPlugin, { baseUrl: "/api/auth" })
	.use(router)
	.mount("#app");
