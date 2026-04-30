import { createYAuthClient } from "@yackey-labs/yauth-go-client";
import { YAuthPlugin } from "@yackey-labs/yauth-go-ui-vue";
import { createApp } from "vue";
import App from "./App.vue";
import { router } from "./router";

const client = createYAuthClient({ baseUrl: "/api/auth" });

createApp(App)
	.use(YAuthPlugin, { client })
	.use(router)
	.mount("#app");
