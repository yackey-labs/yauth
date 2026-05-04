import { createYAuthClient } from "@yackey-labs/yauth-client";
import { YAuthPlugin } from "@yackey-labs/yauth-ui-vue";
import { createApp } from "vue";
import App from "./App.vue";
import { router } from "./router";
import "./style.css";

const client = createYAuthClient({ baseUrl: "/api/auth" });

createApp(App)
	.use(YAuthPlugin, { client })
	.use(router)
	.mount("#app");
