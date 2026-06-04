<script setup lang="ts">
import { ref } from "vue";
import {
  type CreateDestinationInput,
  useAuditDestinations,
} from "../composables/useAuditExport";

const props = defineProps<{
  organizationId?: string | null;
}>();

const emit = defineEmits<{ created: [void] }>();

const { create, submitting, error } = useAuditDestinations(
  () => props.organizationId ?? null,
);

const kindTag = ref<"webhook" | "syslog" | "s3" | "splunk" | "datadog">(
  "webhook",
);
const name = ref("");

// Webhook fields
const webhookUrl = ref("");
const webhookFormat = ref<"json" | "cef" | "rfc5424">("json");
const webhookHmac = ref("");

// Syslog fields
const syslogHost = ref("");
const syslogPort = ref(6514);
const syslogTransport = ref<"tcp" | "udp" | "tls">("tcp");
const syslogFacility = ref(13);

// S3 fields
const s3Bucket = ref("");
const s3Prefix = ref("audit");
const s3Region = ref("us-east-1");
const s3Partition = ref<"by_date" | "by_org" | "by_date_and_org">("by_date");

async function onSubmit() {
  let kind: CreateDestinationInput["kind"];
  switch (kindTag.value) {
    case "webhook":
      kind = {
        type: "webhook",
        url: webhookUrl.value.trim(),
        format: webhookFormat.value,
        hmac_secret: webhookHmac.value.trim() || undefined,
      };
      break;
    case "syslog":
      kind = {
        type: "syslog",
        host: syslogHost.value.trim(),
        port: syslogPort.value,
        transport: syslogTransport.value,
        facility: syslogFacility.value,
      };
      break;
    case "s3":
      kind = {
        type: "s3",
        bucket: s3Bucket.value.trim(),
        prefix: s3Prefix.value.trim(),
        region: s3Region.value.trim(),
        partition: s3Partition.value,
      };
      break;
    case "splunk":
      kind = {
        type: "splunk",
        hec_url: "https://splunk.example.com:8088",
        hec_token: "TODO: token", // stub — not deliverable yet
      };
      break;
    case "datadog":
      kind = {
        type: "datadog",
        site: "datadoghq.com",
        api_key: "TODO: key", // stub — not deliverable yet
      };
      break;
  }
  try {
    await create({
      name: name.value.trim(),
      organization_id: props.organizationId ?? undefined,
      kind,
    });
    emit("created");
    name.value = "";
    webhookUrl.value = "";
    webhookHmac.value = "";
    syslogHost.value = "";
    s3Bucket.value = "";
  } catch {
    // surfaced via error ref
  }
}
</script>

<template>
  <form class="space-y-3 rounded-md border border-border p-4" @submit.prevent="onSubmit">
    <h3 class="text-base font-semibold">Add destination</h3>

    <div
      v-if="error"
      class="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive"
      role="alert"
      aria-live="polite"
    >
      {{ error }}
    </div>

    <label class="block">
      <span class="text-xs font-medium">Name</span>
      <input
        v-model="name"
        type="text"
        required
        class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
      />
    </label>

    <label class="block">
      <span class="text-xs font-medium">Kind</span>
      <select
        v-model="kindTag"
        class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm focus:outline-none focus:ring-1 focus:ring-ring"
      >
        <option value="webhook">Webhook (HTTPS POST)</option>
        <option value="syslog">Syslog (RFC 5424)</option>
        <option value="s3">S3-compatible object storage</option>
        <option value="splunk">Splunk HEC (follow-up)</option>
        <option value="datadog">Datadog logs (follow-up)</option>
      </select>
    </label>

    <fieldset v-if="kindTag === 'webhook'" class="space-y-2">
      <label class="block">
        <span class="text-xs font-medium">URL</span>
        <input
          v-model="webhookUrl"
          type="url"
          required
          placeholder="https://hooks.example.com/yauth-audit"
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        />
      </label>
      <label class="block">
        <span class="text-xs font-medium">Format</span>
        <select
          v-model="webhookFormat"
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        >
          <option value="json">JSON</option>
          <option value="cef">CEF</option>
          <option value="rfc5424">RFC 5424 syslog body</option>
        </select>
      </label>
      <label class="block">
        <span class="text-xs font-medium">HMAC secret (optional)</span>
        <input
          v-model="webhookHmac"
          type="password"
          placeholder="cryptographic random, 32 bytes recommended"
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        />
        <p class="mt-1 text-xs text-muted-foreground">
          When set, each request carries
          <code class="font-mono">X-Yauth-Signature: t=&lt;unix&gt;,v1=&lt;hex&gt;</code>.
          See <code>docs/audit-export/webhook.md</code> for the verifier helper
          (Node + Python).
        </p>
      </label>
    </fieldset>

    <fieldset v-else-if="kindTag === 'syslog'" class="space-y-2">
      <label class="block">
        <span class="text-xs font-medium">Host</span>
        <input
          v-model="syslogHost"
          type="text"
          required
          placeholder="siem.example.internal"
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        />
      </label>
      <label class="block">
        <span class="text-xs font-medium">Port</span>
        <input
          v-model.number="syslogPort"
          type="number"
          required
          min="1"
          max="65535"
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        />
      </label>
      <label class="block">
        <span class="text-xs font-medium">Transport</span>
        <select
          v-model="syslogTransport"
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        >
          <option value="tcp">TCP (RFC 6587 octet-counted)</option>
          <option value="udp">UDP (unauthenticated, not recommended)</option>
          <option value="tls">TCP + TLS (follow-up)</option>
        </select>
      </label>
      <label class="block">
        <span class="text-xs font-medium">Facility (0–23)</span>
        <input
          v-model.number="syslogFacility"
          type="number"
          required
          min="0"
          max="23"
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        />
      </label>
    </fieldset>

    <fieldset v-else-if="kindTag === 's3'" class="space-y-2">
      <label class="block">
        <span class="text-xs font-medium">Bucket</span>
        <input
          v-model="s3Bucket"
          type="text"
          required
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        />
      </label>
      <label class="block">
        <span class="text-xs font-medium">Prefix</span>
        <input
          v-model="s3Prefix"
          type="text"
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        />
      </label>
      <label class="block">
        <span class="text-xs font-medium">Region</span>
        <input
          v-model="s3Region"
          type="text"
          required
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        />
      </label>
      <label class="block">
        <span class="text-xs font-medium">Partition</span>
        <select
          v-model="s3Partition"
          class="mt-1 block w-full rounded-md border border-input bg-transparent px-3 py-1.5 text-sm shadow-sm"
        >
          <option value="by_date">By date</option>
          <option value="by_org">By org</option>
          <option value="by_date_and_org">By date and org</option>
        </select>
      </label>
    </fieldset>

    <fieldset
      v-else-if="kindTag === 'splunk' || kindTag === 'datadog'"
      class="rounded-md bg-amber-500/10 px-3 py-2 text-xs text-amber-700"
    >
      {{ kindTag === "splunk" ? "Splunk HEC" : "Datadog logs" }} dispatch is
      accepted at the API but currently returns
      <code>NotImplemented</code> — events will dead-letter immediately. See
      <code>docs/audit-export/splunk.md</code> for the follow-up plan.
    </fieldset>

    <button
      type="submit"
      :disabled="submitting"
      class="inline-flex h-9 cursor-pointer items-center justify-center rounded-md bg-primary px-4 text-sm font-medium text-primary-foreground shadow hover:bg-primary/90 disabled:pointer-events-none disabled:opacity-50"
    >
      Add destination
    </button>
  </form>
</template>
