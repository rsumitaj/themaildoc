/**
 * `cloudflare:workers` outside workerd.
 *
 * The runtime module only exists inside the Worker, so importing anything that
 * reads a binding would fail the moment a test file touched it. This stands in
 * for it under Node, with no bindings, which is also the case worth testing:
 * every write path has to degrade quietly when the database is not there.
 */
export const env: Record<string, unknown> = {};
