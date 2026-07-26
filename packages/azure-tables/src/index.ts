import type { TableClient } from "@azure/data-tables";
import type {
  AuditedRoleAssignmentMutationStore,
  PrincipalLookupStore,
  RoleAssignmentAuditReader,
  RoleAssignmentReader,
} from "@pegma/authorization-storage";

/**
 * The Azure operations required by this adapter.
 *
 * Hosts construct and provision the real `TableClient`, including credentials,
 * retry policy, telemetry, table name, and primary-region endpoint.
 */
export type AzureTableClient = Pick<
  TableClient,
  "getEntity" | "listEntities" | "submitTransaction"
>;

export interface AzureTableStorageAdapterOptions {
  readonly tableClient: AzureTableClient;
  /** Exact host-application namespace, fixed for this adapter instance. */
  readonly applicationId: string;
}

/**
 * Durable Azure Table Storage adapter with safe combined role mutations.
 *
 * Raw role and audit mutation ports are intentionally absent so callers cannot
 * split the assignment transaction from its derived lifecycle audit event.
 */
export interface AzureTableStorageAdapter
  extends
    PrincipalLookupStore,
    RoleAssignmentReader,
    RoleAssignmentAuditReader,
    AuditedRoleAssignmentMutationStore {}

export {
  createAzureTableIdentityLinkEntity,
  createAzureTableStorageAdapter,
} from "./azure-table-storage.js";
