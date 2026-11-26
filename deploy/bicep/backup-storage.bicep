// Olympos backup storage account, hardened per SPEC §10.3.1.
// Deploy into the customer's subscription; the server's user-assigned
// managed identity gets a data-plane role WITHOUT blobs/delete.
@description('Storage account name (3-24 lowercase alphanumerics).')
param accountName string
param location string = resourceGroup().location
@description('Container for backups.')
param containerName string = 'olympos-backups'
@description('Principal (object) ID of the Olympos server user-assigned managed identity.')
param serverIdentityPrincipalId string
@description('Subnet ID for the private endpoint (the server VNet).')
param privateEndpointSubnetId string
@minValue(0)
@maxValue(146000)
@description('Days the container default immutability policy keeps every new blob version from delete and overwrite (1 or more). 0 (the default) sets no policy and leaves version-level immutability support off on the container. A policy holds every version that long, whatever its tier, so lifecycle rules cannot delete it earlier. The policy is created unlocked. A container gets support when it is created: docs/install.md#immutability-optional.')
param defaultImmutabilityDays int = 0
@description('Send version-level immutability support on the account, as the module did before v0.4.0. Set true only for an account deployed with the module before v0.4.0, which has it on; a new account leaves it false (docs/install.md#immutability-optional).')
param accountVersionLevelSupport bool = false
@description('Lifecycle: delete by tier after N days.')
param dailyDays int = 7
param weeklyDays int = 28
param monthlyDays int = 372
@minValue(1)
@description('Lifecycle: delete the objects of a native run that never completed (olympos-state=incomplete) after N days.')
param incompleteDays int = 7
param logAnalyticsWorkspaceId string = ''

// 4. Version-level immutability support on the container only, and only with a policy. On the account only with
// accountVersionLevelSupport, for accounts deployed before v0.4.0, so that their redeploy sends the payload they
// were created with (an account can get support only at creation, and a container can have it without the
// account). Support cannot be turned off once it is on; an existing container gets it only by migration.
// With 0 the container is plain.
var immutable = defaultImmutabilityDays > 0
var versionLevelSupport = immutable ? { immutableStorageWithVersioning: { enabled: true } } : {}
var accountSupport = accountVersionLevelSupport ? { immutableStorageWithVersioning: { enabled: true } } : {}

resource sa 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: accountName
  location: location
  kind: 'StorageV2'
  sku: { name: 'Standard_ZRS' }
  properties: union({
    publicNetworkAccess: 'Disabled'          // 1. private endpoint only
    allowSharedKeyAccess: false              // 2. MI option: no shared key
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    defaultToOAuthAuthentication: true
    networkAcls: { defaultAction: 'Deny', bypass: 'None' }
  }, accountSupport)                         // 4. account-level support: accounts from before v0.4.0 only
}

resource blobSvc 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: sa
  name: 'default'
  properties: {
    isVersioningEnabled: true                                    // 4. versioning
    deleteRetentionPolicy: { enabled: true, days: 30 }           //    soft delete
    containerDeleteRetentionPolicy: { enabled: true, days: 30 }
  }
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobSvc
  name: containerName
  properties: union({ publicAccess: 'None' }, versionLevelSupport)   // 4. version-level support, with a policy only
}

// 4. Optional container default immutability policy (time-based), the storage owner's choice.
// A default policy applies to every new blob version, dry runs and probe blobs included, and a version
// under it cannot be deleted before its period ends: it keeps every object at least defaultImmutabilityDays.
// Without it, the server still cannot delete, but it can re-tag or overwrite a backup, and the lifecycle
// rules below then delete it. ARM creates the policy unlocked: it can be shortened (an update, allowed under
// the resource lock below) or, with that lock lifted, removed. Locking it
// (az storage container immutability-policy lock) cannot be undone.
// Per-tier locks set by the server at write time are planned (https://github.com/Warewave-Technology/olympos/issues/79).
resource immutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = if (immutable) {
  parent: container
  name: 'default'
  properties: {
    immutabilityPeriodSinceCreationInDays: defaultImmutabilityDays
    allowProtectedAppendWrites: false
  }
}

// Retention is done by lifecycle rules on the olympos-tier index tag (SPEC §10.3).
// The same policy deletes what a native ClickHouse run left behind when it died: its objects carry
// olympos-state=incomplete until the run's signed manifest is written, and are retagged complete after it.
// A run that completed is not touched: its objects are retagged olympos-state=complete, so the filter
// no longer matches them. Every rule uses daysAfterCreationGreaterThan, as the tier rules do.
// With a container default immutability policy (defaultImmutabilityDays > 0), a delete waits until the
// immutability period of that version ends, for every rule alike.
// With soft delete on, a version a rule deletes stays soft-deleted for 30 days and can be restored.
resource lifecycle 'Microsoft.Storage/storageAccounts/managementPolicies@2023-05-01' = {
  parent: sa
  name: 'default'
  properties: {
    policy: {
      rules: [for r in [
        { name: 'olympos-daily', tag: 'olympos-tier', value: 'daily', days: dailyDays }
        { name: 'olympos-weekly', tag: 'olympos-tier', value: 'weekly', days: weeklyDays }
        { name: 'olympos-monthly', tag: 'olympos-tier', value: 'monthly', days: monthlyDays }
        { name: 'olympos-test', tag: 'olympos-tier', value: 'test', days: 2 }
        { name: 'olympos-incomplete', tag: 'olympos-state', value: 'incomplete', days: incompleteDays }
      ]: {
        name: r.name
        enabled: true
        type: 'Lifecycle'
        definition: {
          filters: {
            blobTypes: [ 'blockBlob' ]
            blobIndexMatch: [ { name: r.tag, op: '==', value: r.value } ]
          }
          actions: {
            baseBlob: { delete: { daysAfterCreationGreaterThan: r.days } }
            version: { delete: { daysAfterCreationGreaterThan: r.days } }
          }
        }
      }]
    }
  }
}

// 3. Custom data-plane role: read/write/tag, NO delete.
resource writerRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(sa.id, 'olympos-backup-writer')
  properties: {
    roleName: 'Olympos Backup Writer (${accountName})'
    description: 'Write and tag backup blobs. Cannot delete.'
    assignableScopes: [ sa.id ]
    permissions: [ {
      actions: [ 'Microsoft.Storage/storageAccounts/blobServices/containers/read' ]
      dataActions: [
        'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'
        'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/write'
        'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/add/action'
        'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/read'
        'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/tags/write'
      ]
      notDataActions: [ 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/delete' ]
    } ]
  }
}

resource assignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(container.id, serverIdentityPrincipalId, writerRole.id)
  scope: container
  properties: {
    principalId: serverIdentityPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: writerRole.id
  }
}

// 1. Private endpoint in the server VNet (DNS zone link is environment-specific).
resource pe 'Microsoft.Network/privateEndpoints@2023-11-01' = {
  name: '${accountName}-blob-pe'
  location: location
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [ {
      name: 'blob'
      properties: { privateLinkServiceId: sa.id, groupIds: [ 'blob' ] }
    } ]
  }
}

// 5. Resource lock.
resource lock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'olympos-backups-cannot-delete'
  scope: sa
  properties: { level: 'CanNotDelete', notes: 'Olympos backup storage (SPEC §10.3.1)' }
}

// 7. Diagnostics to Log Analytics.
resource diag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (!empty(logAnalyticsWorkspaceId)) {
  name: 'olympos-blob-audit'
  scope: blobSvc
  properties: {
    workspaceId: logAnalyticsWorkspaceId
    logs: [
      { category: 'StorageRead', enabled: true }
      { category: 'StorageWrite', enabled: true }
      { category: 'StorageDelete', enabled: true }
    ]
  }
}

output accountId string = sa.id
output writerRoleId string = writerRole.id
