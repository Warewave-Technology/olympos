// Olympos Key Vault: the KEK (envelope encryption), the key that signs the
// manifests of native ClickHouse backups, and the server's role assignments.
// Secrets (the HMAC key olympos-hmac, the Entra client secret, kv:// secrets)
// are added afterwards with az keyvault secret set (docs/azure.md). Soft
// delete and purge protection are ON: every Olympos backup of its own
// database (olympos-self) is useless without the KEK (docs/restore-olympos.md),
// and a native ClickHouse backup cannot be restored without the manifest key
// version that signed it. Both keys are in this vault, so the server's check
// of the KEK (Dashboard › Needs attention, if purge protection is off) covers
// the manifest key too.
@description('Key Vault name (3-24 alphanumerics and dashes).')
param vaultName string
param location string = resourceGroup().location
@description('Principal (object) ID of the Olympos server user-assigned managed identity.')
param serverIdentityPrincipalId string
@description('Soft-delete retention in days (7-90).')
@minValue(7)
@maxValue(90)
param softDeleteRetentionDays int = 90
@description('Subnet ID for the private endpoint (the server VNet). Empty: public network access stays enabled.')
param privateEndpointSubnetId string = ''

resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: vaultName
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'premium' }     // HSM-backed keys available
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: softDeleteRetentionDays
    enablePurgeProtection: true               // cannot be turned off again
    publicNetworkAccess: empty(privateEndpointSubnetId) ? 'Enabled' : 'Disabled'
    networkAcls: empty(privateEndpointSubnetId) ? { defaultAction: 'Allow', bypass: 'AzureServices' } : { defaultAction: 'Deny', bypass: 'None' }
  }
}

resource kek 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: kv
  name: 'olympos-kek'
  properties: {
    kty: 'RSA'
    keySize: 3072
    keyOps: [ 'wrapKey', 'unwrapKey' ]
  }
}

// Key Vault Crypto User: wrap/unwrap and keys/get (recovery level check).
resource cryptoUser 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kek
  name: guid(kek.id, serverIdentityPrincipalId, 'crypto-user')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')
    principalId: serverIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// The key that signs the manifests of native ClickHouse backups
// (keyVault.manifestKeyName, default olympos-manifest): EC P-256, sign and
// verify only. ARM creates a key only when it does not exist, so deploying
// the template again adds no version. Rotation adds a version; keep every
// version enabled while a backup it signed is within retention
// (docs/install.md, "The manifest key").
resource manifestKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: kv
  name: 'olympos-manifest'
  properties: {
    kty: 'EC'
    curveName: 'P-256'
    keyOps: [ 'sign', 'verify' ]
  }
}

// Key Vault Crypto User on the manifest key: keys/sign to sign a manifest,
// keys/get to read the public key that the server verifies with (locally:
// it never calls the vault's verify).
resource manifestSigner 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: manifestKey
  name: guid(manifestKey.id, serverIdentityPrincipalId, 'crypto-user')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '12338af0-0e69-4776-bea7-57ae8d297424')
    principalId: serverIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

// Key Vault Secrets Officer: reads kv:// secrets and writes Vault AppRole
// secret IDs (Vaults › Configure). Use Secrets User if you do not manage vaults.
resource secretsOfficer 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: kv
  name: guid(kv.id, serverIdentityPrincipalId, 'secrets-officer')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'b86a8fe4-44ce-4948-aee5-eccb2c155cd7')
    principalId: serverIdentityPrincipalId
    principalType: 'ServicePrincipal'
  }
}

resource pe 'Microsoft.Network/privateEndpoints@2023-11-01' = if (!empty(privateEndpointSubnetId)) {
  name: '${vaultName}-pe'
  location: location
  properties: {
    subnet: { id: privateEndpointSubnetId }
    privateLinkServiceConnections: [ { name: 'vault', properties: { privateLinkServiceId: kv.id, groupIds: [ 'vault' ] } } ]
  }
}

output vaultUri string = kv.properties.vaultUri
